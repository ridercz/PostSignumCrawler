using System;
using System.Collections.Specialized;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using NConsoler;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Crypto.Parameters;

namespace PostSignumCrawler {
    class Program {
        private const string URL = "http://www.postsignum.cz/certifikaty_uzivatelu.html";
        private const string HTML_START = "<a title=\"Formát určený pro OS Linux a ostatní OS.\" href=\"";
        private const string HTML_END = "\"";
        private const string HTML_ENCODING = "iso-8859-2";

        private static readonly string[] _certExts = { ".cer", ".crt", ".der", ".pem" };
        private static readonly Encoding _encoding = Encoding.GetEncoding(HTML_ENCODING);
        private static readonly WebClient _client = new WebClient();

        static void Main(string[] args) {
            Consolery.Run();
        }

        // Actions

        [Action("Get certificates from CA and analyze them")]
        public static void Analyze(
            [Required(Description = "From serial number (inclusive)")] int fromSN,
            [Required(Description = "To serial number (inclusive)")] int toSN,
            [Optional("cache", "cf", Description = "Folder for cached certificates")] string cacheFolder,
            [Optional("found", "ff", Description = "Folder for found vulnerable certificates")] string foundFolder,
            [Optional(1000, "dw", Description = "Wait between download attempts (ms)")] int wait,
            [Optional(false, "do", Description = "Download only (don't analyze)")] bool downloadOnly) {

            Directory.CreateDirectory(cacheFolder);
            Directory.CreateDirectory(foundFolder);

            if (fromSN <= toSN) {
                Console.WriteLine($"Indexing from {fromSN} to {toSN}:");
                for (int serialNumber = fromSN; serialNumber <= toSN; serialNumber++) {
                    ProcessCertificate(cacheFolder, foundFolder, wait, downloadOnly, serialNumber);
                }
            }
            else {
                Console.WriteLine($"Indexing from {fromSN} to {toSN} (reverse order):");
                for (int serialNumber = fromSN; serialNumber >= toSN; serialNumber--) {
                    ProcessCertificate(cacheFolder, foundFolder, wait, downloadOnly, serialNumber);
                }
            }
        }


        [Action("Analyze certificates already in cache")]
        public static void AnalyzeCache(
            [Optional("cache", "cf", Description = "Folder for cached certificates")] string cacheFolder,
            [Optional("found", "ff", Description = "Folder for found vulnerable certificates")] string foundFolder) {

            var cacheFiles = Directory.GetFiles(cacheFolder);
            foreach (var file in cacheFiles) {
                if (!_certExts.Contains(Path.GetExtension(file).ToLowerInvariant())) continue;

                var foundFileName = Path.Combine(foundFolder, Path.GetFileName(file));
                Console.Write($"File {Path.GetFileNameWithoutExtension(file)}: ");

                if (File.Exists(foundFileName)) {
                    Console.WriteLine("Vulnerable (already analyzed)");
                }
                else {
                    var isVulnerable = AnalyzeCertificate(file);
                    if (isVulnerable) {
                        Console.WriteLine("Vulnerable");
                        File.Copy(file, foundFileName);
                    }
                    else {
                        Console.WriteLine("OK");
                    }
                }
            }

            foreach (var folder in Directory.GetDirectories(cacheFolder)) {
                AnalyzeCache(folder, foundFolder);
            }
        }

        [Action("Create index of certificates")]
        public static void Index(
            [Optional("found", "f", Description = "Folder with certificates")] string folderName,
            [Optional(false, "np", Description = "Do not show progress on console (faster)")] bool noProgress) {
            Console.WriteLine("Indexing...");
            var sb = new StringBuilder();
            sb.AppendLine(string.Join("\t", "SerialNumber", "Hash", "NotBefore", "NotAfter", "Length", "Domain", "Name", "Email", "Issuer", "Subject"));

            IndexFolder(folderName, sb, noProgress);

            var indexFileName = Path.Combine(folderName, "index.csv");
            File.WriteAllText(indexFileName, sb.ToString());
        }

        // Helper methods

        private static void IndexFolder(string folderName, StringBuilder sb, bool noProgress) {
            foreach (var fileName in Directory.GetFiles(folderName)) {
                if (!_certExts.Contains(Path.GetExtension(fileName).ToLowerInvariant())) continue;

                var cert = new System.Security.Cryptography.X509Certificates.X509Certificate2(fileName);
                var email = cert.GetNameInfo(System.Security.Cryptography.X509Certificates.X509NameType.EmailName, false);
                var domain = email.Substring(email.IndexOf('@') + 1);
                var name = cert.GetNameInfo(System.Security.Cryptography.X509Certificates.X509NameType.SimpleName, false);

                if (!noProgress) Console.WriteLine($"  0x{cert.GetSerialNumberString(),-20} {email,-40} {name}");

                sb.AppendLine(string.Join("\t",
                    "0x" + cert.GetSerialNumberString(),
                    cert.GetCertHashString(),
                    cert.NotBefore.ToString("yyyy-MM-dd"),
                    cert.NotAfter.ToString("yyyy-MM-dd"),
                    cert.PublicKey.Key.KeySize,
                    domain,
                    name,
                    email,
                    cert.Issuer,
                    cert.Subject));
            }

            foreach (var subFolderName in Directory.GetDirectories(folderName)) {
                IndexFolder(subFolderName, sb, noProgress);
            }
        }

        private static void ProcessCertificate(string cacheFolder, string foundFolder, int wait, bool downloadOnly, int serialNumber) {
            // Create file names
            var snString = serialNumber.ToString().PadLeft(8, '0');
            var cacheFileName = Path.Combine(cacheFolder, snString.Substring(0, 4), serialNumber.ToString().PadLeft(8, '0') + ".crt");
            var foundFileName = Path.Combine(foundFolder, serialNumber.ToString().PadLeft(8, '0') + ".crt");
            Directory.CreateDirectory(Path.GetDirectoryName(cacheFileName));


            // Download certificate
            var downloadResult = DownloadCertificate(serialNumber, cacheFileName);

            // Analyze certificate
            if (File.Exists(cacheFileName)) {
                if (downloadOnly) {
                    Console.WriteLine("Skipped");
                }
                if (File.Exists(foundFileName)) {
                    Console.WriteLine("Vulnerable (already analyzed)");
                }
                else {
                    var isVulnerable = AnalyzeCertificate(cacheFileName);
                    if (isVulnerable) {
                        Console.WriteLine("Vulnerable");
                        File.Copy(cacheFileName, foundFileName);
                    }
                    else {
                        Console.WriteLine("OK");
                    }
                }
            }

            // Wait to avoid hammering CA servers
            if (downloadResult && wait > 0) System.Threading.Thread.Sleep(wait);
        }

        private static string GetCertificateDownloadUrl(int serialNumber) {
            // Prepare parameters
            var fields = new NameValueCollection();
            fields.Add("idb_hf_0", string.Empty);
            fields.Add("qca", "on");
            fields.Add("certSerioveCislo", serialNumber.ToString());
            fields.Add("submitSerioveCislo", "ODESLAT");
            fields.Add("certEmail", string.Empty);

            // Get page
            var bytes = _client.UploadValues(URL, "POST", fields);
            var html = _encoding.GetString(bytes);

            // Find URL in HTML markup
            var startPos = html.IndexOf(HTML_START, StringComparison.CurrentCultureIgnoreCase);
            if (startPos < 0) return null;
            startPos += HTML_START.Length;
            var endPos = html.IndexOf(HTML_END, startPos + 1, StringComparison.CurrentCultureIgnoreCase);
            if (endPos < 0) return null;
            var url = html.Substring(startPos, endPos - startPos);
            url = url.Replace("&amp;", "&");
            return url;
        }

        private static bool DownloadCertificate(int serialNumber, string fileName) {
            Console.Write($"Cert #{serialNumber}: ");
            if (File.Exists(fileName)) {
                Console.WriteLine("Skipped, file already exists");
                return false;
            }

            Console.Write("URL...");
            var url = GetCertificateDownloadUrl(serialNumber);
            if (string.IsNullOrEmpty(url)) {
                Console.WriteLine("Failed, URL not found in page");
                return false;
            }

            Console.Write("OK, File...");
            _client.DownloadFile(url, fileName);
            Console.Write("OK, Analysis...");
            return true;
        }

        private static bool AnalyzeCertificate(string certFile) {
            var x509CertificateParser = new X509CertificateParser();
            var x509Certificate = x509CertificateParser.ReadCertificate(File.ReadAllBytes(certFile));
            var rsaKeyParameters = x509Certificate.GetPublicKey() as RsaKeyParameters;
            return RocaTest.IsVulnerable(rsaKeyParameters);
        }

    }
}
