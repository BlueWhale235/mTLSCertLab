using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using Microsoft.Win32;

namespace MtlsCertGui
{
    public class MtlsApp : Application
    {
        [STAThread]
        public static void Main()
        {
            var app = new MtlsApp();
            app.Run(new MainWindow());
        }
    }

    public class CertTemplate
    {
        public string CaCn { get; set; }
        public string ServerCn { get; set; }
        public string ClientCn { get; set; }
        public string Org { get; set; }
        public string Country { get; set; }
        public string Sans { get; set; }
        public string KeySize { get; set; }
        public string ValidityYears { get; set; }
        public string HashAlg { get; set; }
        public string CustomOids { get; set; }
        public int StartOffsetMinutes { get; set; }
    }

    public class MainWindow : Window
    {
        private TextBox txtCaCn, txtServerCn, txtClientCn, txtOrg, txtCountry, txtValidity, txtPassword, txtSans, txtCustomOids, txtLog, txtStartOffset;
        private ComboBox cmbKeySize, cmbHashAlg;
        private Button btnGenerate, btnExportTemplate, btnImportTemplate;

        public MainWindow()
        {
            Title = "专业级 mTLS 证书实验室";
            Width = 650;
            Height = 900;
            WindowStartupLocation = WindowStartupLocation.CenterScreen;
            Background = new SolidColorBrush(Color.FromRgb(240, 242, 245));

            var scrollViewer = new ScrollViewer { VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
            var mainStack = new StackPanel { Margin = new Thickness(25) };

            // Header
            mainStack.Children.Add(new TextBlock { 
                Text = "Pro mTLS Certificate Toolkit", 
                FontSize = 26, 
                FontWeight = FontWeights.ExtraBold, 
                Foreground = new SolidColorBrush(Color.FromRgb(31, 41, 55)),
                Margin = new Thickness(0, 0, 0, 10),
                HorizontalAlignment = HorizontalAlignment.Center 
            });

            // --- Template Buttons ---
            var templatePanel = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Center, Margin = new Thickness(0,0,0,20) };
            btnImportTemplate = CreateIconButton("📁 导入模板", (s, e) => ImportTemplate());
            btnExportTemplate = CreateIconButton("💾 保存模板", (s, e) => ExportTemplate());
            templatePanel.Children.Add(btnImportTemplate);
            templatePanel.Children.Add(btnExportTemplate);
            mainStack.Children.Add(templatePanel);

            // --- Subject Info Group ---
            var groupSubject = CreateGroup("证书主体 (Subject Identity)");
            txtCaCn = AddInput(groupSubject, "根证书 (CA) CN:", "My Private Root CA");
            txtServerCn = AddInput(groupSubject, "服务器证书 CN:", "localhost");
            txtClientCn = AddInput(groupSubject, "客户端证书 CN:", "mtls-client-01");
            txtOrg = AddInput(groupSubject, "组织 (Organization):", "My Company");
            txtCountry = AddInput(groupSubject, "国家/地区 (Country):", "CN");
            mainStack.Children.Add(groupSubject);

            // --- Crypto Options Group ---
            var groupCrypto = CreateGroup("加密与扩展 (Crypto & Extensions)");
            txtSans = AddInput(groupCrypto, "服务器 SAN (逗号分隔):", "127.0.0.1, dev.local, server.internal");
            txtCustomOids = AddInput(groupCrypto, "额外 EKU OIDs (逗号分隔):", "");
            
            var cryptoGrid = new UniformGrid { Columns = 2 };
            
            var keyBox = new StackPanel { Margin = new Thickness(0,0,5,0) };
            keyBox.Children.Add(new TextBlock { Text = "RSA 密钥长度:", Margin = new Thickness(0,5,0,2) });
            cmbKeySize = new ComboBox { ItemsSource = new[] { "2048", "3072", "4096" }, SelectedIndex = 0, Padding = new Thickness(5) };
            keyBox.Children.Add(cmbKeySize);
            cryptoGrid.Children.Add(keyBox);

            var hashBox = new StackPanel { Margin = new Thickness(5,0,0,0) };
            hashBox.Children.Add(new TextBlock { Text = "Hash 算法:", Margin = new Thickness(0,5,0,2) });
            cmbHashAlg = new ComboBox { ItemsSource = new[] { "SHA256", "SHA384", "SHA512" }, SelectedIndex = 0, Padding = new Thickness(5) };
            hashBox.Children.Add(cmbHashAlg);
            cryptoGrid.Children.Add(hashBox);
            
            groupCrypto.Children.Add(cryptoGrid);

            var timeGrid = new UniformGrid { Columns = 2, Margin = new Thickness(0,10,0,0) };
            
            var valBox = new StackPanel { Margin = new Thickness(0,0,5,0) };
            valBox.Children.Add(new TextBlock { Text = "有效期 (年):", Margin = new Thickness(0,5,0,2) });
            txtValidity = new TextBox { Text = "2", Padding = new Thickness(5) };
            valBox.Children.Add(txtValidity);
            timeGrid.Children.Add(valBox);

            var offBox = new StackPanel { Margin = new Thickness(5,0,0,0) };
            offBox.Children.Add(new TextBlock { Text = "生效偏移 (分钟前):", Margin = new Thickness(0,5,0,2) });
            txtStartOffset = new TextBox { Text = "10", Padding = new Thickness(5) };
            offBox.Children.Add(txtStartOffset);
            timeGrid.Children.Add(offBox);

            groupCrypto.Children.Add(timeGrid);
            txtPassword = AddInput(groupCrypto, "PFX 保护密码:", "admin123");
            mainStack.Children.Add(groupCrypto);

            // Generate Button
            btnGenerate = new Button
            {
                Content = "🛠 生成全套 mTLS 证书",
                Height = 55,
                Margin = new Thickness(0, 20, 0, 15),
                Background = new SolidColorBrush(Color.FromRgb(37, 99, 235)),
                Foreground = Brushes.White,
                FontSize = 18,
                FontWeight = FontWeights.Bold,
                BorderThickness = new Thickness(0)
            };
            btnGenerate.Click += async (s, e) => await GenerateCertsAsync();
            mainStack.Children.Add(btnGenerate);

            // Log
            txtLog = new TextBox
            {
                Height = 150,
                IsReadOnly = true,
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                Background = new SolidColorBrush(Color.FromRgb(17, 24, 39)),
                Foreground = new SolidColorBrush(Color.FromRgb(16, 185, 129)),
                FontFamily = new FontFamily("Consolas"),
                Padding = new Thickness(8),
                TextWrapping = TextWrapping.Wrap
            };
            mainStack.Children.Add(txtLog);

            scrollViewer.Content = mainStack;
            Content = scrollViewer;
        }

        private Button CreateIconButton(string text, RoutedEventHandler handler)
        {
            var btn = new Button { Content = text, Margin = new Thickness(5), Padding = new Thickness(10, 5, 10, 5), Background = Brushes.White };
            btn.Click += handler;
            return btn;
        }

        private StackPanel CreateGroup(string header)
        {
            var sp = new StackPanel { Margin = new Thickness(0, 0, 0, 20) };
            sp.Children.Add(new Border { 
                BorderBrush = Brushes.LightGray, BorderThickness = new Thickness(0,0,0,1), Margin = new Thickness(0,0,0,10),
                Child = new TextBlock { Text = header, FontWeight = FontWeights.Bold, Foreground = Brushes.SteelBlue, Padding = new Thickness(0,0,0,5) }
            });
            return sp;
        }

        private TextBox AddInput(StackPanel parent, string label, string @default)
        {
            parent.Children.Add(new TextBlock { Text = label, Margin = new Thickness(0, 2, 0, 2), FontSize = 12 });
            var tb = new TextBox { Text = @default, Margin = new Thickness(0, 0, 0, 8), Padding = new Thickness(5), BorderBrush = Brushes.Silver };
            parent.Children.Add(tb);
            return tb;
        }

        private void Log(string msg) => Dispatcher.Invoke(() => {
            txtLog.AppendText($"[{DateTime.Now:HH:mm:ss}] {msg}\n");
            txtLog.ScrollToEnd();
        });

        private void ExportTemplate()
        {
            var template = new CertTemplate {
                CaCn = txtCaCn.Text, ServerCn = txtServerCn.Text, ClientCn = txtClientCn.Text,
                Org = txtOrg.Text, Country = txtCountry.Text, Sans = txtSans.Text,
                KeySize = cmbKeySize.Text, HashAlg = cmbHashAlg.Text, ValidityYears = txtValidity.Text,
                CustomOids = txtCustomOids.Text,
                StartOffsetMinutes = int.TryParse(txtStartOffset.Text, out var o) ? o : 10
            };
            var saveFile = new SaveFileDialog { Filter = "JSON Template|*.json", FileName = "mtls-template.json" };
            if (saveFile.ShowDialog() == true) {
                File.WriteAllText(saveFile.FileName, JsonSerializer.Serialize(template, new JsonSerializerOptions { WriteIndented = true }));
                Log("✅ 模板已导出至: " + Path.GetFileName(saveFile.FileName));
            }
        }

        private void ImportTemplate()
        {
            var openFile = new OpenFileDialog { Filter = "JSON Template|*.json" };
            if (openFile.ShowDialog() == true) {
                try {
                    var template = JsonSerializer.Deserialize<CertTemplate>(File.ReadAllText(openFile.FileName));
                    txtCaCn.Text = template.CaCn; txtServerCn.Text = template.ServerCn; txtClientCn.Text = template.ClientCn;
                    txtOrg.Text = template.Org; txtCountry.Text = template.Country; txtSans.Text = template.Sans;
                    cmbKeySize.Text = template.KeySize; cmbHashAlg.Text = template.HashAlg; txtValidity.Text = template.ValidityYears;
                    txtCustomOids.Text = template.CustomOids; txtStartOffset.Text = template.StartOffsetMinutes.ToString();
                    Log("✅ 已从模板加载配置");
                } catch { Log("❌ 模板格式错误"); }
            }
        }

        private async Task GenerateCertsAsync()
        {
            btnGenerate.IsEnabled = false;
            txtLog.Clear();
            
            var config = new {
                CaCn = txtCaCn.Text, ServerCn = txtServerCn.Text, ClientCn = txtClientCn.Text,
                Org = txtOrg.Text, Country = txtCountry.Text,
                KeySize = int.Parse(cmbKeySize.Text),
                HashName = new HashAlgorithmName(cmbHashAlg.Text),
                ValidityYears = int.TryParse(txtValidity.Text, out int v) ? v : 2,
                StartOffset = int.TryParse(txtStartOffset.Text, out int o) ? o : 10,
                Password = txtPassword.Text,
                Sans = txtSans.Text.Split(',').Select(s => s.Trim()).Where(s => !string.IsNullOrEmpty(s)).ToList(),
                CustomOids = txtCustomOids.Text.Split(',').Select(s => s.Trim()).Where(s => !string.IsNullOrEmpty(s)).ToList()
            };

            Log("🚀 开始执行加密流程...");

            try
            {
                await Task.Run(() =>
                {
                    string outDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "certs_pro_output");
                    if (Directory.Exists(outDir)) Directory.Delete(outDir, true);
                    Directory.CreateDirectory(outDir);

                    string baseDn = $"O={config.Org}, C={config.Country}";
                    var startDate = DateTimeOffset.UtcNow.AddMinutes(-config.StartOffset);

                    // 1. Root CA
                    Log($"生成根证书 (RSA {config.KeySize}, {config.HashName})...");
                    using var caKey = RSA.Create(config.KeySize);
                    var caRequest = new CertificateRequest($"CN={config.CaCn}, {baseDn}", caKey, config.HashName, RSASignaturePadding.Pkcs1);
                    caRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
                    caRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
                    var caCert = caRequest.CreateSelfSigned(startDate, DateTimeOffset.UtcNow.AddYears(10));

                    // 2. Server Cert
                    Log($"签署服务器证书: {config.ServerCn}...");
                    using var serverKey = RSA.Create(config.KeySize);
                    var serverRequest = new CertificateRequest($"CN={config.ServerCn}, {baseDn}", serverKey, config.HashName, RSASignaturePadding.Pkcs1);
                    var serverEkus = new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") };
                    foreach(var oid in config.CustomOids) serverEkus.Add(new Oid(oid));
                    serverRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(serverEkus, false));
                    
                    var sanBuilder = new SubjectAlternativeNameBuilder();
                    sanBuilder.AddDnsName(config.ServerCn);
                    foreach(var san in config.Sans) { 
                        if (System.Net.IPAddress.TryParse(san, out var ip)) sanBuilder.AddIpAddress(ip);
                        else sanBuilder.AddDnsName(san);
                    }
                    serverRequest.CertificateExtensions.Add(sanBuilder.Build());
                    var serverCert = Sign(serverRequest, caCert, caKey, config.ValidityYears, startDate, config.HashName);

                    // 3. Client Cert
                    Log($"签署客户端证书: {config.ClientCn}...");
                    using var clientKey = RSA.Create(config.KeySize);
                    var clientRequest = new CertificateRequest($"CN={config.ClientCn}, {baseDn}", clientKey, config.HashName, RSASignaturePadding.Pkcs1);
                    var clientEkus = new OidCollection { new Oid("1.3.6.1.5.5.7.3.2") };
                    foreach(var oid in config.CustomOids) clientEkus.Add(new Oid(oid));
                    clientRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(clientEkus, false));
                    var clientCert = Sign(clientRequest, caCert, caKey, config.ValidityYears, startDate, config.HashName);

                    // Saving
                    Save(outDir, "ca", caCert, null, null);
                    Save(outDir, "server", serverCert, serverKey, config.Password);
                    Save(outDir, "client", clientCert, clientKey, config.Password);

                    Log("\n✅ 成功！所有证书已就绪。");
                    Log("目录: " + outDir);
                });
            }
            catch (Exception ex) { Log("❌ 失败: " + ex.Message); }
            finally { btnGenerate.IsEnabled = true; }
        }

        private X509Certificate2 Sign(CertificateRequest req, X509Certificate2 ca, RSA caKey, int years, DateTimeOffset start, HashAlgorithmName hash)
        {
            var serial = new byte[16];
            RandomNumberGenerator.Fill(serial);
            return req.Create(ca.SubjectName, X509SignatureGenerator.CreateForRSA(caKey, RSASignaturePadding.Pkcs1),
                start, start.AddYears(years), serial);
        }

        private void Save(string dir, string name, X509Certificate2 cert, RSA key, string pwd)
        {
            File.WriteAllText(Path.Combine(dir, $"{name}.crt"), ExportPem(cert.Export(X509ContentType.Cert), "CERTIFICATE"));
            if (key != null) {
                File.WriteAllText(Path.Combine(dir, $"{name}.key"), ExportPem(key.ExportRSAPrivateKey(), "RSA PRIVATE KEY"));
                using var pfx = cert.CopyWithPrivateKey(key);
                File.WriteAllBytes(Path.Combine(dir, $"{name}.pfx"), pfx.Export(X509ContentType.Pfx, pwd));
            }
        }

        private string ExportPem(byte[] data, string type) => $"-----BEGIN {type}-----\n{Convert.ToBase64String(data, Base64FormattingOptions.InsertLineBreaks)}\n-----END {type}-----";
    }

    public class UniformGrid : Panel 
    {
        public int Columns { get; set; }
        protected override Size MeasureOverride(Size availableSize) {
            double w = availableSize.Width / Math.Max(1, Columns);
            foreach (UIElement child in Children) child.Measure(new Size(w, availableSize.Height));
            return new Size(availableSize.Width, Children.Count > 0 ? Children.Cast<UIElement>().Max(c => c.DesiredSize.Height) : 0);
        }
        protected override Size ArrangeOverride(Size finalSize) {
            double x = 0, w = finalSize.Width / Math.Max(1, Columns);
            foreach (UIElement child in Children) { child.Arrange(new Rect(x, 0, w, finalSize.Height)); x += w; }
            return finalSize;
        }
    }
}