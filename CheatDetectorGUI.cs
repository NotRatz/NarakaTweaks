using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using Microsoft.Win32;

// Assembly metadata removed from this file to avoid duplicate attribute errors.

namespace RatzCheatDetector
{
    class Program
    {
        [STAThread]
        static void Main(string[] args)
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            // Check if running as administrator
            if (!IsAdministrator())
            {
                // Automatically restart as administrator
                try
                {
                    ProcessStartInfo startInfo = new ProcessStartInfo();
                    startInfo.UseShellExecute = true;
                    startInfo.WorkingDirectory = Environment.CurrentDirectory;
                    startInfo.FileName = Application.ExecutablePath;
                    startInfo.Verb = "runas"; // Request elevation

                    Process.Start(startInfo);
                    return; // Exit current non-elevated process
                }
                catch (System.ComponentModel.Win32Exception)
                {
                    // User cancelled UAC prompt
                    MessageBox.Show(
                        "Administrator privileges are required to run this tool.\n\n" +
                        "The UAC prompt was cancelled.",
                        "Administrator Rights Required",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Warning);
                    return;
                }
            }

            Application.Run(new ScannerForm());
        }

        static bool IsAdministrator()
        {
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
    }

    // Main scanner window
    public class ScannerForm : Form
    {
        private Label titleLabel;
        private Label subtitleLabel;
        private Button scanButton;
        private Button cancelButton;
        private ProgressBar progressBar;
        private Label statusLabel;
        private DataGridView resultsGrid;

        private List<DetectionResult> detectionResults = new List<DetectionResult>();
        private bool scanInProgress = false;
        private CancellationTokenSource cts;

        public ScannerForm()
        {
            InitializeComponents();
        }

        private void InitializeComponents()
        {
            // Form settings
            this.Text = "EGL - Morus Cup Tool";
            this.Size = new Size(1000, 700);
            this.StartPosition = FormStartPosition.CenterScreen;
            this.FormBorderStyle = FormBorderStyle.Sizable;
            this.BackColor = Color.FromArgb(24, 24, 30);

            // Top panel for title
            Panel topPanel = new Panel();
            topPanel.Dock = DockStyle.Top;
            topPanel.Height = 120;
            topPanel.Padding = new Padding(20);
            topPanel.BackColor = Color.FromArgb(30, 30, 36);
            this.Controls.Add(topPanel);

            titleLabel = new Label();
            titleLabel.Text = "EGL - Morus Cup Tool";
            titleLabel.Font = new Font("Segoe UI", 24, FontStyle.Bold);
            titleLabel.ForeColor = Color.FromArgb(200, 230, 255);
            titleLabel.AutoSize = true;
            titleLabel.Location = new Point(20, 10);
            topPanel.Controls.Add(titleLabel);

            subtitleLabel = new Label();
            subtitleLabel.Text = "System inspector and unauthorized software detection";
            subtitleLabel.Font = new Font("Segoe UI", 10, FontStyle.Regular);
            subtitleLabel.ForeColor = Color.FromArgb(180, 200, 220);
            subtitleLabel.AutoSize = true;
            subtitleLabel.Location = new Point(22, 55);
            topPanel.Controls.Add(subtitleLabel);

            // Main layout
            TableLayoutPanel mainLayout = new TableLayoutPanel();
            mainLayout.Dock = DockStyle.Fill;
            mainLayout.ColumnCount = 2;
            mainLayout.RowCount = 3;
            mainLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 55f));
            mainLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 45f));
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 65f));
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 25f));
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 10f));
            mainLayout.Padding = new Padding(20);
            mainLayout.BackColor = Color.Transparent;
            this.Controls.Add(mainLayout);

            // Left: big controls and instructions
            Panel leftPanel = new Panel();
            leftPanel.Dock = DockStyle.Fill;
            leftPanel.BackColor = Color.FromArgb(28, 28, 34);
            mainLayout.Controls.Add(leftPanel, 0, 0);
            mainLayout.SetRowSpan(leftPanel, 2);

            Label instructions = new Label();
            instructions.Text = "Click START SCAN to begin a comprehensive system inspection. Results will appear on the right in real-time.";
            instructions.Font = new Font("Segoe UI", 11, FontStyle.Regular);
            instructions.ForeColor = Color.FromArgb(200, 200, 210);
            instructions.Size = new Size(450, 80);
            instructions.Location = new Point(20, 20);
            leftPanel.Controls.Add(instructions);

            scanButton = new Button();
            scanButton.Text = "START SCAN";
            scanButton.Font = new Font("Segoe UI", 16, FontStyle.Bold);
            scanButton.Size = new Size(320, 80);
            scanButton.Location = new Point(20, 120);
            scanButton.BackColor = Color.FromArgb(0, 120, 215);
            scanButton.ForeColor = Color.White;
            scanButton.FlatStyle = FlatStyle.Flat;
            scanButton.FlatAppearance.BorderSize = 0;
            scanButton.Cursor = Cursors.Hand;
            scanButton.Click += ScanButton_Click;
            leftPanel.Controls.Add(scanButton);

            cancelButton = new Button();
            cancelButton.Text = "CANCEL";
            cancelButton.Font = new Font("Segoe UI", 10, FontStyle.Bold);
            cancelButton.Size = new Size(120, 40);
            cancelButton.Location = new Point(360, 160);
            cancelButton.BackColor = Color.FromArgb(160, 20, 20);
            cancelButton.ForeColor = Color.White;
            cancelButton.FlatStyle = FlatStyle.Flat;
            cancelButton.FlatAppearance.BorderSize = 0;
            cancelButton.Cursor = Cursors.Hand;
            cancelButton.Click += (s, e) => CancelScan();
            cancelButton.Enabled = false;
            leftPanel.Controls.Add(cancelButton);

            // Right: results grid
            resultsGrid = new DataGridView();
            resultsGrid.Dock = DockStyle.Fill;
            resultsGrid.AutoGenerateColumns = false;
            resultsGrid.BackgroundColor = Color.FromArgb(22, 22, 26);
            resultsGrid.ForeColor = Color.White;
            resultsGrid.BorderStyle = BorderStyle.None;
            resultsGrid.EnableHeadersVisualStyles = false;
            resultsGrid.ColumnHeadersDefaultCellStyle.BackColor = Color.FromArgb(35, 35, 40);
            resultsGrid.ColumnHeadersDefaultCellStyle.ForeColor = Color.White;
            resultsGrid.RowHeadersVisible = false;
            resultsGrid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
            resultsGrid.ReadOnly = true;

            var colStatus = new DataGridViewTextBoxColumn();
            colStatus.HeaderText = "Status";
            colStatus.DataPropertyName = "Status";
            colStatus.Width = 90;
            resultsGrid.Columns.Add(colStatus);

            var colMethod = new DataGridViewTextBoxColumn();
            colMethod.HeaderText = "Method";
            colMethod.DataPropertyName = "Method";
            colMethod.AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill;
            resultsGrid.Columns.Add(colMethod);

            var colDetails = new DataGridViewTextBoxColumn();
            colDetails.HeaderText = "Details";
            colDetails.DataPropertyName = "Details";
            colDetails.AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill;
            resultsGrid.Columns.Add(colDetails);

            Panel rightPanel = new Panel();
            rightPanel.Dock = DockStyle.Fill;
            rightPanel.BackColor = Color.FromArgb(22, 22, 26);
            rightPanel.Padding = new Padding(10);
            rightPanel.Controls.Add(resultsGrid);
            mainLayout.Controls.Add(rightPanel, 1, 0);
            mainLayout.SetRowSpan(rightPanel, 3);

            // Bottom row: progress and status
            progressBar = new ProgressBar();
            progressBar.Style = ProgressBarStyle.Continuous;
            progressBar.Value = 0;
            progressBar.Dock = DockStyle.Fill;

            Panel bottomLeft = new Panel();
            bottomLeft.Dock = DockStyle.Fill;
            bottomLeft.Padding = new Padding(10);
            bottomLeft.Controls.Add(progressBar);
            mainLayout.Controls.Add(bottomLeft, 0, 2);

            statusLabel = new Label();
            statusLabel.Text = "Ready";
            statusLabel.Font = new Font("Segoe UI", 10, FontStyle.Regular);
            statusLabel.ForeColor = Color.FromArgb(180, 200, 220);
            statusLabel.AutoSize = false;
            statusLabel.TextAlign = ContentAlignment.MiddleCenter;
            statusLabel.Dock = DockStyle.Fill;

            Panel bottomRight = new Panel();
            bottomRight.Dock = DockStyle.Fill;
            bottomRight.Padding = new Padding(10);
            bottomRight.Controls.Add(statusLabel);
            mainLayout.Controls.Add(bottomRight, 1, 2);

            // Consent label (subtle)
            Label consentLabel = new Label();
            consentLabel.Text = "By hitting start scan you consent to the use of this tool and scan.";
            consentLabel.Font = new Font("Segoe UI", 8, FontStyle.Italic);
            consentLabel.ForeColor = Color.FromArgb(140, 140, 150);
            consentLabel.AutoSize = true;
            consentLabel.Location = new Point(20, this.ClientSize.Height - 40);
            consentLabel.Anchor = AnchorStyles.Left | AnchorStyles.Bottom;
            this.Controls.Add(consentLabel);

            // Initialize empty grid
            RefreshResultsGrid();
        }

        private async void ScanButton_Click(object sender, EventArgs e)
        {
            if (scanInProgress) return;

            scanInProgress = true;
            scanButton.Enabled = false;
            cancelButton.Enabled = true;
            progressBar.Value = 0;
            statusLabel.Text = "Starting scan...";
            detectionResults.Clear();
            RefreshResultsGrid();

            cts = new CancellationTokenSource();

            try
            {
                await Task.Run(() => RunAllDetections(cts.Token));

                if (cts.IsCancellationRequested)
                {
                    UpdateStatus("Scan cancelled by user.");
                    MessageBox.Show("Scan was cancelled.", "Scan Cancelled", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                else
                {
                    UpdateProgress(100);
                    UpdateStatus("Scan Complete!");

                    // Send webhook with detection results
                    try
                    {
                        UpdateStatus("Sending detection report...");

                        var detectedMethods = detectionResults.Where(r => r.Detected).ToList();
                        bool webhookSent = WebhookManager.SendDetectionWebhook(detectedMethods);

                        if (webhookSent)
                        {
                            Console.WriteLine("Detection report sent successfully via Discord webhook");
                        }
                        else
                        {
                            Console.WriteLine("Failed to send detection report - webhook not configured or failed");
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Webhook transmission error: {ex.Message}");
                    }

                    var detected = detectionResults.Where(r => r.Detected).ToList();
                    if (detected.Count > 0)
                    {
                        SaveDetectionReport(detected);
                        this.Hide();
                        ShowCheaterScreen(detected);
                        Application.Exit();
                    }
                    else
                    {
                        MessageBox.Show(
                            "System scan complete!\n\n" +
                            "No unauthorized software detected.\n" +
                            "Total checks: " + detectionResults.Count +
                            "\n\nDetection report has been transmitted (if configured).",
                            "Scan Complete - System Clean",
                            MessageBoxButtons.OK,
                            MessageBoxIcon.Information);
                    }
                }
            }
            finally
            {
                scanInProgress = false;
                scanButton.Enabled = true;
                cancelButton.Enabled = false;
                cts?.Dispose();
                cts = null;
                UpdateStatus("Ready");
                RefreshResultsGrid();
            }
        }

        private void CancelScan()
        {
            if (cts != null && !cts.IsCancellationRequested)
            {
                cts.Cancel();
            }
        }

        private void ShowCheaterScreen(List<DetectionResult> detectedMethods)
        {
            CheaterForm cheaterForm = new CheaterForm(detectedMethods);
            cheaterForm.ShowDialog();
        }

        // Detection methods (same as before) - they append to detectionResults

        private void DetectRunningProcess()
        {
            try
            {
                string[] cheatNames = { "CYZ", "cheat", "hack", "injector", "bypass", "parry", "script", "aimbot", "trigger", "wallhack", "modmenu", "trainer" };

                // Comprehensive whitelist: anti-cheat software, security tools, and our detector
                string[] whitelistNames = {
                    // Our detector variants
                    "ratz", "cheatdetector", "ratz cheat detector", "naraka cheat detector", "cheatengine", "cheat engine", "naraka-cheat-detector",
                    // Major anti-cheat systems
                    "anti-cheat", "anticheat", "eac", "easy anti-cheat", "easyanticheat",
                    "battleye", "vanguard", "ricochet", "faceit", "esea",
                    // Game anti-cheats
                    "nprotect", "gameguard", "xigncode", "hackshield", "punkbuster",
                    "valve anti-cheat", "vac", "fairfight", "treyarch", "activision",
                    // System security tools
                    "defender", "malware", "antivirus", "kaspersky", "norton",
                    "mcafee", "avast", "avg", "bitdefender", "eset", "sophos",
                    // Process monitoring tools (legitimate)
                    "process explorer", "process hacker", "procmon", "sysinternals",
                    "task manager", "taskmgr", "perfmon", "resmon",
                    // Development tools
                    "visual studio", "vscode", "devenv", "code.exe", "rider",
                    // System processes
                    "windows", "system", "svchost", "dwm", "explorer"
                };

                foreach (var proc in Process.GetProcesses())
                {
                    string procName = proc.ProcessName.ToLower();

                    bool isWhitelisted = false;
                    foreach (var whitelist in whitelistNames)
                    {
                        if (procName.IndexOf(whitelist, StringComparison.OrdinalIgnoreCase) >= 0)
                        {
                            isWhitelisted = true;
                            break;
                        }
                    }
                    if (isWhitelisted) continue;

                    foreach (var cheatName in cheatNames)
                    {
                        if (procName.IndexOf(cheatName, StringComparison.OrdinalIgnoreCase) >= 0)
                        {
                            detectionResults.Add(new DetectionResult
                            {
                                Method = "Running Process Check",
                                Detected = true,
                                Details = "Process: " + proc.ProcessName
                            });
                            return;
                        }
                    }
                }

                detectionResults.Add(new DetectionResult { Method = "Running Process Check", Detected = false });
            }
            catch (Exception ex)
            {
                detectionResults.Add(new DetectionResult { Method = "Running Process Check", Detected = false, Details = ex.Message });
            }
            finally
            {
                RefreshResultsGrid();
            }
        }

        private void RunAllDetections(CancellationToken token)
        {
            UpdateStatus("Scanning running processes...");
            UpdateProgress(10);
            DetectRunningProcess();
            if (token.IsCancellationRequested) return;

            UpdateStatus("Scanning file system...");
            UpdateProgress(20);
            DetectFileSystem();
            if (token.IsCancellationRequested) return;

            UpdateStatus("Checking prefetch cache...");
            UpdateProgress(30);
            DetectPrefetch();
            if (token.IsCancellationRequested) return;

            UpdateStatus("Analyzing execution tracking (BAM/DAM)...");
            UpdateProgress(45);
            DetectBAMDAM();
            if (token.IsCancellationRequested) return;

            UpdateStatus("Checking UserAssist logs...");
            UpdateProgress(55);
            DetectUserAssist();
            if (token.IsCancellationRequested) return;

            UpdateStatus("Scanning MUICache...");
            UpdateProgress(65);
            DetectMUICache();
            if (token.IsCancellationRequested) return;

            UpdateStatus("Analyzing recent documents...");
            UpdateProgress(75);
            DetectRecentDocs();
            if (token.IsCancellationRequested) return;

            UpdateStatus("Checking jump lists...");
            UpdateProgress(85);
            DetectJumpLists();
            if (token.IsCancellationRequested) return;

            UpdateStatus("Scanning error reports...");
            UpdateProgress(90);
            DetectWER();
            if (token.IsCancellationRequested) return;

            UpdateStatus("Checking event logs...");
            UpdateProgress(95);
            DetectApplicationEvents();
            if (token.IsCancellationRequested) return;

            UpdateStatus("Finalizing scan...");
            UpdateProgress(100);
        }

        private void UpdateStatus(string message)
        {
            if (statusLabel.InvokeRequired)
            {
                statusLabel.Invoke(new Action(() => statusLabel.Text = message));
            }
            else
            {
                statusLabel.Text = message;
            }
            Thread.Sleep(100);
        }

        private void UpdateProgress(int value)
        {
            if (progressBar.InvokeRequired)
            {
                progressBar.Invoke(new Action(() => progressBar.Value = value));
            }
            else
            {
                progressBar.Value = value;
            }
        }

        private void SaveDetectionReport(List<DetectionResult> detectedMethods)
        {
            try
            {
                string exePath = AppDomain.CurrentDomain.BaseDirectory;
                string reportPath = Path.Combine(exePath, "DETECTION_REPORT.txt");

                StringBuilder sb = new StringBuilder();
                sb.AppendLine("===============================================================");
                sb.AppendLine("  RATZ SYSTEM INSPECTOR - DETECTION REPORT");
                sb.AppendLine("===============================================================");
                sb.AppendLine();
                sb.AppendLine("Scan Date: " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
                sb.AppendLine("Computer: " + Environment.MachineName);
                sb.AppendLine("User: " + Environment.UserName);
                sb.AppendLine();
                sb.AppendLine("===============================================================");
                sb.AppendLine("  UNAUTHORIZED SOFTWARE DETECTED");
                sb.AppendLine("===============================================================");
                sb.AppendLine();
                sb.AppendLine("Total Detections: " + detectedMethods.Count);
                sb.AppendLine();

                foreach (var result in detectedMethods)
                {
                    sb.AppendLine("Detection Method: " + result.Method);
                    if (!string.IsNullOrEmpty(result.Details))
                    {
                        sb.AppendLine("  Details: " + result.Details);
                    }
                    sb.AppendLine();
                }

                sb.AppendLine("===============================================================");
                sb.AppendLine("  ALL SCAN RESULTS");
                sb.AppendLine("===============================================================");
                sb.AppendLine();

                foreach (var result in detectionResults)
                {
                    string status = result.Detected ? "[DETECTED]" : "[CLEAN]";
                    sb.AppendLine(status + " " + result.Method);
                    if (!string.IsNullOrEmpty(result.Details))
                    {
                        sb.AppendLine("  " + result.Details);
                    }
                }

                sb.AppendLine();
                sb.AppendLine("===============================================================");
                sb.AppendLine("  END OF REPORT");
                sb.AppendLine("===============================================================");

                File.WriteAllText(reportPath, sb.ToString());
            }
            catch { }
        }

        private void DetectFileSystem()
        {
            try
            {
                // Only search for executables and DLLs with cheat-related names
                string[] cheatPatterns = { "*CYZ*.exe", "*CYZ*.dll", "*cheat*.exe", "*cheat*.dll", "*injector*.exe", "*injector*.dll", "*hack*.exe", "*hack*.dll" };

                // Comprehensive file whitelist
                string[] whitelistPatterns = {
                    // Our detector variants
                    "*ratz*", "*cheatdetector*", "*ratz cheat detector*", "*naraka cheat detector*", "*cheatengine*", "*cheat engine*",
                    // Anti-cheat systems
                    "*anti-cheat*", "*anticheat*", "*eac*", "*easy*anti*cheat*",
                    "*battleye*", "*vanguard*", "*ricochet*", "*faceit*", "*esea*",
                    // Game anti-cheats
                    "*nprotect*", "*gameguard*", "*xigncode*", "*hackshield*", "*punkbuster*",
                    "*vac*", "*fairfight*",
                    // Security software
                    "*defender*", "*malware*", "*antivirus*", "*kaspersky*", "*norton*",
                    "*mcafee*", "*avast*", "*avg*", "*bitdefender*", "*eset*", "*sophos*",
                    // Development tools
                    "*visual*studio*", "*vscode*", "*rider*", "*jetbrains*",
                    // System tools
                    "*sysinternals*", "*process*explorer*", "*process*hacker*"
                };

                string[] searchPaths = {
                    Environment.GetEnvironmentVariable("TEMP"),
                    Environment.GetEnvironmentVariable("LOCALAPPDATA"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                    Environment.GetFolderPath(Environment.SpecialFolder.Desktop)
                };

                foreach (var path in searchPaths)
                {
                    if (string.IsNullOrEmpty(path) || !Directory.Exists(path)) continue;

                    foreach (var pattern in cheatPatterns)
                    {
                        var files = Directory.GetFiles(path, pattern, SearchOption.TopDirectoryOnly);
                        foreach (var file in files)
                        {
                            string fileName = Path.GetFileName(file).ToLower();

                            // Skip whitelisted anti-cheat files
                            bool isWhitelisted = false;
                            foreach (var whitelist in whitelistPatterns)
                            {
                                if (fileName.IndexOf(whitelist.Replace("*", ""), StringComparison.OrdinalIgnoreCase) >= 0)
                                {
                                    isWhitelisted = true;
                                    break;
                                }
                            }

                            if (!isWhitelisted && (file.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) || file.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)))
                            {
                                detectionResults.Add(new DetectionResult
                                {
                                    Method = "File System Search",
                                    Detected = true,
                                    Details = "File: " + file
                                });
                                RefreshResultsGrid();
                                return;
                            }
                        }
                    }
                }

                detectionResults.Add(new DetectionResult { Method = "File System Search", Detected = false });
            }
            catch (Exception ex)
            {
                detectionResults.Add(new DetectionResult { Method = "File System Search", Detected = false, Details = ex.Message });
            }
            finally
            {
                RefreshResultsGrid();
            }
        }

        private void DetectPrefetch()
        {
            try
            {
                string prefetchPath = Path.Combine(Environment.GetEnvironmentVariable("SystemRoot"), "Prefetch");
                if (!Directory.Exists(prefetchPath))
                {
                    detectionResults.Add(new DetectionResult { Method = "Prefetch Execution Traces", Detected = false });
                    return;
                }

                string[] cheatPatterns = { "CYZ.EXE-*.pf", "CHEAT*.pf", "INJECTOR*.pf", "HACK*.pf" };

                // Prefetch whitelist patterns
                string[] prefetchWhitelist = {
                    "CHEATDETECTOR", "RATZ", "NARAKA", "ANTICHEAT", "ANTI-CHEAT", "EAC", "BATTLEYE",
                    "VANGUARD", "RICOCHET", "FACEIT", "ESEA", "PUNKBUSTER"
                };

                foreach (var pattern in cheatPatterns)
                {
                    var files = Directory.GetFiles(prefetchPath, pattern, SearchOption.TopDirectoryOnly);
                    foreach (var file in files)
                    {
                        string fileName = Path.GetFileName(file).ToUpper();

                        bool isWhitelisted = false;
                        foreach (var whitelist in prefetchWhitelist)
                        {
                            if (fileName.IndexOf(whitelist, StringComparison.OrdinalIgnoreCase) >= 0)
                            {
                                isWhitelisted = true;
                                break;
                            }
                        }
                        if (isWhitelisted) continue;

                        detectionResults.Add(new DetectionResult
                        {
                            Method = "Prefetch Execution Traces",
                            Detected = true,
                            Details = "Prefetch: " + Path.GetFileName(file)
                        });
                        RefreshResultsGrid();
                        return;
                    }
                }

                detectionResults.Add(new DetectionResult { Method = "Prefetch Execution Traces", Detected = false });
            }
            catch (Exception ex)
            {
                detectionResults.Add(new DetectionResult { Method = "Prefetch Execution Traces", Detected = false, Details = ex.Message });
            }
            finally
            {
                RefreshResultsGrid();
            }
        }

        private void DetectBAMDAM()
        {
            try
            {
                string userSid = WindowsIdentity.GetCurrent().User.Value;
                string[] registryPaths = {
                    @"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\" + userSid,
                    @"SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\" + userSid
                };

                string[] cheatPatterns = { "CYZ", "cheat", "injector", "hack" };

                // Comprehensive BAM/DAM whitelist
                string[] whitelistPatterns = {
                    // Our detector variants
                    "ratz", "cheatdetector", "naraka cheat detector",
                    // Anti-cheat systems
                    "anti-cheat", "anticheat", "eac", "easy", "battleye", "vanguard",
                    "ricochet", "faceit", "esea", "nprotect", "gameguard", "xigncode",
                    "hackshield", "punkbuster", "vac", "fairfight",
                    // Security software
                    "defender", "malware", "antivirus", "kaspersky", "norton",
                    "mcafee", "avast", "avg", "bitdefender", "eset", "sophos",
                    // Development & system tools
                    "visual", "vscode", "devenv", "rider", "jetbrains",
                    "sysinternals", "procexp", "procmon", "processhacker"
                };

                foreach (var regPath in registryPaths)
                {
                    using (RegistryKey key = Registry.LocalMachine.OpenSubKey(regPath))
                    {
                        if (key != null)
                        {
                            foreach (var valueName in key.GetValueNames())
                            {
                                string valueNameLower = valueName.ToLower();

                                // Skip the CheatDetector itself (multiple name variants)
                                if ((valueNameLower.Contains("ratz") && valueNameLower.Contains("detector")) ||
                                    (valueNameLower.Contains("naraka") && valueNameLower.Contains("cheat") && valueNameLower.Contains("detector")) ||
                                    valueNameLower.Contains("cheatdetector"))
                                    continue;

                                bool isWhitelisted = false;
                                foreach (var whitelist in whitelistPatterns)
                                {
                                    if (valueNameLower.IndexOf(whitelist, StringComparison.OrdinalIgnoreCase) >= 0)
                                    {
                                        isWhitelisted = true;
                                        break;
                                    }
                                }
                                if (isWhitelisted) continue;

                                if (!valueNameLower.EndsWith(".exe") && !valueNameLower.EndsWith(".dll"))
                                    continue;

                                foreach (var pattern in cheatPatterns)
                                {
                                    if (valueNameLower.IndexOf(pattern, StringComparison.OrdinalIgnoreCase) >= 0)
                                    {
                                        detectionResults.Add(new DetectionResult
                                        {
                                            Method = "BAM/DAM Execution Tracking",
                                            Detected = true,
                                            Details = "Registry: " + Path.GetFileName(valueName)
                                        });
                                        RefreshResultsGrid();
                                        return;
                                    }
                                }
                            }
                        }
                    }
                }

                detectionResults.Add(new DetectionResult { Method = "BAM/DAM Execution Tracking", Detected = false });
            }
            catch (Exception ex)
            {
                detectionResults.Add(new DetectionResult { Method = "BAM/DAM Execution Tracking", Detected = false, Details = ex.Message });
            }
            finally
            {
                RefreshResultsGrid();
            }
        }

        private void DetectUserAssist()
        {
            try
            {
                string userAssistPath = @"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count";

                using (RegistryKey key = Registry.CurrentUser.OpenSubKey(userAssistPath))
                {
                    if (key != null)
                    {
                        string[] cheatPatterns = { "CYZ", "PLM" };

                        foreach (var valueName in key.GetValueNames())
                        {
                            foreach (var pattern in cheatPatterns)
                            {
                                if (valueName.IndexOf(pattern, StringComparison.OrdinalIgnoreCase) >= 0)
                                {
                                    detectionResults.Add(new DetectionResult
                                    {
                                        Method = "UserAssist Execution Tracking",
                                        Detected = true,
                                        Details = "UserAssist entry found"
                                    });
                                    RefreshResultsGrid();
                                    return;
                                }
                            }
                        }
                    }
                }

                detectionResults.Add(new DetectionResult { Method = "UserAssist Execution Tracking", Detected = false });
            }
            catch (Exception ex)
            {
                detectionResults.Add(new DetectionResult { Method = "UserAssist Execution Tracking", Detected = false, Details = ex.Message });
            }
            finally
            {
                RefreshResultsGrid();
            }
        }

        private void DetectMUICache()
        {
            try
            {
                string muiCachePath = @"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache";

                using (RegistryKey key = Registry.CurrentUser.OpenSubKey(muiCachePath))
                {
                    if (key != null)
                    {
                        string[] cheatPatterns = { "CYZ", "cheat", "injector" };

                        foreach (var valueName in key.GetValueNames())
                        {
                            foreach (var pattern in cheatPatterns)
                            {
                                if (valueName.IndexOf(pattern, StringComparison.OrdinalIgnoreCase) >= 0)
                                {
                                    detectionResults.Add(new DetectionResult
                                    {
                                        Method = "MUICache Program Name Cache",
                                        Detected = true,
                                        Details = "MUICache: " + Path.GetFileName(valueName)
                                    });
                                    RefreshResultsGrid();
                                    return;
                                }
                            }
                        }
                    }
                }

                detectionResults.Add(new DetectionResult { Method = "MUICache Program Name Cache", Detected = false });
            }
            catch (Exception ex)
            {
                detectionResults.Add(new DetectionResult { Method = "MUICache Program Name Cache", Detected = false, Details = ex.Message });
            }
            finally
            {
                RefreshResultsGrid();
            }
        }

        private void DetectRecentDocs()
        {
            try
            {
                string recentPath = @"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\\.exe";

                using (RegistryKey key = Registry.CurrentUser.OpenSubKey(recentPath))
                {
                    if (key != null)
                    {
                        int dummy;
                        foreach (var valueName in key.GetValueNames())
                        {
                            if (int.TryParse(valueName, out dummy))
                            {
                                byte[] data = key.GetValue(valueName) as byte[];
                                if (data != null)
                                {
                                    string value = Encoding.Unicode.GetString(data);
                                    if (value.IndexOf("CYZ", StringComparison.OrdinalIgnoreCase) >= 0)
                                    {
                                        detectionResults.Add(new DetectionResult
                                        {
                                            Method = "Recent Documents Registry",
                                            Detected = true,
                                            Details = "RecentDocs entry found"
                                        });
                                        RefreshResultsGrid();
                                        return;
                                    }
                                }
                            }
                        }
                    }
                }

                detectionResults.Add(new DetectionResult { Method = "Recent Documents Registry", Detected = false });
            }
            catch (Exception ex)
            {
                detectionResults.Add(new DetectionResult { Method = "Recent Documents Registry", Detected = false, Details = ex.Message });
            }
            finally
            {
                RefreshResultsGrid();
            }
        }

        private void DetectJumpLists()
        {
            try
            {
                string[] recentPaths = {
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), @"Microsoft\Windows\Recent\AutomaticDestinations"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), @"Microsoft\Windows\Recent\CustomDestinations")
                };

                foreach (var recentPath in recentPaths)
                {
                    if (Directory.Exists(recentPath))
                    {
                        var files = Directory.GetFiles(recentPath, "*", SearchOption.TopDirectoryOnly);
                        foreach (var file in files)
                        {
                            try
                            {
                                FileInfo fi = new FileInfo(file);
                                if (fi.Length > 1048576) continue;

                                string content = File.ReadAllText(file);
                                if (content.IndexOf("CYZ.exe", StringComparison.OrdinalIgnoreCase) >= 0)
                                {
                                    detectionResults.Add(new DetectionResult
                                    {
                                        Method = "Jump Lists and Recent Items",
                                        Detected = true,
                                        Details = "Jump List: " + Path.GetFileName(file)
                                    });
                                    RefreshResultsGrid();
                                    return;
                                }
                            }
                            catch { }
                        }
                    }
                }

                detectionResults.Add(new DetectionResult { Method = "Jump Lists and Recent Items", Detected = false });
            }
            catch (Exception ex)
            {
                detectionResults.Add(new DetectionResult { Method = "Jump Lists and Recent Items", Detected = false, Details = ex.Message });
            }
            finally
            {
                RefreshResultsGrid();
            }
        }

        private void DetectWER()
        {
            try
            {
                string[] werPaths = {
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Microsoft\Windows\WER\ReportQueue"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"Microsoft\Windows\WER\ReportQueue")
                };

                foreach (var werPath in werPaths)
                {
                    if (Directory.Exists(werPath))
                    {
                        var dirs = Directory.GetDirectories(werPath, "*CYZ*", SearchOption.TopDirectoryOnly);
                        if (dirs.Length > 0)
                        {
                            detectionResults.Add(new DetectionResult
                            {
                                Method = "Windows Error Reporting (WER)",
                                Detected = true,
                                Details = "WER: " + Path.GetFileName(dirs[0])
                            });
                            RefreshResultsGrid();
                            return;
                        }
                    }
                }

                detectionResults.Add(new DetectionResult { Method = "Windows Error Reporting (WER)", Detected = false });
            }
            catch (Exception ex)
            {
                detectionResults.Add(new DetectionResult { Method = "Windows Error Reporting (WER)", Detected = false, Details = ex.Message });
            }
            finally
            {
                RefreshResultsGrid();
            }
        }

        private void DetectApplicationEvents()
        {
            try
            {
                EventLog appLog = new EventLog("Application");
                int count = 0;
                int maxCheck = 100;

                foreach (EventLogEntry entry in appLog.Entries)
                {
                    if (count++ > maxCheck) break;

                    if (entry.Message != null && entry.Message.IndexOf("CYZ", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        detectionResults.Add(new DetectionResult
                        {
                            Method = "Application Event Log",
                            Detected = true,
                            Details = "Application event log entry found"
                        });
                        RefreshResultsGrid();
                        return;
                    }
                }

                detectionResults.Add(new DetectionResult { Method = "Application Event Log", Detected = false });
            }
            catch (Exception ex)
            {
                detectionResults.Add(new DetectionResult { Method = "Application Event Log", Detected = false, Details = ex.Message });
            }
            finally
            {
                RefreshResultsGrid();
            }
        }

        private void RefreshResultsGrid()
        {
            if (resultsGrid == null) return;

            if (resultsGrid.InvokeRequired)
            {
                resultsGrid.Invoke(new Action(() => RefreshResultsGrid()));
                return;
            }

            var rows = detectionResults.Select(r => new {
                Status = r.Detected ? "DETECTED" : "CLEAN",
                Method = r.Method,
                Details = string.IsNullOrEmpty(r.Details) ? "" : r.Details
            }).ToList();

            resultsGrid.DataSource = null;
            resultsGrid.DataSource = rows;
        }
    }

    // Cheater detection screen with flashing text
    public class CheaterForm : Form
    {
        private Label cheaterLabel;
        private Label detailsLabel;
        private System.Windows.Forms.Timer flashTimer;
        private bool isRed = true;
        private List<DetectionResult> detectedMethods;

        public CheaterForm(List<DetectionResult> detectedMethods)
        {
            this.detectedMethods = detectedMethods;
            InitializeComponents();
            StartFlashing();
        }

        private void InitializeComponents()
        {
            // Form settings
            this.Text = "UNAUTHORIZED SOFTWARE DETECTED";
            this.Size = new Size(1000, 700);
            this.StartPosition = FormStartPosition.CenterScreen;
            this.FormBorderStyle = FormBorderStyle.None;
            this.WindowState = FormWindowState.Maximized;
            this.BackColor = Color.Black;
            this.TopMost = true;

            // CHEATER label (flashing)
            cheaterLabel = new Label();
            cheaterLabel.Text = "? CHEATER DETECTED ?";
            cheaterLabel.Font = new Font("Arial", 72, FontStyle.Bold);
            cheaterLabel.ForeColor = Color.Red;
            cheaterLabel.BackColor = Color.Transparent;
            cheaterLabel.AutoSize = true;
            cheaterLabel.Location = new Point(100, 150);
            this.Controls.Add(cheaterLabel);

            // Details panel
            Panel detailsPanel = new Panel();
            detailsPanel.Size = new Size(800, 300);
            detailsPanel.Location = new Point(100, 350);
            detailsPanel.BackColor = Color.FromArgb(20, 20, 20);
            detailsPanel.BorderStyle = BorderStyle.FixedSingle;
            this.Controls.Add(detailsPanel);

            // Details label
            detailsLabel = new Label();
            detailsLabel.Font = new Font("Consolas", 14, FontStyle.Regular);
            detailsLabel.ForeColor = Color.FromArgb(255, 100, 100);
            detailsLabel.BackColor = Color.Transparent;
            detailsLabel.AutoSize = false;
            detailsLabel.Size = new Size(780, 280);
            detailsLabel.Location = new Point(10, 10);

            StringBuilder sb = new StringBuilder();
            sb.AppendLine("UNAUTHORIZED SOFTWARE DETECTED");
            sb.AppendLine();
            sb.AppendLine("Detection Count: " + detectedMethods.Count);
            sb.AppendLine();
            sb.AppendLine("Detected Methods:");
            sb.AppendLine();

            foreach (var result in detectedMethods)
            {
                sb.AppendLine("• " + result.Method);
                if (!string.IsNullOrEmpty(result.Details))
                {
                    sb.AppendLine("  " + result.Details);
                }
            }

            sb.AppendLine();
            sb.AppendLine("A detailed report has been saved to:");
            sb.AppendLine("DETECTION_REPORT.txt");

            detailsLabel.Text = sb.ToString();
            detailsPanel.Controls.Add(detailsLabel);

            // Close button
            Button closeButton = new Button();
            closeButton.Text = "CLOSE";
            closeButton.Font = new Font("Arial", 16, FontStyle.Bold);
            closeButton.Size = new Size(200, 60);
            closeButton.Location = new Point(400, 600);
            closeButton.BackColor = Color.FromArgb(100, 0, 0);
            closeButton.ForeColor = Color.White;
            closeButton.FlatStyle = FlatStyle.Flat;
            closeButton.Click += (s, e) => this.Close();
            this.Controls.Add(closeButton);

            // Center everything
            this.Load += (s, e) => CenterControls();
        }

        private void CenterControls()
        {
            cheaterLabel.Left = (this.ClientSize.Width - cheaterLabel.Width) / 2;

            foreach (Control ctrl in this.Controls)
            {
                if (ctrl is Panel || ctrl is Button)
                {
                    ctrl.Left = (this.ClientSize.Width - ctrl.Width) / 2;
                }
            }
        }

        private void StartFlashing()
        {
            flashTimer = new System.Windows.Forms.Timer();
            flashTimer.Interval = 500; // Flash every 500ms
            flashTimer.Tick += FlashTimer_Tick;
            flashTimer.Start();
        }

        private void FlashTimer_Tick(object sender, EventArgs e)
        {
            if (isRed)
            {
                cheaterLabel.ForeColor = Color.Yellow;
                isRed = false;
            }
            else
            {
                cheaterLabel.ForeColor = Color.Red;
                isRed = true;
            }
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            if (flashTimer != null)
            {
                flashTimer.Stop();
                flashTimer.Dispose();
            }
            base.OnFormClosing(e);
        }
    }

    public class DetectionResult
    {
        public string Method { get; set; }
        public bool Detected { get; set; }
        public string Details { get; set; }
    }

    public static class WebhookManager
    {
        /// <summary>
        /// Sends a Discord webhook with detection results
        /// </summary>
        /// <param name="detectedMethods">List of detection results</param>
        /// <param name="webhookUrl">Discord webhook URL (optional - will try to read from file if null)</param>
        /// <returns>True if webhook was sent successfully</returns>
        public static bool SendDetectionWebhook(List<DetectionResult> detectedMethods, string webhookUrl = null)
        {
            try
            {
                // Get webhook URL if not provided
                if (string.IsNullOrEmpty(webhookUrl))
                {
                    webhookUrl = GetWebhookUrl();
                    if (string.IsNullOrEmpty(webhookUrl))
                    {
                        Console.WriteLine("WebhookManager: No webhook URL found");
                        return false;
                    }
                }

                // Create the Discord embed payload
                string jsonPayload = CreateDiscordPayload(detectedMethods);

                // Send the webhook
                return SendWebhookRequest(webhookUrl, jsonPayload);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"WebhookManager Error: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Creates the Discord webhook payload with detection information
        /// </summary>
        private static string CreateDiscordPayload(List<DetectionResult> detectedMethods)
        {
            var detectedCount = detectedMethods?.Count ?? 0;
            var computerName = Environment.MachineName;
            var userName = Environment.UserName;
            var timestamp = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ");

            // Build JSON manually to avoid Newtonsoft.Json dependency
            StringBuilder json = new StringBuilder();
            json.Append("{");
            json.Append("\"username\":\"Ratz Security\",");
            json.Append("\"embeds\":[{");
            json.Append("\"title\":\"?? CHEAT DETECTION ALERT\",");

            if (detectedCount > 0)
            {
                json.Append($"\"description\":\"**UNAUTHORIZED SOFTWARE DETECTED**\\n\\n{detectedCount} detection method(s) triggered.\",");
                json.Append("\"color\":16711680,"); // Red
            }
            else
            {
                json.Append("\"description\":\"System scan completed - no unauthorized software detected.\",");
                json.Append("\"color\":65280,"); // Green
            }

            json.Append("\"fields\":[");

            // Add detection method fields
            if (detectedMethods != null && detectedMethods.Count > 0)
            {
                for (int i = 0; i < detectedMethods.Count; i++)
                {
                    var result = detectedMethods[i];
                    json.Append("{");
                    json.Append($"\"name\":\"?? {EscapeJsonString(result.Method)}\",");

                    string value = string.IsNullOrEmpty(result.Details) ?
                                  "Detection triggered" :
                                  $"```{EscapeJsonString(result.Details)}```";
                    json.Append($"\"value\":\"{EscapeJsonString(value)}\",");
                    json.Append("\"inline\":false");
                    json.Append("}");

                    if (i < detectedMethods.Count - 1) json.Append(",");
                }
                json.Append(",");
            }

            // Add system information field
            json.Append("{");
            json.Append("\"name\":\"?? System Information\",");
            json.Append($"\"value\":\"```Computer: {EscapeJsonString(computerName)}\\nUser: {EscapeJsonString(userName)}\\nTimestamp: {timestamp}```\",");
            json.Append("\"inline\":false");
            json.Append("}");

            json.Append("],"); // End fields
            json.Append("\"footer\":{\"text\":\"Ratz Cheat Detection System\"},");
            json.Append($"\"timestamp\":\"{timestamp}\"");
            json.Append("}]"); // End embeds
            json.Append("}"); // End payload

            return json.ToString();
        }

        /// <summary>
        /// Escapes special characters for JSON string values
        /// </summary>
        private static string EscapeJsonString(string input)
        {
            if (string.IsNullOrEmpty(input))
                return "";

            return input.Replace("\\", "\\\\")
                       .Replace("\"", "\\\"")
                       .Replace("\r", "\\r")
                       .Replace("\n", "\\n")
                       .Replace("\t", "\\t");
        }

        /// <summary>
        /// Returns the webhook URL. Prefer reading from webhook.txt in the executable folder.
        /// </summary>
        private static string GetWebhookUrl()
        {
            try
            {
                string exePath = AppDomain.CurrentDomain.BaseDirectory;
                string configPath = Path.Combine(exePath, "webhook.txt");
                if (File.Exists(configPath))
                {
                    var url = File.ReadAllText(configPath).Trim();
                    if (!string.IsNullOrEmpty(url))
                    {
                        Console.WriteLine("WebhookManager: Using webhook from webhook.txt");
                        return url;
                    }
                }
            }
            catch { }

            Console.WriteLine("WebhookManager: No webhook configured in webhook.txt");
            return null;
        }

        /// <summary>
        /// Validates if the URL is a valid Discord webhook URL
        /// </summary>
        private static bool IsValidWebhookUrl(string url)
        {
            if (string.IsNullOrWhiteSpace(url))
                return false;

            try
            {
                Uri uri = new Uri(url);
                return uri.Host.Contains("discord") && url.Contains("/webhooks/");
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Sends the actual webhook request to Discord
        /// </summary>
        private static bool SendWebhookRequest(string webhookUrl, string jsonPayload)
        {
            try
            {
                // Enable TLS 1.2
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

                using (var client = new WebClient())
                {
                    client.Headers[HttpRequestHeader.ContentType] = "application/json";
                    client.Headers[HttpRequestHeader.UserAgent] = "RatzCheatDetector/1.0";

                    Console.WriteLine($"WebhookManager: Sending webhook to Discord...");

                    byte[] data = Encoding.UTF8.GetBytes(jsonPayload);
                    byte[] response = client.UploadData(webhookUrl, "POST", data);

                    string responseText = Encoding.UTF8.GetString(response);
                    Console.WriteLine($"WebhookManager: Webhook sent successfully. Response: {responseText}");

                    return true;
                }
            }
            catch (WebException webEx)
            {
                Console.WriteLine($"WebhookManager: Web error sending webhook: {webEx.Message}");

                if (webEx.Response is HttpWebResponse httpResponse)
                {
                    using (var reader = new StreamReader(httpResponse.GetResponseStream()))
                    {
                        string errorResponse = reader.ReadToEnd();
                        Console.WriteLine($"WebhookManager: Server response: {errorResponse}");
                    }
                }

                return false;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"WebhookManager: Error sending webhook: {ex.Message}");
                return false;
            }
        }
    }
}
