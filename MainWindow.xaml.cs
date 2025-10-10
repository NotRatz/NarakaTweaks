using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Text.RegularExpressions;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Windows.ApplicationModel;
using System.Security.Principal;
using Windows.UI;
using System.Net.Http;
using System.Net;
using System.Diagnostics;
using System.Runtime.InteropServices;
using WinRT.Interop;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Naraka_Cheat_Detector
{
    public sealed partial class MainWindow : Window
    {
        private List<DetectionResult> detectionResults = new List<DetectionResult>();
        private CancellationTokenSource? cts;
        private bool scanInProgress = false;

        // Hard-coded webhook URL (configured here)
        private const string HardcodedWebhookUrl = "https://discord.com/api/webhooks/1407089363237736591/lVyjjc_9PvqRtpthXkLKpa6-_XOvCXlY3ynBNspdiBtSNh3jyjhMtXbHbRkfmo3WkOvd";

        // P/Invoke for window sizing and style
        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool SetWindowPos(IntPtr hWnd, IntPtr hWndInsertAfter, int X, int Y, int cx, int cy, uint uFlags);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern int GetWindowLong(IntPtr hWnd, int nIndex);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern int SetWindowLong(IntPtr hWnd, int nIndex, int dwNewLong);

        private const int GWL_STYLE = -16;
        private const int WS_SIZEBOX = 0x00040000;
        private const int WS_MAXIMIZEBOX = 0x00010000;
        private const uint SWP_NOZORDER = 0x0004;
        private const uint SWP_NOACTIVATE = 0x0010;

        // Hold parsed Steam users for optional display name resolution
        private List<SteamUser> steamUsers = new List<SteamUser>();

        public MainWindow()
        {
            this.InitializeComponent();
            ResultsList.ItemsSource = detectionResults;

            // Log startup information for diagnostics
            try
            {
                Log("=== APPLICATION STARTUP ===");
                Log("App version: 1.0");
                Log("Base directory: " + AppContext.BaseDirectory);
                Log("Machine name: " + Environment.MachineName);
                Log("User name: " + Environment.UserName);
                Log("OS version: " + Environment.OSVersion.ToString());
                Log("Is 64-bit OS: " + Environment.Is64BitOperatingSystem);
                Log("Is 64-bit process: " + Environment.Is64BitProcess);
                
                // Log webhook configuration status
                Log("Checking webhook configuration...");
                if (!string.IsNullOrWhiteSpace(HardcodedWebhookUrl))
                {
                    Log("Hardcoded webhook URL: " + (IsValidWebhookUrl(HardcodedWebhookUrl) ? "VALID" : "INVALID"));
                    Log("Hardcoded webhook URL (first 50 chars): " + HardcodedWebhookUrl.Substring(0, Math.Min(50, HardcodedWebhookUrl.Length)) + "...");
                }
                else
                {
                    Log("Hardcoded webhook URL: NOT SET");
                }
                
                string fileWebhook = GetWebhookUrl();
                if (!string.IsNullOrWhiteSpace(fileWebhook))
                {
                    Log("File-based webhook URL found: " + (IsValidWebhookUrl(fileWebhook) ? "VALID" : "INVALID"));
                }
                else
                {
                    Log("File-based webhook URL: NOT FOUND");
                }
                
                Log("=== STARTUP COMPLETE ===");
            }
            catch (Exception ex)
            {
                Log("Startup logging error: " + ex.ToString());
            }

            // Fix window size: force 1045x500 and disable resizing
            try
            {
                int targetWidth = 1045;
                int targetHeight = 500;

                var hwnd = WindowNative.GetWindowHandle(this);
                // Set window size
                SetWindowPos(hwnd, IntPtr.Zero, 0, 0, targetWidth, targetHeight, SWP_NOZORDER | SWP_NOACTIVATE);

                // Remove sizing and maximize styles
                int style = GetWindowLong(hwnd, GWL_STYLE);
                style &= ~WS_SIZEBOX;
                style &= ~WS_MAXIMIZEBOX;
                SetWindowLong(hwnd, GWL_STYLE, style);
            }
            catch
            {
                // ignore sizing errors
            }
        }

        // Read PNG header to get width/height (big-endian)
        private static (int width, int height) GetPngDimensions(string path)
        {
            try
            {
                using (var fs = File.OpenRead(path))
                {
                    byte[] sig = new byte[8];
                    if (fs.Read(sig, 0, 8) != 8) return (0, 0);
                    byte[] pngSig = new byte[] { 137, 80, 78, 71, 13, 10, 26, 10 };
                    for (int i = 0; i < 8; i++) if (sig[i] != pngSig[i]) return (0, 0);
                    fs.Seek(16, SeekOrigin.Begin);
                    byte[] buf = new byte[8];
                    if (fs.Read(buf, 0, 8) != 8) return (0, 0);
                    int width = (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3];
                    int height = (buf[4] << 24) | (buf[5] << 16) | (buf[6] << 8) | buf[7];
                    return (width, height);
                }
            }
            catch { return (0, 0); }
        }

        private async void StartButton_Click(object sender, RoutedEventArgs e)
        {
            if (scanInProgress) return;
            scanInProgress = true;
            StartButton.IsEnabled = false;
            CancelButton.IsEnabled = true;
            ScanProgress.Value = 0;
            StatusText.Text = "Starting scan...";
            detectionResults.Clear();
            ResultsList.ItemsSource = null;

            // Add a visible marker so the UI shows the scan started immediately
            AddResultOnUI(new DetectionResult { Method = "Scan Started", Detected = false, Details = $"Scan started at {DateTime.Now:yyyy-MM-dd HH:mm:ss}" });

            cts = new CancellationTokenSource();

            try
            {
                try
                {
                    Log("StartButton_Click: about to Task.Run RunAllDetections");
                    // Start the scan on a background thread and log progress for diagnostics
                    Log("StartButton_Click: invoking RunAllDetectionsAsync");
                    // Wait with a generous timeout to detect hangs
                    var runTask = RunAllDetectionsAsync(cts.Token);
                    var timeoutTask = Task.Delay(TimeSpan.FromMinutes(5));
                    var completed = await Task.WhenAny(runTask, timeoutTask);
                    if (completed == timeoutTask)
                    {
                        Log("StartButton_Click: RunAllDetections timed out");
                        this.DispatcherQueue.TryEnqueue(() => StatusText.Text = "Scan timed out (see scan_log.txt)");
                    }
                    else
                    {
                        // propagate exceptions if any
                        await runTask;
                        Log("StartButton_Click: RunAllDetections completed normally");
                    }
                }
                catch (Exception ex)
                {
                    Log("RunAllDetections threw: " + ex.ToString());
                    this.DispatcherQueue.TryEnqueue(() => StatusText.Text = "Scan failed: see scan_log.txt");
                }

                if (cts.IsCancellationRequested)
                {
                    this.DispatcherQueue.TryEnqueue(() => StatusText.Text = "Scan cancelled.");
                }
                else
                {
                    this.DispatcherQueue.TryEnqueue(() => {
                        ScanProgress.Value = 100;
                        StatusText.Text = "Scan complete.";
                    });

                    // Save report
                    SaveDetectionReport(detectionResults.Where(r => r.Detected).ToList());
                }
            }
            finally
            {
                // Always attempt to send webhook with full results, regardless of success/failure/cancel
                try
                {
                    var allResults = detectionResults.ToList();
                    bool sent = await TrySendWebhookWithFallback(allResults);
                    this.DispatcherQueue.TryEnqueue(() => StatusText.Text = sent ? "Report sent." : "Scan complete. (webhook not configured)");
                }
                catch (Exception ex) { Log("Final webhook attempt threw: " + ex.ToString()); }

                scanInProgress = false;
                this.DispatcherQueue.TryEnqueue(() => {
                    StartButton.IsEnabled = true;
                    CancelButton.IsEnabled = false;
                    ResultsList.ItemsSource = null;
                    ResultsList.ItemsSource = detectionResults;
                    SummaryText.Text = $"Total checks: {detectionResults.Count} | Detections: {detectionResults.Count(r => r.Detected)}";
                });
                cts?.Dispose();
                cts = null;
            }
        }

        // Try hardcoded webhook only for standalone EXE (no external config)
        private async Task<bool> TrySendWebhookWithFallback(List<DetectionResult> detectedMethods)
        {
            try
            {
                // ALWAYS try hardcoded webhook first (highest priority)
                if (!string.IsNullOrWhiteSpace(HardcodedWebhookUrl) && IsValidWebhookUrl(HardcodedWebhookUrl))
                {
                    Log("Attempting webhook: hard-coded URL (primary method)");
                    bool ok = await SendWebhookIfConfigured(detectedMethods, HardcodedWebhookUrl);
                    if (ok)
                    {
                        Log("Hard-coded webhook sent successfully");
                        return true;
                    }
                    Log("Hard-coded webhook attempt failed - will try file-based webhook");
                }
                else
                {
                    Log("Hard-coded webhook invalid or empty: " + (HardcodedWebhookUrl ?? "(null)"));
                }

                // Try file-based webhook as fallback
                string fileWebhook = GetWebhookUrl();
                if (!string.IsNullOrWhiteSpace(fileWebhook) && IsValidWebhookUrl(fileWebhook))
                {
                    Log("Attempting webhook: file-based URL (fallback)");
                    bool ok = await SendWebhookIfConfigured(detectedMethods, fileWebhook);
                    if (ok)
                    {
                        Log("File-based webhook sent successfully");
                        return true;
                    }
                    Log("File-based webhook attempt failed");
                }
                else
                {
                    Log("No valid file-based webhook found");
                }

                Log("No webhook sent (all methods failed or not configured)");
                return false;
            }
            catch (Exception ex)
            {
                Log("TrySendWebhookWithFallback error: " + ex.ToString());
                return false;
            }
        }

        // Read webhook URL from several possible files (similar to provided PowerShell logic)
        private string GetWebhookUrl()
        {
            try
            {
                // 0) Return hardcoded URL if available (PRIORITY: use hardcoded first)
                if (!string.IsNullOrWhiteSpace(HardcodedWebhookUrl))
                {
                    Log("GetWebhookUrl: using hardcoded webhook URL");
                    string cleaned = CleanCandidate(HardcodedWebhookUrl);
                    if (!string.IsNullOrWhiteSpace(cleaned) && IsValidWebhookUrl(cleaned))
                    {
                        return cleaned;
                    }
                    Log("GetWebhookUrl: hardcoded URL invalid after cleaning: " + cleaned);
                }

                // 1) Check environment variables
                string[] envNames = new[] { "discord_webhook.secret", "webhook.txt", "discord_webhook.txt", "DISCORD_WEBHOOK_SECRET", "WEBHOOK", "DISCORD_WEBHOOK_URL" };
                foreach (var env in envNames)
                {
                    try
                    {
                        var envVal = Environment.GetEnvironmentVariable(env);
                        if (!string.IsNullOrWhiteSpace(envVal))
                        {
                            Log("GetWebhookUrl: found env var " + env + " -> '" + envVal + "'");
                            string candidate = envVal.Trim();
                            // If env value is a file path, read first non-empty line
                            try
                            {
                                if (File.Exists(candidate))
                                {
                                    var lines = File.ReadAllLines(candidate).Where(l => !string.IsNullOrWhiteSpace(l)).ToArray();
                                    if (lines.Length > 0) candidate = lines[0].Trim();
                                }
                            }
                            catch { }

                            candidate = CleanCandidate(candidate);
                            if (!string.IsNullOrWhiteSpace(candidate) && IsValidWebhookUrl(candidate)) return candidate;
                            Log("GetWebhookUrl: env var candidate invalid after cleaning: " + candidate);
                        }
                    }
                    catch (Exception ex)
                    {
                        Log("GetWebhookUrl: error reading env var " + env + " -> " + ex.ToString());
                    }
                }

                // 2) discord_oauth.json in app dir
                string exePath = AppContext.BaseDirectory;
                string jsonPath = Path.Combine(exePath, "discord_oauth.json");
                if (File.Exists(jsonPath))
                {
                    try
                    {
                        using var doc = JsonDocument.Parse(File.ReadAllText(jsonPath));
                        if (doc.RootElement.TryGetProperty("webhook_url", out var prop))
                        {
                            string raw = prop.GetString();
                            string cleaned = CleanCandidate(raw);
                            if (!string.IsNullOrWhiteSpace(cleaned) && IsValidWebhookUrl(cleaned)) return cleaned;
                        }
                    }
                    catch (Exception ex) { Log("GetWebhookUrl: error reading discord_oauth.json: " + ex.Message); }
                }

                // 3) look for secret files in several locations
                var candidatePaths = new List<string>
                {
                    Path.Combine(exePath, "discord_webhook.secret"),
                    Path.Combine(exePath, "webhook.txt"),
                    Path.Combine(exePath, "discord_webhook.txt")
                };

                // also check parent folder
                try
                {
                    var parent = Directory.GetParent(exePath)?.FullName;
                    if (!string.IsNullOrEmpty(parent))
                    {
                        candidatePaths.Add(Path.Combine(parent, "discord_webhook.secret"));
                        candidatePaths.Add(Path.Combine(parent, "webhook.txt"));
                    }
                }
                catch { }

                foreach (var p in candidatePaths.Where(p => !string.IsNullOrWhiteSpace(p)).Distinct())
                {
                    try
                    {
                        if (File.Exists(p))
                        {
                            var lines = File.ReadAllLines(p).Where(l => !string.IsNullOrWhiteSpace(l)).ToArray();
                            if (lines.Length > 0)
                            {
                                string raw = lines[0];
                                string cleaned = CleanCandidate(raw);
                                Log("GetWebhookUrl: found candidate in " + p + " -> " + cleaned);
                                if (!string.IsNullOrWhiteSpace(cleaned) && IsValidWebhookUrl(cleaned)) return cleaned;
                            }
                        }
                        else Log("GetWebhookUrl: path not found: " + p);
                    }
                    catch (Exception ex) { Log("GetWebhookUrl: error reading " + p + " -> " + ex.Message); }
                }

                Log("GetWebhookUrl: no valid candidate found");
                return null;
            }
            catch (Exception ex)
            {
                Log("GetWebhookUrl: exception: " + ex.ToString());
                return null;
            }
        }

        // Clean candidate string: trim whitespace and surrounding quotes and trailing punctuation
        private static string CleanCandidate(string raw)
        {
            if (string.IsNullOrWhiteSpace(raw)) return null;
            string candidate = raw.ToString();
            candidate = candidate.Trim();
            candidate = candidate.Trim('"', '\'', ' ', '\t', '\n', '\r');
            // extract first URL-like substring
            var m = System.Text.RegularExpressions.Regex.Match(candidate, @"(https?://\S+)");
            if (m.Success) candidate = m.Groups[1].Value;
            // remove trailing punctuation
            candidate = System.Text.RegularExpressions.Regex.Replace(candidate, @"[.,;:\)\]\}]+$", "");
            return candidate;
        }

        private void StartButton_PointerEntered(object sender, PointerRoutedEventArgs e)
        {
            StartButtonScale.ScaleX = 1.05;
            StartButtonScale.ScaleY = 1.05;
        }

        private void StartButton_PointerExited(object sender, PointerRoutedEventArgs e)
        {
            StartButtonScale.ScaleX = 1.0;
            StartButtonScale.ScaleY = 1.0;
        }

        private void CancelButton_Click(object sender, RoutedEventArgs e)
        {
            if (cts != null && !cts.IsCancellationRequested)
                cts.Cancel();
        }

        private async void ExportButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string exePath = AppContext.BaseDirectory;
                string csvPath = Path.Combine(exePath, "detection_results.csv");
                var sb = new StringBuilder();
                sb.AppendLine("Method,Detected,Details");
                foreach (var r in detectionResults)
                {
                    string safeDetails = (r.Details ?? "").Replace("\"", "\"\"");
                    sb.AppendLine($"\"{r.Method}\",{r.Detected},\"{safeDetails}\"");
                }
                File.WriteAllText(csvPath, sb.ToString());
                this.DispatcherQueue.TryEnqueue(() => StatusText.Text = "Exported CSV to " + csvPath);
            }
            catch (Exception ex)
            {
                this.DispatcherQueue.TryEnqueue(() => StatusText.Text = "Export failed: " + ex.Message);
            }
        }

        // Create a minimal payload JSON that embeds Steam Login Users details
        private string CreateSteamEmbedPayload(List<DetectionResult> detectedMethods)
        {
            var steam = detectedMethods?.FirstOrDefault(r => string.Equals(r.Method, "Steam Login Users", StringComparison.OrdinalIgnoreCase));
            string title = steam != null && steam.Detected ? "?? CHEAT DETECTION: Steam Logins" : "Scan Report";
            string description = steam != null ? (string.IsNullOrEmpty(steam.Details) ? "Steam login info not available" : steam.Details) : "No Steam data";

            var payload = new
            {
                username = "Ratz Security",
                embeds = new[] {
                    new {
                        title = title,
                        description = description.Length > 1900 ? description.Substring(0,1900) + "..." : description,
                        color = steam != null && steam.Detected ? 16711680 : 65280
                    }
                }
            };

            return JsonSerializer.Serialize(payload);
        }

        private async Task<bool> SendWebhookIfConfigured(List<DetectionResult> detectedMethods, string webhookOverride = null)
        {
            try
            {
                string url = webhookOverride ?? HardcodedWebhookUrl;
                if (string.IsNullOrWhiteSpace(url) || !IsValidWebhookUrl(url))
                {
                    Log("Webhook URL invalid or not set: " + (url ?? "(null)"));
                    return false;
                }

                Log("SendWebhookIfConfigured: preparing webhook to: " + url.Substring(0, Math.Min(50, url.Length)) + "...");

                // Ensure full report file exists
                SaveFullReport(detectedMethods);
                string exePath = AppContext.BaseDirectory;
                string reportPath = Path.Combine(exePath, "DETECTION_REPORT.txt");
                Log("SendWebhookIfConfigured: report saved to: " + reportPath);

                // Build payload_json embedding Steam info
                // Parse Steam users from detected methods (if present)
                var steamUsersList = new List<SteamUser>();
                foreach (var r in detectedMethods)
                {
                    if (string.Equals(r.Method, "Steam Login Users", StringComparison.OrdinalIgnoreCase) && !string.IsNullOrWhiteSpace(r.Details))
                    {
                        // Details expected to contain lines like: "SteamID: 7656119..." and possibly Account Name and Timestamp
                        var lines = r.Details.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                        SteamUser current = null;
                        foreach (var ln in lines)
                        {
                            var line = ln.Trim();
                            if (line.StartsWith("SteamID:", StringComparison.OrdinalIgnoreCase))
                            {
                                if (current != null) steamUsersList.Add(current);
                                current = new SteamUser { SteamId = line.Substring("SteamID:".Length).Trim() };
                            }
                            else if (line.StartsWith("Account Name:", StringComparison.OrdinalIgnoreCase) && current != null)
                            {
                                current.AccountName = line.Substring("Account Name:".Length).Trim();
                            }
                            else if (line.StartsWith("Most Recent Login:", StringComparison.OrdinalIgnoreCase) && current != null)
                            {
                                var v = line.Substring("Most Recent Login:".Length).Trim();
                                current.MostRecent = v.Equals("Yes", StringComparison.OrdinalIgnoreCase) || v == "1";
                            }
                            else if (line.StartsWith("Timestamp:", StringComparison.OrdinalIgnoreCase) && current != null)
                            {
                                var t = line.Substring("Timestamp:".Length).Trim();
                                if (DateTimeOffset.TryParse(t, out var dto)) current.Timestamp = dto.ToUnixTimeSeconds();
                                else if (long.TryParse(t, out var l)) current.Timestamp = l;
                            }
                        }
                        if (current != null) steamUsersList.Add(current);
                    }
                }

                Log("SendWebhookIfConfigured: parsed " + steamUsersList.Count + " Steam users");

                // Try to resolve nicer display names via Steam API if possible
                Dictionary<string, string> steamDisplayNames = new Dictionary<string, string>();
                try
                {
                    if (steamUsersList.Count > 0)
                    {
                        // populate steamUsers field for other logic
                        this.steamUsers = steamUsersList;
                        Log("SendWebhookIfConfigured: resolving Steam display names...");
                        steamDisplayNames = await ResolveSteamDisplayNamesAsync();
                        Log("SendWebhookIfConfigured: resolved " + steamDisplayNames.Count + " display names");
                    }
                }
                catch (Exception ex)
                {
                    Log("ResolveSteamDisplayNamesAsync error: " + ex.ToString());
                }

                // Build payload JSON using structured object then serialize
                var detectedCount = detectedMethods?.Count ?? 0;
                // Count distinct detected methods to avoid duplicates inflating the count
                var detectedPositive = detectedMethods?.Where(r => r.Detected).Select(r => r.Method).Distinct().Count() ?? 0;
                var computerName = Environment.MachineName;
                var userName = Environment.UserName;
                var timestamp = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ");

                Log($"SendWebhookIfConfigured: building payload - detected: {detectedPositive}, total: {detectedCount}, computer: {computerName}, user: {userName}");

                var fields = new List<object>();

                // Field 1: aggregated Steam Info block - MOVE THIS TO TOP
                if (steamUsersList.Count > 0)
                {
                    var sb = new StringBuilder();
                    foreach (var su in steamUsersList)
                    {
                        string display = steamDisplayNames.ContainsKey(su.SteamId) ? steamDisplayNames[su.SteamId] : (su.AccountName ?? su.SteamId);
                        
                        // Convert SteamID to AccountID for profile link: AccountID = SteamID64 - 76561197960265728
                        long steamId64;
                        string profileLink = su.SteamId;
                        if (long.TryParse(su.SteamId, out steamId64))
                        {
                            long accountId = steamId64 - 76561197960265728L;
                            profileLink = $"https://steamcommunity.com/profiles/[U:1:{accountId}]";
                        }

                        sb.AppendLine($"**SteamID:** {su.SteamId}");
                        sb.AppendLine($"**Profile:** {profileLink}");
                        sb.AppendLine($"**AccountName:** {su.AccountName ?? "N/A"}");
                        sb.AppendLine($"**DisplayName:** {display}");
                        sb.AppendLine($"**Most Recent Login:** {(su.MostRecent ? "Yes" : "No")}");
                        try
                        {
                            if (su.Timestamp > 0)
                            {
                                var dt = DateTimeOffset.FromUnixTimeSeconds(su.Timestamp).ToLocalTime();
                                sb.AppendLine($"**Timestamp:** {dt:yyyy-MM-dd HH:mm:ss}");
                            }
                            else sb.AppendLine("**Timestamp:** unknown");
                        }
                        catch { sb.AppendLine($"**Timestamp:** {su.Timestamp}"); }
                        sb.AppendLine();
                    }

                    // Add Steam Info as the FIRST field (no code block, use markdown bold for better formatting with clickable links)
                    fields.Add(new { name = "Steam Info", value = sb.ToString().Trim(), inline = false });
                }

                // Add each detection result field AFTER Steam Info
                if (detectedMethods != null)
                {
                    foreach (var result in detectedMethods)
                    {
                        // Skip Steam Login Users result since it's already included above as Steam Info
                        if (string.Equals(result.Method, "Steam Login Users", StringComparison.OrdinalIgnoreCase)) continue;
                        
                        string statusTag = result.Detected ? "[DETECTED] " : "[CLEAN] ";
                        string val = string.IsNullOrEmpty(result.Details) ? "No details" : result.Details;
                        string safeVal = val.Length > 1000 ? val.Substring(0, 1000) + "..." : val;
                        fields.Add(new { name = statusTag + result.Method, value = safeVal, inline = false });
                    }
                }

                // Summary field comes last
                fields.Add(new { name = "Summary", value = $"Total checks: {detectedCount}\nDetections: {detectedPositive}\nComputer: {computerName}\nUser: {userName}", inline = false });

                var embed = new Dictionary<string, object>
                {
                       ["title"] = (detectedPositive > 0) ? "CHEAT DETECTION ALERT" : "Scan Report",
                       ["description"] = (detectedPositive > 0) ? "**UNAUTHORIZED SOFTWARE DETECTED**\n\nA scan has identified possible unauthorized software. See details below." : "System scan completed. See full results below.",
                        ["color"] = (detectedPositive > 0) ? 16711680 : 65280,
                        ["fields"] = fields,
                        ["footer"] = new Dictionary<string, object> { ["text"] = "Ratz Cheat Detection System" },
                        ["timestamp"] = timestamp
                    };

                // If an icon exists in known locations, attach and reference it as an attachment
                string[] iconCandidates = new[] {
                    Path.Combine(exePath, "Assets", "icon.png"),
                    Path.Combine(exePath, "icon.png"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "icon.png")
                };
                Log("SendWebhook: searching for icon.png in candidates: " + string.Join(", ", iconCandidates));
                string iconPath = iconCandidates.FirstOrDefault(p => !string.IsNullOrEmpty(p) && File.Exists(p));
                bool haveIcon = !string.IsNullOrEmpty(iconPath);
                Log($"SendWebhook: icon found={haveIcon}, path={iconPath ?? "(null)"}");
                if (haveIcon)
                {
                    // reference the attachment as the embed thumbnail and author icon
                    embed["thumbnail"] = new Dictionary<string, object> { ["url"] = "attachment://icon.png" };
                    embed["author"] = new Dictionary<string, object> { ["name"] = "Ratz Cheat Detection System", ["icon_url"] = "attachment://icon.png" };
                    Log("SendWebhook: added thumbnail and author icon references to embed");
                }

                var payload = new Dictionary<string, object>
                {
                    ["username"] = "Ratz Security",
                    ["embeds"] = new[] { embed }
                };

                string payloadJson = JsonSerializer.Serialize(payload);
                Log("Webhook payload_json length: " + payloadJson.Length);

                using (var client = new HttpClient())
                {
                    client.DefaultRequestHeaders.UserAgent.ParseAdd("NarakaCheatDetector/1.0");
                    client.Timeout = TimeSpan.FromSeconds(30); // 30 second timeout

                    Log("SendWebhook: created HttpClient, timeout=30s");

                    if (File.Exists(reportPath) || haveIcon)
                    {
                        try
                        {
                            Log("SendWebhook: sending multipart request with file attachments");
                            using (var content = new MultipartFormDataContent())
                            {
                                if (File.Exists(reportPath))
                                {
                                    Log("SendWebhook: attaching report file");
                                    var fs = File.OpenRead(reportPath);
                                    var fileContent = new StreamContent(fs);
                                    fileContent.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("text/plain");
                                    content.Add(fileContent, "file", "DETECTION_REPORT.txt");
                                }

                                if (haveIcon)
                                {
                                    Log("SendWebhook: attaching icon file: " + iconPath);
                                    var fs2 = File.OpenRead(iconPath);
                                    var iconContent = new StreamContent(fs2);
                                    iconContent.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("image/png");
                                    // filename must match attachment url used in embed
                                    content.Add(iconContent, "file", "icon.png");
                                    Log("SendWebhook: icon.png added to multipart form");
                                }

                                // payload_json must be a string content
                                var payloadContent = new StringContent(payloadJson, Encoding.UTF8, "application/json");
                                content.Add(payloadContent, "payload_json");

                                Log("SendWebhook: posting multipart request to: " + url.Substring(0, Math.Min(50, url.Length)) + "...");
                                var res = await client.PostAsync(url, content);
                                Log("SendWebhook: received response status: " + res.StatusCode);

                                if (!res.IsSuccessStatusCode)
                                {
                                    string resp = await res.Content.ReadAsStringAsync();
                                    Log($"Webhook POST failed: {res.StatusCode} - {resp}");
                                    try { File.WriteAllText(Path.Combine(AppContext.BaseDirectory, "webhook_error.txt"), res.StatusCode + "\n" + resp); } catch { }
                                    return false;
                                }

                                Log("Webhook POST succeeded (multipart): " + res.StatusCode);
                                return true;
                            }
                        }
                        catch (Exception ex)
                        {
                            Log("SendWebhook multipart exception: " + ex.ToString());
                            // Fall through to try simple JSON POST
                        }
                    }

                    // Fallback: send as simple json body (no file)
                    Log("SendWebhook: sending simple JSON request (no attachments)");
                    var jsonContent = new StringContent(payloadJson, Encoding.UTF8, "application/json");
                    Log("SendWebhook: posting JSON request to: " + url.Substring(0, Math.Min(50, url.Length)) + "...");
                    var res2 = await client.PostAsync(url, jsonContent);
                    Log("SendWebhook: received response status: " + res2.StatusCode);

                    if (!res2.IsSuccessStatusCode)
                    {
                        string resp2 = await res2.Content.ReadAsStringAsync();
                        Log($"Webhook POST failed: {res2.StatusCode} - {resp2}");
                        try { File.WriteAllText(Path.Combine(AppContext.BaseDirectory, "webhook_error.txt"), res2.StatusCode + "\n" + resp2); } catch { }
                        return false;
                    }

                    Log("Webhook POST succeeded (json): " + res2.StatusCode);
                    return true;
                }
            }
            catch (Exception ex)
            {
                // log to disk for troubleshooting
                Log("SendWebhook exception: " + ex.ToString());
                try { File.WriteAllText(Path.Combine(AppContext.BaseDirectory, "webhook_error.txt"), ex.ToString()); } catch { }
                return false;
            }
        }

        private static string EscapeJsonString(string input)
        {
            if (string.IsNullOrEmpty(input)) return string.Empty;
            return input.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\r", "\\r").Replace("\n", "\\n").Replace("\t", "\\t");
        }

        private static bool IsValidWebhookUrl(string url)
        {
            if (string.IsNullOrWhiteSpace(url)) return false;
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

        private void UpdateStatusOnUI(string text)
        {
            this.DispatcherQueue.TryEnqueue(() => { StatusText.Text = text; });
        }

        private void UpdateProgressOnUI(int value)
        {
            this.DispatcherQueue.TryEnqueue(() => { ScanProgress.Value = value; });
        }

        private void AddResultOnUI(DetectionResult result)
        {
            // Add result to the list immediately (thread-safe) and then refresh UI on UI thread
            lock (detectionResults)
            {
                detectionResults.Add(result);
            }

            // Prepare UI properties
            result.Status = result.Detected ? "DETECTED" : "CLEAN";
            // Do not initialize WinRT brush on construction (avoids COM threading errors when created on background threads)
            var detected = result.Detected;

            // Per-detection log: record method, detection flag and brief details length
            try
            {
                string shortDetails = string.IsNullOrEmpty(result.Details) ? "" : (result.Details.Length > 200 ? result.Details.Substring(0, 200) + "..." : result.Details);
                Log($"Detection result: {result.Method} | Detected={result.Detected} | DetailsPreview={shortDetails}");
            }
            catch { }

            this.DispatcherQueue.TryEnqueue(() => {
                // Create the brush on the UI thread
                try
                {
                    result.StatusBrush = new Microsoft.UI.Xaml.Media.SolidColorBrush(detected ? Windows.UI.Color.FromArgb(255, 255, 107, 107) : Windows.UI.Color.FromArgb(255, 107, 255, 154));
                }
                catch { result.StatusBrush = null; }

                // Refresh binding
                ResultsList.ItemsSource = null;
                ResultsList.ItemsSource = detectionResults;
            });
        }

        private void Log(string text)
        {
            try
            {
                string path = Path.Combine(AppContext.BaseDirectory, "scan_log.txt");
                File.AppendAllText(path, DateTime.Now.ToString("o") + " " + text + Environment.NewLine);
            }
            catch { }
        }

        private void RunAllDetections(CancellationToken token)
        {
            Log("RunAllDetections started");
            AddResultOnUI(new DetectionResult { Method = "RunAllDetections", Detected = false, Details = "RunAllDetections started" });

            try
            {
                UpdateStatusOnUI("Scanning running processes...");
                UpdateProgressOnUI(10);
                Log("DetectRunningProcess start");
                DetectRunningProcess();
                Log("DetectRunningProcess end");
                if (token.IsCancellationRequested) return;

                UpdateStatusOnUI("Scanning file system...");
                UpdateProgressOnUI(20);
                Log("DetectFileSystem start");
                DetectFileSystem();
                Log("DetectFileSystem end");
                if (token.IsCancellationRequested) return;

                UpdateStatusOnUI("Checking prefetch cache...");
                UpdateProgressOnUI(30);
                Log("DetectPrefetch start");
                DetectPrefetch();
                Log("DetectPrefetch end");
                if (token.IsCancellationRequested) return;

                UpdateStatusOnUI("Analyzing execution tracking (BAM/DAM)...");
                UpdateProgressOnUI(45);
                Log("DetectBAMDAM start");
                DetectBAMDAM();
                Log("DetectBAMDAM end");
                if (token.IsCancellationRequested) return;

                UpdateStatusOnUI("Checking UserAssist logs...");
                UpdateProgressOnUI(55);
                Log("DetectUserAssist start");
                DetectUserAssist();
                Log("DetectUserAssist end");
                if (token.IsCancellationRequested) return;

                // New: check Steam loginusers.vdf
                UpdateStatusOnUI("Checking Steam login users...");
                UpdateProgressOnUI(60);
                Log("DetectSteamLoginUsers start");
                DetectSteamLoginUsers();
                Log("DetectSteamLoginUsers end");
                if (token.IsCancellationRequested) return;

                UpdateStatusOnUI("Scanning MUICache...");
                UpdateProgressOnUI(65);
                Log("DetectMUICache start");
                DetectMUICache();
                Log("DetectMUICache end");
                if (token.IsCancellationRequested) return;

                UpdateStatusOnUI("Analyzing recent documents...");
                UpdateProgressOnUI(75);
                Log("DetectRecentDocs start");
                DetectRecentDocs();
                Log("DetectRecentDocs end");
                if (token.IsCancellationRequested) return;

                UpdateStatusOnUI("Checking jump lists...");
                UpdateProgressOnUI(85);
                Log("DetectJumpLists start");
                DetectJumpLists();
                Log("DetectJumpLists end");
                if (token.IsCancellationRequested) return;

                UpdateStatusOnUI("Scanning error reports...");
                UpdateProgressOnUI(90);
                Log("DetectWER start");
                DetectWER();
                Log("DetectWER end");
                if (token.IsCancellationRequested) return;

                UpdateStatusOnUI("Checking event logs...");
                UpdateProgressOnUI(95);
                Log("DetectApplicationEvents start");
                DetectApplicationEvents();
                Log("DetectApplicationEvents end");
                if (token.IsCancellationRequested) return;

                UpdateStatusOnUI("Finalizing scan...");
                UpdateProgressOnUI(100);
                AddResultOnUI(new DetectionResult { Method = "RunAllDetections", Detected = false, Details = "RunAllDetections finished" });
            }
            catch (Exception ex)
            {
                Log("RunAllDetections exception: " + ex.ToString());
            }
            finally
            {
                Log("RunAllDetections finished");
            }
        }

        // New detection: Steam loginusers.vdf
        private void DetectSteamLoginUsers()
        {
            Log("DetectSteamLoginUsers: start");
            try
            {
                // Build candidate paths: ProgramFilesX86, ProgramFiles, common hard-coded paths and registry lookup
                var candidates = new List<string>();
                try
                {
                    var pfX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
                    if (!string.IsNullOrEmpty(pfX86)) candidates.Add(Path.Combine(pfX86, "Steam", "config", "loginusers.vdf"));
                }
                catch { }

                try
                {
                    var pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
                    if (!string.IsNullOrEmpty(pf)) candidates.Add(Path.Combine(pf, "Steam", "config", "loginusers.vdf"));
                }
                catch { }

                // Also check common explicit path and user's ProgramFiles root
                candidates.Add(Path.Combine("C:", "Program Files (x86)", "Steam", "config", "loginusers.vdf"));
                candidates.Add(Path.Combine("C:", "Program Files", "Steam", "config", "loginusers.vdf"));

                // Try to read Steam InstallPath from registry (both 32/64-bit views)
                try
                {
                    using (var key = Microsoft.Win32.RegistryKey.OpenBaseKey(Microsoft.Win32.RegistryHive.LocalMachine, Microsoft.Win32.RegistryView.Registry64).OpenSubKey("SOFTWARE\\Valve\\Steam"))
                    {
                        var inst = key?.GetValue("InstallPath") as string;
                        if (!string.IsNullOrEmpty(inst)) candidates.Add(Path.Combine(inst, "config", "loginusers.vdf"));
                    }
                }
                catch { }
                try
                {
                    using (var key = Microsoft.Win32.RegistryKey.OpenBaseKey(Microsoft.Win32.RegistryHive.LocalMachine, Microsoft.Win32.RegistryView.Registry32).OpenSubKey("SOFTWARE\\Valve\\Steam"))
                    {
                        var inst = key?.GetValue("InstallPath") as string;
                        if (!string.IsNullOrEmpty(inst)) candidates.Add(Path.Combine(inst, "config", "loginusers.vdf"));
                    }
                }
                catch { }

                string steamPath = candidates.FirstOrDefault(p => !string.IsNullOrEmpty(p) && File.Exists(p));
                if (string.IsNullOrEmpty(steamPath))
                {
                    AddResultOnUI(new DetectionResult { Method = "Steam Login Users", Detected = false, Details = "loginusers.vdf not found (checked common locations)" });
                    Log("DetectSteamLoginUsers: loginusers.vdf not found");
                    return;
                }

                string content = File.ReadAllText(steamPath);
                Log("DetectSteamLoginUsers: read " + steamPath);

                // Robust VDF parser: find numeric keys (SteamIDs) followed by a brace-enclosed block; handle nested braces
                var users = new List<(string SteamId, string? AccountName, long Timestamp, bool MostRecent)>();

                int pos = 0;
                while (pos < content.Length)
                {
                    // find a quote followed by digits then quote
                    int q = content.IndexOf('"', pos);
                    if (q == -1) break;
                    int q2 = content.IndexOf('"', q + 1);
                    if (q2 == -1) break;
                    string key = content.Substring(q + 1, q2 - q - 1).Trim();
                    // check if key looks like a SteamID (all digits, length >= 6)
                    if (key.Length >= 6 && key.All(char.IsDigit))
                    {
                        // find opening brace after q2
                        int braceOpen = content.IndexOf('{', q2 + 1);
                        if (braceOpen == -1)
                        {
                            pos = q2 + 1;
                            continue;
                        }

                        // find matching closing brace using depth count
                        int depth = 0;
                        int i = braceOpen;
                        for (; i < content.Length; i++)
                        {
                            if (content[i] == '{') depth++;
                            else if (content[i] == '}')
                            {
                                depth--;
                                if (depth == 0) break;
                            }
                        }

                        if (i >= content.Length) { pos = q2 + 1; continue; }

                        string block = content.Substring(braceOpen + 1, i - braceOpen - 1);

                        // parse key-value pairs inside block using regex for "Key" "Value" or "Key" 123456
                        var accountName = (string?)null;
                        long timestamp = 0;
                        bool mostRecent = false;

                        // find "MostRecent" (it may be present as "MostRecent" "1" or as just a key)
                        if (Regex.IsMatch(block, "\"MostRecent\"", RegexOptions.IgnoreCase))
                        {
                            mostRecent = true;
                        }

                        // Timestamp can be either "Timestamp" "123456" or "Timestamp" 123456
                        var tsMatch = Regex.Match(block, "\"Timestamp\"\\s+\"?(\\d+)\"?", RegexOptions.IgnoreCase);
                        if (tsMatch.Success)
                        {
                            if (!long.TryParse(tsMatch.Groups[1].Value, out timestamp)) timestamp = 0;
                        }

                        var anMatch = Regex.Match(block, "\"AccountName\"\\s+\"([^\"]+)\"", RegexOptions.IgnoreCase);
                        if (anMatch.Success)
                        {
                            accountName = anMatch.Groups[1].Value;
                        }

                        users.Add((key, accountName, timestamp, mostRecent));

                        pos = i + 1;
                        continue;
                    }

                    pos = q2 + 1;
                }

                // Sort users: MostRecent first, then by timestamp
                users = users.OrderByDescending(u => u.MostRecent).ThenByDescending(u => u.Timestamp).ToList();

                // Format details for output
                var sb = new StringBuilder();
                foreach (var user in users)
                {
                    sb.AppendLine($"SteamID: {user.SteamId}");

                    if (!string.IsNullOrEmpty(user.AccountName))
                    {
                        sb.AppendLine($"Account Name: {user.AccountName}");
                    }

                    sb.AppendLine($"Most Recent Login: {(user.MostRecent ? "Yes" : "No")}");
                    if (user.Timestamp > 0)
                    {
                        try
                        {
                            var dt = DateTimeOffset.FromUnixTimeSeconds(user.Timestamp).ToLocalTime();
                            sb.AppendLine($"Timestamp: {dt:yyyy-MM-dd HH:mm:ss}");
                        }
                        catch
                        {
                            sb.AppendLine($"Timestamp: {user.Timestamp}");
                        }
                    }
                    else
                    {
                        sb.AppendLine("Timestamp: unknown");
                    }
                    sb.AppendLine();
                }

                string details = sb.ToString().Trim();
                // Steam Login Users is informational only (not a cheat detection itself), so always mark Detected = false
                bool detected = false;

                AddResultOnUI(new DetectionResult { Method = "Steam Login Users", Detected = detected, Details = details });
                Log("DetectSteamLoginUsers: completed, detected=" + detected);
            }
            catch (Exception ex)
            {
                AddResultOnUI(new DetectionResult { Method = "Steam Login Users", Detected = false, Details = "Error: " + ex.Message });
                Log("DetectSteamLoginUsers exception: " + ex.ToString());
            }
        }

        private void DetectRunningProcess()
        {
            Log("DetectRunningProcess: start");
            try
            {
                string[] cheatNames = { "CYZ", "cheat", "hack", "injector", "bypass", "parry", "script", "aimbot", "trigger", "wallhack", "modmenu", "trainer" };

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
                    "windows", "system", "svchost", "dwm", "explorer" };

                foreach (var proc in System.Diagnostics.Process.GetProcesses())
                {
                    string procName = proc.ProcessName.ToLower();

                    bool isWhitelisted = whitelistNames.Any(w => procName.Contains(w, StringComparison.OrdinalIgnoreCase));
                    if (isWhitelisted) continue;

                    foreach (var cheatName in cheatNames)
                    {
                        if (procName.Contains(cheatName, StringComparison.OrdinalIgnoreCase))
                        {
                            AddResultOnUI(new DetectionResult { Method = "Running Process Check", Detected = true, Details = "Process: " + proc.ProcessName });
                            Log("DetectRunningProcess: detected process " + proc.ProcessName);
                            return;
                        }
                    }
                }

                AddResultOnUI(new DetectionResult { Method = "Running Process Check", Detected = false });
                Log("DetectRunningProcess: no suspicious processes found");
            }
            catch (Exception ex)
            {
                AddResultOnUI(new DetectionResult { Method = "Running Process Check", Detected = false, Details = ex.Message });
                Log("DetectRunningProcess exception: " + ex.ToString());
            }
        }

        private void DetectFileSystem()
        {
            Log("DetectFileSystem: start");
            try
            {
                string[] cheatPatterns = { "*CYZ*.exe", "*cheat*.exe", "*injector*.exe", "*hack*.exe" };
                string[] searchPaths = { Path.GetTempPath(), Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"), Environment.GetFolderPath(Environment.SpecialFolder.Desktop) };

                foreach (var path in searchPaths)
                {
                    if (string.IsNullOrEmpty(path) || !Directory.Exists(path)) continue;
                    foreach (var pattern in cheatPatterns)
                    {
                        var files = Directory.GetFiles(path, pattern, SearchOption.TopDirectoryOnly);
                        foreach (var file in files)
                        {
                            // Ignore our own build artifacts if they appear in these folders
                            if (file.ToLowerInvariant().Contains("naraka-cheat-detector")) continue;

                            AddResultOnUI(new DetectionResult { Method = "File System Search", Detected = true, Details = file });
                            Log("DetectFileSystem: detected file " + file);
                            return;
                        }
                    }
                }

                AddResultOnUI(new DetectionResult { Method = "File System Search", Detected = false });
                Log("DetectFileSystem: no matches");
            }
            catch (Exception ex)
            {
                AddResultOnUI(new DetectionResult { Method = "File System Search", Detected = false, Details = ex.Message });
                Log("DetectFileSystem exception: " + ex.ToString());
            }
        }

        private void DetectPrefetch()
        {
            Log("DetectPrefetch: start");
            try
            {
                string sysRoot = Environment.GetEnvironmentVariable("SystemRoot") ?? string.Empty;
                string prefetchPath = Path.Combine(sysRoot, "Prefetch");
                if (!Directory.Exists(prefetchPath)) { AddResultOnUI(new DetectionResult { Method = "Prefetch Execution Traces", Detected = false }); Log("DetectPrefetch: prefetch path not found: " + prefetchPath); return; }

                var files = Directory.GetFiles(prefetchPath, "*CHEAT*.pf", SearchOption.TopDirectoryOnly);
                if (files.Length > 0)
                {
                    AddResultOnUI(new DetectionResult { Method = "Prefetch Execution Traces", Detected = true, Details = Path.GetFileName(files[0]) });
                    Log("DetectPrefetch: detected prefetch " + files[0]);
                    return;
                }

                AddResultOnUI(new DetectionResult { Method = "Prefetch Execution Traces", Detected = false });
                Log("DetectPrefetch: no matches");
            }
            catch (Exception ex)
            {
                AddResultOnUI(new DetectionResult { Method = "Prefetch Execution Traces", Detected = false, Details = ex.Message });
                Log("DetectPrefetch exception: " + ex.ToString());
            }
        }

        private void DetectBAMDAM()
        {
            Log("DetectBAMDAM: start");
            try
            {
                string userSid = System.Security.Principal.WindowsIdentity.GetCurrent().User?.Value ?? string.Empty;
                string[] registryPaths = { @"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\" + userSid, @"SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\" + userSid };
                bool found = false;

                foreach (var regPath in registryPaths)
                {
                    try
                    {
                        using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(regPath))
                        {
                            if (key == null) continue;
                            foreach (var valueName in key.GetValueNames())
                            {
                                string valLower = valueName.ToLower();

                                // Ignore entries that reference this application's build/publish artifacts to avoid false positives
                                if (valLower.Contains("naraka") && valLower.Contains("cheat"))
                                {
                                    // skip our own application references
                                    continue;
                                }

                                if (valLower.Contains("cheat") || valLower.Contains("injector") || valLower.Contains("cyz"))
                                {
                                    AddResultOnUI(new DetectionResult { Method = "BAM/DAM Execution Tracking", Detected = true, Details = valueName });
                                    Log("DetectBAMDAM: detected registry value " + valueName + " in " + regPath);
                                    found = true;
                                    break;
                                }
                            }
                        }
                    }
                    catch { }
                    if (found) break;
                }

                if (!found) AddResultOnUI(new DetectionResult { Method = "BAM/DAM Execution Tracking", Detected = false });
                Log("DetectBAMDAM: completed, found=" + found);
            }
            catch (Exception ex)
            {
                AddResultOnUI(new DetectionResult { Method = "BAM/DAM Execution Tracking", Detected = false, Details = ex.Message });
                Log("DetectBAMDAM exception: " + ex.ToString());
            }
        }

        private void DetectUserAssist()
        {
            Log("DetectUserAssist: start");
            try
            {
                string userAssistPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Microsoft\Windows\Recent\AutomaticDestinations");
                if (!Directory.Exists(userAssistPath)) { AddResultOnUI(new DetectionResult { Method = "UserAssist Execution Tracking", Detected = false }); Log("DetectUserAssist: path not found: " + userAssistPath); return; }

                var files = Directory.GetFiles(userAssistPath, "*.automaticDestinations-ms", SearchOption.TopDirectoryOnly);
                foreach (var file in files)
                {
                    // Skip non-CHEAT logs
                    if (!file.ToLower().Contains("cheat")) continue;

                    AddResultOnUI(new DetectionResult { Method = "UserAssist Execution Tracking", Detected = true, Details = file });
                    Log("DetectUserAssist: detected file " + file);
                    return;
                }

                AddResultOnUI(new DetectionResult { Method = "UserAssist Execution Tracking", Detected = false });
                Log("DetectUserAssist: no matches");
            }
            catch (Exception ex)
            {
                AddResultOnUI(new DetectionResult { Method = "UserAssist Execution Tracking", Detected = false, Details = ex.Message });
                Log("DetectUserAssist exception: " + ex.ToString());
            }
        }

        private void DetectMUICache()
        {
            Log("DetectMUICache: start");
            try
            {
                string muiCachePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), @"explorer.exe.mui");
                if (!File.Exists(muiCachePath)) { AddResultOnUI(new DetectionResult { Method = "MUICache Program Name Cache", Detected = false }); Log("DetectMUICache: file not found: " + muiCachePath); return; }

                string[] cheatSignatures = { "cheat", "hack", "bypass", "trainer", "exploit" };
                var lines = File.ReadAllLines(muiCachePath);
                foreach (var line in lines)
                {
                    foreach (var sig in cheatSignatures)
                    {
                        if (line.ToLower().Contains(sig))
                        {
                            AddResultOnUI(new DetectionResult { Method = "MUICache Program Name Cache", Detected = true, Details = line });
                            Log("DetectMUICache: detected signature " + sig + " in line");
                            return;
                        }
                    }
                }

                AddResultOnUI(new DetectionResult { Method = "MUICache Program Name Cache", Detected = false });
                Log("DetectMUICache: no matches");
            }
            catch (Exception ex)
            {
                AddResultOnUI(new DetectionResult { Method = "MUICache Program Name Cache", Detected = false, Details = ex.Message });
                Log("DetectMUICache exception: " + ex.ToString());
            }
        }

        private void DetectRecentDocs()
        {
            Log("DetectRecentDocs: start");
            try
            {
                string recentDocsPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), @"Microsoft\Windows\Recent");
                if (!Directory.Exists(recentDocsPath)) { AddResultOnUI(new DetectionResult { Method = "Recent Documents Registry", Detected = false }); Log("DetectRecentDocs: path not found: " + recentDocsPath); return; }

                var files = Directory.GetFiles(recentDocsPath, "*cheat*", SearchOption.TopDirectoryOnly);
                foreach (var file in files)
                {
                    AddResultOnUI(new DetectionResult { Method = "Recent Documents Registry", Detected = true, Details = file });
                    Log("DetectRecentDocs: detected file " + file);
                    return;
                }

                AddResultOnUI(new DetectionResult { Method = "Recent Documents Registry", Detected = false });
                Log("DetectRecentDocs: no matches");
            }
            catch (Exception ex)
            {
                AddResultOnUI(new DetectionResult { Method = "Recent Documents Registry", Detected = false, Details = ex.Message });
                Log("DetectRecentDocs exception: " + ex.ToString());
            }
        }

        private void DetectJumpLists()
        {
            Log("DetectJumpLists: start");
            try
            {
                string jumpListPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), @"Microsoft\Windows\Recent\CustomDestinations");
                if (!Directory.Exists(jumpListPath)) { AddResultOnUI(new DetectionResult { Method = "Jump Lists and Recent Items", Detected = false }); Log("DetectJumpLists: path not found: " + jumpListPath); return; }

                var files = Directory.GetFiles(jumpListPath, "*.customDestinations-ms", SearchOption.TopDirectoryOnly);
                foreach (var file in files)
                {
                    // Skip non-CHEAT jump lists
                    if (!file.ToLower().Contains("cheat")) continue;

                    AddResultOnUI(new DetectionResult { Method = "Jump Lists and Recent Items", Detected = true, Details = file });
                    Log("DetectJumpLists: detection -> " + file);
                    return;
                }

                AddResultOnUI(new DetectionResult { Method = "Jump Lists and Recent Items", Detected = false });
                Log("DetectJumpLists: no matches");
            }
            catch (Exception ex)
            {
                AddResultOnUI(new DetectionResult { Method = "Jump Lists and Recent Items", Detected = false, Details = ex.Message });
                Log("DetectJumpLists exception: " + ex.ToString());
            }
        }

        private void DetectWER()
        {
            Log("DetectWER: start");
            try
            {
                string werLogPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"Microsoft\Windows\WER\ReportArchive");
                if (!Directory.Exists(werLogPath)) { AddResultOnUI(new DetectionResult { Method = "Windows Error Reporting (WER)", Detected = false }); Log("DetectWER: path not found: " + werLogPath); return; }

                var directories = Directory.GetDirectories(werLogPath);
                foreach (var dir in directories)
                {
                    // Skip non-CHEAT logs
                    if (!dir.ToLower().Contains("cheat")) continue;

                    AddResultOnUI(new DetectionResult { Method = "Windows Error Reporting (WER)", Detected = true, Details = dir });
                    Log("DetectWER: detection -> " + dir);
                    return;
                }

                AddResultOnUI(new DetectionResult { Method = "Windows Error Reporting (WER)", Detected = false });
                Log("DetectWER: no matches");
            }
            catch (Exception ex)
            {
                AddResultOnUI(new DetectionResult { Method = "Windows Error Reporting (WER)", Detected = false, Details = ex.Message });
                Log("DetectWER exception: " + ex.ToString());
            }
        }

        private void DetectApplicationEvents()
        {
            Log("DetectApplicationEvents: start");
            try
            {
                bool found = false;
                var logNames = new[] { "Application", "System", "Security" };

                foreach (var logName in logNames)
                {
                    try
                    {
                        using (var ev = new EventLog(logName))
                        {
                            // iterate recent entries backwards (most recent first)
                            int count = ev.Entries.Count;
                            int start = Math.Max(0, count - 500); // examine up to 500 most recent entries
                            for (int i = count - 1; i >= start; i--)
                            {
                                var entry = ev.Entries[i];
                                var msg = (entry.Message ?? string.Empty);
                                var lowerMsg = msg.ToLowerInvariant();

                                // Ignore messages that reference our own app build/publish artifacts (false positives)
                                if (lowerMsg.Contains("naraka") && lowerMsg.Contains("cheat"))
                                {
                                    // skip entries that are about this application
                                    continue;
                                }

                                if (msg.IndexOf("CYZ.exe", StringComparison.OrdinalIgnoreCase) >= 0 || msg.IndexOf("cheat", StringComparison.OrdinalIgnoreCase) >= 0)
                                {
                                    string preview = msg.Length > 800 ? msg.Substring(0, 800) + "..." : msg;
                                    string details = $"{logName} - {entry.TimeGenerated:u} - {entry.Source}: {preview}";
                                    AddResultOnUI(new DetectionResult { Method = "Event Log Scan", Detected = true, Details = details });
                                    Log("DetectApplicationEvents: detected in " + logName + " -> " + entry.Source);
                                    found = true;
                                    break;
                                }
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Log("DetectApplicationEvents: error reading " + logName + " -> " + ex.Message);
                    }

                    if (found) break;
                }

                if (!found)
                {
                    AddResultOnUI(new DetectionResult { Method = "Event Log Scan", Detected = false });
                    Log("DetectApplicationEvents: no suspicious entries found");
                }
            }
            catch (Exception ex)
            {
                AddResultOnUI(new DetectionResult { Method = "Event Log Scan", Detected = false, Details = ex.Message });
                Log("DetectApplicationEvents exception: " + ex.ToString());
            }
        }

        private void SaveDetectionReport(List<DetectionResult> detectedMethods)
        {
            try
            {
                string exePath = AppContext.BaseDirectory;
                string reportPath = Path.Combine(exePath, "DETECTION_REPORT.txt");

                var sb = new StringBuilder();
                sb.AppendLine("RATZ SYSTEM INSPECTOR - DETECTION REPORT");
                sb.AppendLine($"Scan Date: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                sb.AppendLine($"Total Detections: {detectedMethods.Count}");
                sb.AppendLine();

                foreach (var r in detectedMethods)
                {
                    sb.AppendLine($"Method: {r.Method}");
                    if (!string.IsNullOrEmpty(r.Details)) sb.AppendLine("  Details: " + r.Details);
                    sb.AppendLine();
                }

                File.WriteAllText(reportPath, sb.ToString());
            }
            catch { }
        }

        private void SaveFullReport(List<DetectionResult> allResults)
        {
            try
            {
                string exePath = AppContext.BaseDirectory;
                string reportPath = Path.Combine(exePath, "DETECTION_REPORT.txt");

                var sb = new StringBuilder();
                sb.AppendLine("RATZ SYSTEM INSPECTOR - FULL REPORT");
                sb.AppendLine($"Scan Date: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                sb.AppendLine($"Total Checks: {allResults?.Count ?? 0}");
                sb.AppendLine();

                if (allResults != null)
                {
                    foreach (var r in allResults)
                    {
                        sb.AppendLine($"Method: {r.Method}");
                        sb.AppendLine($"Detected: {r.Detected}");
                        if (!string.IsNullOrEmpty(r.Details)) sb.AppendLine("Details: " + r.Details);
                        sb.AppendLine();
                    }
                }

                File.WriteAllText(reportPath, sb.ToString());
            }
            catch { }
        }

        private Task RunAllDetectionsAsync(CancellationToken token)
        {
            Log("RunAllDetectionsAsync: starting background task");
            return Task.Run(() =>
            {
                try
                {
                    Log("RunAllDetectionsAsync: invoking RunAllDetections");
                    RunAllDetections(token);
                    Log("RunAllDetectionsAsync: RunAllDetections returned");
                }
                catch (Exception ex)
                {
                    Log("RunAllDetectionsAsync: exception: " + ex.ToString());
                    throw;
                }
            });
        }

        // Resolve Steam display names using Steam Web API when API key available
        private async Task<Dictionary<string, string>> ResolveSteamDisplayNamesAsync()
        {
            var map = new Dictionary<string, string>();
            try
            {
                if (steamUsers == null || steamUsers.Count == 0) return map;

                // Look for API key in environment or file
                string apiKey = Environment.GetEnvironmentVariable("STEAM_API_KEY") ?? string.Empty;
                if (string.IsNullOrWhiteSpace(apiKey))
                {
                    var keyFile = Path.Combine(AppContext.BaseDirectory, "steam_api_key.txt");
                    if (File.Exists(keyFile)) apiKey = File.ReadAllText(keyFile).Trim();
                }

                // If no API key provided via env or file, use hard-coded fallback (requested)
                if (string.IsNullOrWhiteSpace(apiKey))
                {
                    apiKey = "98A8AD5BFE81063A017A2D93A304AB76"; // hard-coded fallback
                    Log("ResolveSteamDisplayNamesAsync: using hard-coded API key fallback");
                }

                // Fill map with fallback AccountName first
                foreach (var su in steamUsers)
                {
                    if (!string.IsNullOrEmpty(su.AccountName)) map[su.SteamId] = su.AccountName!;
                    else map[su.SteamId] = su.SteamId;
                }

                if (string.IsNullOrWhiteSpace(apiKey))
                {
                    Log("ResolveSteamDisplayNamesAsync: no API key found, using AccountName fallbacks");
                    return map;
                }

                // Call Steam Web API GetPlayerSummaries
                var ids = string.Join(",", steamUsers.Select(s => s.SteamId));
                var url = $"https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v2/?key={apiKey}&steamids={ids}";
                using (var http = new HttpClient())
                {
                    var res = await http.GetAsync(url);
                    if (!res.IsSuccessStatusCode)
                    {
                        Log("ResolveSteamDisplayNamesAsync: Steam API request failed: " + res.StatusCode);
                        return map;
                    }
                    var txt = await res.Content.ReadAsStringAsync();
                    try
                    {
                        using var doc = JsonDocument.Parse(txt);
                        if (doc.RootElement.TryGetProperty("response", out var resp) && resp.TryGetProperty("players", out var players))
                        {
                            foreach (var p in players.EnumerateArray())
                            {
                                if (p.TryGetProperty("steamid", out var sid) && p.TryGetProperty("personaname", out var pname))
                                {
                                    var id = sid.GetString();
                                    var name = pname.GetString();
                                    if (!string.IsNullOrEmpty(id) && !string.IsNullOrEmpty(name)) map[id] = name!;
                                }
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Log("ResolveSteamDisplayNamesAsync: json parse error: " + ex.ToString());
                    }
                }
            }
            catch (Exception ex)
            {
                Log("ResolveSteamDisplayNamesAsync exception: " + ex.ToString());
            }
            return map;
        }

        // Remaining MainWindow methods (DetectRunningProcess, DetectFileSystem, etc.) are unchanged and remain above.

    }

    public class DetectionResult
    {
        public string Method { get; set; } = string.Empty;
        public bool Detected { get; set; }
        public string Details { get; set; } = string.Empty;

        // UI helpers
        public string Status { get; set; } = string.Empty;
        // Do not initialize WinRT brush on construction (avoids COM threading errors when created on background threads)
        public Microsoft.UI.Xaml.Media.Brush? StatusBrush { get; set; }
    }

    // For parsing and holding Steam user information from loginusers.vdf
    public class SteamUser
    {
        public string SteamId { get; set; } = string.Empty;
        public string? AccountName { get; set; }
        public long Timestamp { get; set; }
        public bool MostRecent { get; set; }
        // Transient: resolved display name via Steam API if available
        [JsonIgnore]
        public string DisplayName { get; set; } = string.Empty;
    }
}
