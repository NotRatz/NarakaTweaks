# RatzTweaks.ps1
# Ensure $PSScriptRoot is set even when running via 'irm ... | iex'
if (-not $PSScriptRoot) { $PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $PSScriptRoot) { $PSScriptRoot = (Get-Location).Path }

# If the script is executed via 'irm | iex' the script has no file path; try to
# locate the project root by searching upward from the invocation directory
# for a folder that contains the 'UTILITY' folder (this repository layout).
function Resolve-ProjectRoot {
    param($startPath)
    $startPath = $startPath -or (Get-Location).Path
    $cur = $startPath
    while ($cur) {
        if (Test-Path (Join-Path $cur 'UTILITY')) { return $cur }
        $parent = Split-Path -Parent $cur
        if (-not $parent -or $parent -eq $cur) { break }
        $cur = $parent
    }
    return $startPath
}

$resolvedRoot = Resolve-ProjectRoot -startPath $PSScriptRoot
if ($resolvedRoot -and (Test-Path (Join-Path $resolvedRoot 'UTILITY'))) { $PSScriptRoot = $resolvedRoot }
# --- Show name in big text in PowerShell window, then suppress all further output ---
Write-Host ''
Write-Host 'RRRRR    AAAAA   TTTTTTT' -ForegroundColor Cyan
Write-Host 'RR  RR  AA   AA    TTT  ' -ForegroundColor Cyan
Write-Host 'RRRRR   AAAAAAA    TTT  ' -ForegroundColor Cyan
Write-Host 'RR RR   AA   AA    TTT  ' -ForegroundColor Cyan
Write-Host 'RR  RR  AA   AA    TTT  ' -ForegroundColor Cyan
Write-Host ''
Write-Host 'Rat Naraka Tweaks' -ForegroundColor Yellow
Write-Host ''
Write-Host 'Proceeding to next UI & WebUI' -ForegroundColor DarkGray
Write-Host ''
# Spinner: Loading Resources, please wait ...
$spinnerText = 'Loading Resources, please wait'
$spinnerFrames = @('.  ','.. ','...')
for ($i=0; $i -lt 12; $i++) {
    $frame = $spinnerFrames[$i % $spinnerFrames.Length]
    Write-Host ("$spinnerText$frame") -NoNewline
    Start-Sleep -Milliseconds 250
    Write-Host "`r" -NoNewline
}
Write-Host ''
function Write-Host { param([Parameter(ValueFromRemainingArguments=$true)][object[]]$args) } # no-op
function Write-Output { param([Parameter(ValueFromRemainingArguments=$true)][object[]]$args) } # no-op
$InformationPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'


# Ensure log path and PSCommandPath are defined even when run via iwr | iex
if (-not $PSCommandPath) { $PSCommandPath = Join-Path $PSScriptRoot 'RatzTweaks.ps1' }
$logPath = Join-Path $env:TEMP 'RatzTweaks_fatal.log'
# If log file exists from a previous run, delete and recreate it
if (Test-Path $logPath) {
    try { Remove-Item $logPath -Force } catch {}
    try { New-Item -Path $logPath -ItemType File -Force | Out-Null } catch {}
}
if (-not $global:RatzLog) { $global:RatzLog = @() }
if (-not $global:ErrorsDetected) { $global:ErrorsDetected = $false }
if (-not (Get-Variable -Name 'DiscordAuthError' -Scope Global -ErrorAction SilentlyContinue)) { $global:DiscordAuthError = $null }
if (-not (Get-Variable -Name 'DetectionTriggered' -Scope Global -ErrorAction SilentlyContinue)) { $global:DetectionTriggered = $false }

# Lightweight global logger used throughout the script
if (-not (Get-Command -Name Add-Log -ErrorAction SilentlyContinue)) {
    function global:Add-Log {
        param([Parameter(ValueFromRemainingArguments=$true)][object[]]$Message)
        try { $msg = -join $Message } catch { $msg = [string]::Join('', $Message) }
        if ($msg -match 'ERROR') { $global:ErrorsDetected = $true }
        try { $global:RatzLog += $msg } catch {}
        try {
            if ($logPath) {
                Add-Content -Path $logPath -Value ("{0}  {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $msg)
            }
        } catch {}
    }
}

# --- Auto-download all required files if missing (for irm ... | iex users) ---
$needDownload = $false
if (-not (Test-Path (Join-Path $PSScriptRoot 'UTILITY')) -or -not (Test-Path (Join-Path $PSScriptRoot 'RatzSettings.nip')) -or -not (Test-Path (Join-Path $PSScriptRoot 'ratznaked.jpg'))) {
    $needDownload = $true
}
if ($needDownload) {
    try {
        $repoZipUrl = 'https://github.com/NotRatz/NarakaTweaks/archive/refs/heads/main.zip'
        $tempDir = Join-Path $env:TEMP ('NarakaTweaks_' + [guid]::NewGuid().ToString())
        $zipPath = Join-Path $env:TEMP ('NarakaTweaks-main.zip')
        Write-Host 'Downloading full NarakaTweaks package...'
        Invoke-WebRequest -Uri $repoZipUrl -OutFile $zipPath -UseBasicParsing -ErrorAction Stop
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $tempDir)
        Remove-Item $zipPath -Force
        $extractedRoot = Join-Path $tempDir 'NarakaTweaks-main'
        $mainScript = Join-Path $extractedRoot 'RatzTweaks.ps1'
        Write-Host 'Launching full RatzTweaks.ps1 from temp folder...'
        Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$mainScript`" -WindowStyle Hidden"
        Stop-Process -Id $PID -Force
    } catch {
        Add-Log "ERROR downloading package: $($_.Exception.Message)"
    }
}
if ($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.Major -gt 5) {
    $msg = @"
RatzTweaks requires Windows PowerShell 5.1.
Please run this script using powershell.exe.
"@
    [Console]::WriteLine($msg)
    exit 1
}

# --- Administrator privilege check (required for HKLM registry writes) ---
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    [Console]::WriteLine('RatzTweaks: Administrator privileges required. Attempting to restart with elevation...')
    try {
        $scriptPath = $PSCommandPath
        if (-not $scriptPath) { $scriptPath = Join-Path $PSScriptRoot 'RatzTweaks.ps1' }
        Start-Process -FilePath 'powershell.exe' -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`"" -Verb RunAs
        [Console]::WriteLine('RatzTweaks: Elevated instance started. Closing current instance.')
        exit 0
    } catch {
        [Console]::WriteLine("RatzTweaks: Failed to elevate: $($_.Exception.Message)")
        [Console]::WriteLine('RatzTweaks: Please run this script as Administrator.')
        exit 1
    }
}

# --- Registry lockout check ---
$lockoutKeyPath = 'HKLM:\System\GameConfigStore'
$lockoutValueName = 'Lockout'
try {
    if (Test-Path $lockoutKeyPath) {
        $lockoutValue = Get-ItemProperty -Path $lockoutKeyPath -Name $lockoutValueName -ErrorAction SilentlyContinue
        if ($lockoutValue -and $lockoutValue.$lockoutValueName -eq 1) {
            [Console]::WriteLine('RatzTweaks: Lockout detected. Exiting.')
            exit 0
        }
    }
} catch {
    # Silently continue if registry check fails
}

# --- Revert logic for optional tweaks ---
function Revert-OptionalTweaks {
    try {
        Revert-MSIMode
        Revert-BackgroundApps
        Revert-Widgets
        Revert-Gamebar
        Revert-Copilot
        Restore-DefaultTimers
        Revert-PowerPlan
        Add-Log 'All optional tweaks reverted.'
    } catch {
        Add-Log "ERROR reverting optional tweaks: $($_.Exception.Message)"
    }
}

# --- Naraka: Bladepoint patching ---
function Patch-NarakaBladepoint {
    param(
        [bool]$EnableJiggle,
        [bool]$PatchBoot,
        [string]$CustomPath
    )
    Add-Log "Patch-NarakaBladepoint called: EnableJiggle=$EnableJiggle PatchBoot=$PatchBoot CustomPath=$CustomPath"
    $root = if ($CustomPath) { $CustomPath } else { Find-NarakaDataPath }
    if ($root -and $root -notmatch '(?i)NarakaBladepoint_Data$') { $root = Join-Path $root 'NarakaBladepoint_Data' }
    if (-not $root -or -not (Test-Path $root)) { Add-Log 'NarakaBladepoint_Data folder not found. Skipping Naraka tweaks.'; return }
    $dstBoot = Join-Path $root 'boot.config'
    $dstJiggle = Join-Path $root 'QualitySettingsData.txt'
    if ($PatchBoot) {
        $srcBoot = Join-Path $PSScriptRoot 'boot.config'
        if (Test-Path $srcBoot) {
            try { Copy-Item -Path $srcBoot -Destination $dstBoot -Force; Add-Log "Patched boot.config at $dstBoot" } catch { Add-Log "Naraka boot.config copy failed: $($_.Exception.Message)" }
        }
    }

    if ($EnableJiggle) {
        $content = Get-Content -Raw -Path $dstJiggle
        if ($content -match '"characterAdditionalPhysics1"\s*:\s*false') {
            $patched = $content -replace '"characterAdditionalPhysics1"\s*:\s*false', '"characterAdditionalPhysics1": true'
            Set-Content -Path $dstJiggle -Value $patched
            Add-Log "Patched: characterAdditionalPhysics1 set to true in $dstJiggle."
        } elseif ($content -match '"characterAdditionalPhysics1"\s*:\s*true') {
            Add-Log "Already enabled: characterAdditionalPhysics1 is true in $dstJiggle."
        } else {
            Add-Log "ERROR: No jiggle flag found to toggle in $dstJiggle"
        }
    } catch {
        Add-Log "Jiggle edit failed: $($_.Exception.Message)"
        return
    }
}

function Revert-MSIMode {
    try {
        $pciDevices = Get-WmiObject Win32_PnPEntity | Where-Object { $_.DeviceID -like 'PCI*' }
        foreach ($dev in $pciDevices) {
            $devId = $dev.DeviceID -replace '\', '#'
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\$($devId)\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties"
            if (Test-Path $regPath) {
                Remove-ItemProperty -Path $regPath -Name 'MSISupported' -ErrorAction SilentlyContinue
            }
        }
        Add-Log 'MSI Mode reverted for all PCI devices.'
    } catch { Add-Log "ERROR in Revert-MSIMode: $($_.Exception.Message)" }
}

function Revert-BackgroundApps {
    try {
        Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications' -Name 'GlobalUserDisabled' -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name 'LetAppsRunInBackground' -ErrorAction SilentlyContinue
        Add-Log 'Background Apps revert complete.'
    } catch { Add-Log "ERROR in Revert-BackgroundApps: $($_.Exception.Message)" }
}

function Revert-Widgets {
    try {
        Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Dsh' -Name 'AllowNewsAndInterests' -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds' -Name 'ShellFeedsTaskbarViewMode' -ErrorAction SilentlyContinue
        Add-Log 'Widgets revert complete.'
    } catch { Add-Log "ERROR in Revert-Widgets: $($_.Exception.Message)" }
}

function Revert-Gamebar {
    try {
        Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR' -Name 'AppCaptureEnabled' -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\GameBar' -Name 'ShowStartupPanel' -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\GameBar' -Name 'AutoGameModeEnabled' -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\GameBar' -Name 'GamePanelStartupTipIndex' -ErrorAction SilentlyContinue
        Add-Log 'Game Bar revert complete.'
    } catch { Add-Log "ERROR in Revert-Gamebar: $($_.Exception.Message)" }
}

function Revert-Copilot {
    try {
        Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'ShowCopilotButton' -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot' -Name 'TurnOffWindowsCopilot' -ErrorAction SilentlyContinue
        Add-Log 'Copilot revert complete.'
    } catch { Add-Log "ERROR in Revert-Copilot: $($_.Exception.Message)" }
}

if (-not (Get-Command -Name global:Disable-ViVeFeatures -ErrorAction SilentlyContinue)) {
    function global:Disable-ViVeFeatures {
        try {
            $viveToolPath = Join-Path $PSScriptRoot 'UTILITY' 'ViVeTool.exe'
            if (-not (Test-Path $viveToolPath)) { Add-Log 'ViVeTool.exe not found.'; return }
            $featureIds = @(39145991, 39146010, 39281392, 41655236, 42105254)
            foreach ($id in $featureIds) {
                $cmd = '"' + $viveToolPath + '" /disable /id:' + $id
                Add-Log "Running: cmd.exe /c $cmd"
                try {
                    Add-Log "CMD: cmd.exe /c $cmd"
                    $proc = Start-Process -FilePath cmd.exe -ArgumentList @('/c', $cmd) -Wait -NoNewWindow -PassThru
                    if ($proc.ExitCode -ne 0) {
                        Add-Log "ViVeTool exited with code $($proc.ExitCode) for id $id"
                    }
                } catch {
                    Add-Log "ViVeTool run failed: $($_.Exception.Message)"
                }
            }
            Add-Log 'ViVeTool features disabled.'
        } catch { Add-Log "ERROR in Disable-ViVeFeatures: $($_.Exception.Message)" }
    }
}


function Invoke-AllTweaks {
    # Only proceed if Discord OAuth completed before making any changes
    if (-not $global:DiscordAuthenticated) {
        Add-Log 'Discord authentication required — aborting tweaks.'
        return
    }
    
    # Block tweaks if detection was triggered
    if ($global:DetectionTriggered) {
        Add-Log 'Detection positive — tweaks aborted.'
        [Console]::WriteLine('Invoke-AllTweaks: blocked due to detection')
        return
    }

    # Main registry and system tweaks from RatzTweak.bat
    Write-Host "Applying main registry and system tweaks..."
    $regCmds = @(
        'reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "10" /f',
        'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "GPU_SCHEDULER_MODE" /t REG_SZ /d "22" /f',
        'reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "0" /f',
        'reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d "8" /f',
        'reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d "6" /f',
        'reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f',
        'reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f',
        'reg add "HKLM\SYSTEM\ControlSet001\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "40" /f',
        'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel" /v "SerializeTimerExpiration" /t REG_DWORD /d "1" /f',
        'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettings" /t REG_DWORD /d "1" /f',
        'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d "3" /f',
        'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsMask" /t REG_DWORD /d "3" /f',
        'reg add "HKCU\Control Panel\Keyboard" /v "InitialKeyboardIndicators" /t REG_SZ /d "2" /f',
        'reg add "HKCU\Control Panel\Keyboard" /v "KeyboardSpeed" /t REG_SZ /d "48" /f',
        'reg add "HKCU\Control Panel\Keyboard" /v "KeyboardDelay" /t REG_SZ /d "0" /f',
        'reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers" /v "C:\\Windows\\System32\\dwm.exe" /t REG_SZ /d "NoDTToDITMouseBatch" /f'
    )

    foreach ($cmd in $regCmds) {
        try {
            # Extract the registry path from the reg add command and pre-create the key if needed
            if ($cmd -match 'reg add "([^"]+)"') {
                $regPath = $matches[1]
                $hive, $subkey = $regPath -split('\\',2)
                if ($hive -and $subkey) {
                    $psHive = switch ($hive.ToUpper()) {
                        'HKLM' { 'HKLM:' }
                        'HKCU' { 'HKCU:' }
                        default { $hive + ':' }
                    }
                    $fullKey = $psHive + $subkey
                    if (-not (Test-Path $fullKey)) { New-Item -Path $fullKey -Force | Out-Null }
                }
            }
            Invoke-Expression $cmd 2>$null
        } catch {
            # Suppress error output, optionally log to file if needed
        }
    }

# Set timer resolution using embedded C# service (no external EXE needed)
try {
    Write-Host "Installing: Set Timer Resolution Service ..."
    $csPath = "$env:SystemDrive\Windows\SetTimerResolutionService.cs"
    $exePath = "$env:SystemDrive\Windows\SetTimerResolutionService.exe"
    $cscPath = "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
    if (-not (Test-Path $cscPath)) { $cscPath = "C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe" }

    # IMPORTANT: ServiceBase.ServiceName in code == actual service name you create
    $serviceName   = "STR"
    $displayName   = "Set Timer Resolution Service"

    $MultilineComment = @"
using System;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.ComponentModel;
using System.Configuration.Install;
using System.Collections.Generic;
using System.Reflection;
using System.IO;
using System.Management;
using System.Threading;
using System.Diagnostics;
[assembly: AssemblyVersion("2.1")]
[assembly: AssemblyProduct("Set Timer Resolution service")]
namespace WindowsService
{
    class WindowsService : ServiceBase
    {
        public WindowsService()
        {
            this.ServiceName = "STR";
            this.EventLog.Log = "Application";
            this.CanStop = true;
            this.CanHandlePowerEvent = false;
            this.CanHandleSessionChangeEvent = false;
            this.CanPauseAndContinue = false;
            this.CanShutdown = false;
        }
        static void Main()
        {
            ServiceBase.Run(new WindowsService());
        }
        protected override void OnStart(string[] args)
        {
            base.OnStart(args);
            ReadProcessList();
            NtQueryTimerResolution(out this.MininumResolution, out this.MaximumResolution, out this.DefaultResolution);
            if(null != this.EventLog)
                try { this.EventLog.WriteEntry(String.Format("Minimum={0}; Maximum={1}; Default={2}; Processes='{3}'", this.MininumResolution, this.MaximumResolution, this.DefaultResolution, null != this.ProcessesNames ? String.Join("','", this.ProcessesNames) : "")); }
                catch {}
            if(null == this.ProcessesNames)
            {
                SetMaximumResolution();
                return;
            }
            if(0 == this.ProcessesNames.Count)
            {
                return;
            }
            this.ProcessStartDelegate = new OnProcessStart(this.ProcessStarted);
            try
            {
                String query = String.Format("SELECT * FROM __InstanceCreationEvent WITHIN 0.5 WHERE (TargetInstance isa \"Win32_Process\") AND (TargetInstance.Name=\"{0}\")", String.Join("\" OR TargetInstance.Name=\"", this.ProcessesNames));
                this.startWatch = new ManagementEventWatcher(query);
                this.startWatch.EventArrived += this.startWatch_EventArrived;
                this.startWatch.Start();
            }
            catch(Exception ee)
            {
                if(null != this.EventLog)
                    try { this.EventLog.WriteEntry(ee.ToString(), EventLogEntryType.Error); }
                    catch {}
            }
        }
        protected override void OnStop()
        {
            if(null != this.startWatch)
            {
                this.startWatch.Stop();
            }
            // Restore default timer resolution on service stop
            try {
                uint actual = 0;
                NtSetTimerResolution(this.DefaultResolution, true, out actual);
                if(null != this.EventLog)
                    try { this.EventLog.WriteEntry(String.Format("Restored default; Actual={0}", actual)); }
                    catch {}
            } catch {}
            base.OnStop();
        }
        ManagementEventWatcher startWatch;
        void startWatch_EventArrived(object sender, EventArrivedEventArgs e) 
        {
            try
            {
                ManagementBaseObject process = (ManagementBaseObject)e.NewEvent.Properties["TargetInstance"].Value;
                UInt32 processId = (UInt32)process.Properties["ProcessId"].Value;
                this.ProcessStartDelegate.BeginInvoke(processId, null, null);
            } 
            catch(Exception ee) 
            {
                if(null != this.EventLog)
                    try { this.EventLog.WriteEntry(ee.ToString(), EventLogEntryType.Warning); }
                    catch {}

            }
        }
        [DllImport("kernel32.dll", SetLastError=true)]
        static extern Int32 WaitForSingleObject(IntPtr Handle, Int32 Milliseconds);
        [DllImport("kernel32.dll", SetLastError=true)]
        static extern IntPtr OpenProcess(UInt32 DesiredAccess, Int32 InheritHandle, UInt32 ProcessId);
        [DllImport("kernel32.dll", SetLastError=true)]
        static extern Int32 CloseHandle(IntPtr Handle);
        const UInt32 SYNCHRONIZE = 0x00100000;
        delegate void OnProcessStart(UInt32 processId);
        OnProcessStart ProcessStartDelegate = null;
        void ProcessStarted(UInt32 processId)
        {
            SetMaximumResolution();
            IntPtr processHandle = IntPtr.Zero;
            try
            {
                processHandle = OpenProcess(SYNCHRONIZE, 0, processId);
                if(processHandle != IntPtr.Zero)
                    WaitForSingleObject(processHandle, -1);
            } 
            catch(Exception ee) 
            {
                if(null != this.EventLog)
                    try { this.EventLog.WriteEntry(ee.ToString(), EventLogEntryType.Warning); }
                    catch {}
            }
            finally
            {
                if(processHandle != IntPtr.Zero)
                    CloseHandle(processHandle); 
            }
            SetDefaultResolution();
        }
        List<String> ProcessesNames = null;
        void ReadProcessList()
        {
            String iniFilePath = Assembly.GetExecutingAssembly().Location + ".ini";
            if(File.Exists(iniFilePath))
            {
                this.ProcessesNames = new List<String>();
                String[] iniFileLines = File.ReadAllLines(iniFilePath);
                foreach(var line in iniFileLines)
                {
                    String[] names = line.Split(new char[] {',', ' ', ';'} , StringSplitOptions.RemoveEmptyEntries);
                    foreach(var name in names)
                    {
                        String lwr_name = name.ToLower();
                        if(!lwr_name.EndsWith(".exe"))
                            lwr_name += ".exe";
                        if(!this.ProcessesNames.Contains(lwr_name))
                            this.ProcessesNames.Add(lwr_name);
                    }
                }
            }
        }
        [DllImport("ntdll.dll", SetLastError=true)]
        static extern int NtSetTimerResolution(uint DesiredResolution, bool SetResolution, out uint CurrentResolution);
        [DllImport("ntdll.dll", SetLastError=true)]
        static extern int NtQueryTimerResolution(out uint MinimumResolution, out uint MaximumResolution, out uint ActualResolution);
        uint DefaultResolution = 0;
        uint MininumResolution = 0;
        uint MaximumResolution = 0;
        long processCounter = 0;
        void SetMaximumResolution()
        {
            // Force 5040 (0.504 ms) regardless of reported Maximum; kernel clamps if unsupported.
            long counter = Interlocked.Increment(ref this.processCounter);
            if(counter <= 1)
            {
                uint actual = 0;
                NtSetTimerResolution(5040, true, out actual);
                if(null != this.EventLog)
                    try { this.EventLog.WriteEntry(String.Format("Requested=5040; Actual={0}", actual)); }
                    catch {}
            }
        }
        void SetDefaultResolution()
        {
            long counter = Interlocked.Decrement(ref this.processCounter);
            if(counter < 1)
            {
                uint actual = 0;
                NtSetTimerResolution(this.DefaultResolution, true, out actual);
                if(null != this.EventLog)
                    try { this.EventLog.WriteEntry(String.Format("Actual resolution = {0}", actual)); }
                    catch {}
            }
        }
    }
    [RunInstaller(true)]
    public class WindowsServiceInstaller : Installer
    {
        public WindowsServiceInstaller()
        {
            ServiceProcessInstaller serviceProcessInstaller = 
                               new ServiceProcessInstaller();
            ServiceInstaller serviceInstaller = new ServiceInstaller();
            serviceProcessInstaller.Account = ServiceAccount.LocalSystem;
            serviceProcessInstaller.Username = null;
            serviceProcessInstaller.Password = null;
            serviceInstaller.DisplayName = "Set Timer Resolution Service";
            serviceInstaller.StartType = ServiceStartMode.Automatic;
            serviceInstaller.ServiceName = "STR";
            this.Installers.Add(serviceProcessInstaller);
            this.Installers.Add(serviceInstaller);
        }
    }
}
"@

    Set-Content -Path $csPath -Value $MultilineComment -Force

    if (Test-Path $cscPath) {
        Start-Process -Wait $cscPath -ArgumentList "-out:$exePath $csPath" -WindowStyle Hidden
        Remove-Item $csPath -ErrorAction SilentlyContinue | Out-Null

        # Remove any prior service with either name
        foreach ($old in @("STR","Set Timer Resolution Service")) {
            $svc = Get-Service -Name $old -ErrorAction SilentlyContinue
            if ($svc) {
                try {
                    Set-Service -Name $old -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
                    Stop-Service -Name $old -Force -ErrorAction SilentlyContinue | Out-Null
                    sc.exe delete $old | Out-Null
                } catch {}
            }
        }

        # Install and start service (name must be STR to match ServiceBase.ServiceName)
        New-Service -Name $serviceName -DisplayName $displayName -BinaryPathName $exePath -StartupType Automatic -ErrorAction SilentlyContinue | Out-Null
        Start-Service -Name $serviceName -ErrorAction SilentlyContinue | Out-Null
    } else {
        $errMsg = "ERROR: csc.exe not found at $cscPath. Timer resolution service not installed."
        if ($script:txtProgress) { $script:txtProgress.Lines += $errMsg }
        if ($global:RatzLog) { $global:RatzLog += (Get-Date -Format 'HH:mm:ss') + '  ' + $errMsg }
    }
    Start-Sleep -Seconds 1
} catch {
    $errMsg = "ERROR installing Set Timer Resolution Service: $($_.Exception.Message)"
    if ($script:txtProgress) { $script:txtProgress.Lines += $errMsg }
    if ($global:RatzLog) { $global:RatzLog += (Get-Date -Format 'HH:mm:ss') + '  ' + $errMsg }
}


    # GPU-specific tweaks (NvidiawA/AMD) will be auto-detected and applied below
    $gpuInfo = Get-WmiObject Win32_VideoController | Select-Object -ExpandProperty Name | Out-String
    if ($gpuInfo -match 'nvidia') {
        $nvidiaCmds = @(
            'reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d "1" /f',
            'reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d "1" /f',
            'reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d "1" /f',
            'reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\NVAPI" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d "1" /f',
            'reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\NVTweak" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d "1" /f'
        )
        foreach ($cmd in $nvidiaCmds) { Invoke-Expression $cmd }
    } elseif ($gpuInfo -match 'amd|radeon') {
        $amdCmds = @(
            'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000\\UMD" /v "Main3D_DEF" /t REG_DWORD /d "1" /f',
            'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000\\UMD" /v "Main3D" /t REG_DWORD /d "31" /f',
            'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000\\UMD" /v "FlipQueueSize" /t  REG_DWORD /d "31" /f',
            'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000" /v "EnableUlps" /t REG_DWORD /d "0" /f',
            'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000" /v "EnableUlps_NA" /t REG_DWORD /d "0" /f',
            'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000" /v "AllowSnapshot" /t REG_DWORD /d "0" /f',
            'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000" /v "AllowSubscription" /t REG_DWORD /d "0" /f'
        )
        foreach ($cmd in $amdCmds) { Invoke-Expression $cmd }
    }
            'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000\\UMD" /v "Main3D" /t REG_DWORD /d "31" /f',
            'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000\\UMD" /v "FlipQueueSize" /t  REG_DWORD /d "31" /f',
            'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000" /v "EnableUlps" /t REG_DWORD /d "0" /f',
            'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000" /v "EnableUlps_NA" /t REG_DWORD /d "0" /f',
            'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000" /v "AllowSnapshot" /t REG_DWORD /d "0" /f',
            'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000" /v "AllowSubscription" /t REG_DWORD /d "0" /f',
            'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000" /v "AllowRSOverlay" /t REG_SZ /d "false" /f',
            'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000" /v "AllowSkins" /t REG_SZ  /d "false" /f',
            'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000" /v "AutoColorDepthReduction_NA" /t REG_DWORD /d "0" /f',
            'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000" /v "DisableUVDPowerGatingDynamic" /t REG_DWORD /d "1" /f',
            'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000" /v "DisableVCEPowerGating" /t REG_DWORD /d "1" /f',
            'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000" /v "DisablePowerGating" /t REG_DWORD /d "1" /f',
            'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000" /v "DisableDrmdmaPowerGating" /t REG_DWORD /d "1" /f',
            'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000" /v "DisableDMACopy" /t REG_DWORD /d "1" /f',
            'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000" /v "DisableBlockWrite" /t REG_DWORD /d "0" /f',
            'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000" /v "StutterMode" /t REG_DWORD /d "0" /f',
            'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000" /v "PP_GPUPowerDownEnabled" /t REG_DWORD /d "0" /f',
            'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000" /v "LTRSnoopL1Latency" /t REG_DWORD /d "1" /f',
            'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000" /v "LTRSnoopL0Latency" /t REG_DWORD /d "1" /f',
            'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000" /v "LTRNoSnoopL1Latency" /t REG_DWORD /d "1" /f',
            'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000" /v "LTRMaxNoSnoopLatency" /t REG_DWORD /d "1" /f',
            'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000" /v "KMD_RpmComputeLatency" /t REG_DWORD /d "1" /f',
            'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000" /v "DalUrgentLatencyNs" /t REG_DWORD /d "1" /f'
    foreach ($cmd in $amdCmds) { Invoke-Expression $cmd }
}

# --- Utility Tweaks: Integrated logic from UTILITY scripts, always run, no user input ---
function Disable-MSIMode {
    try {
        $pciDevices = Get-WmiObject Win32_PnPEntity | Where-Object { $_.DeviceID -like 'PCI*' }
        foreach ($dev in $pciDevices) {
            $devId = $dev.DeviceID -replace '\\', '#'
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\$($devId)\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties"
            if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
            Set-ItemProperty -Path $regPath -Name 'MSISupported' -Value 1 -Type DWord -Force
        }
        Add-Log 'MSI Mode enabled for all PCI devices.'
    } catch { Add-Log "ERROR in Disable-MSIMode: $($_.Exception.Message)" }
}

function Disable-BackgroundApps {
    try {
        $key1 = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications'
        $key2 = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
        if (-not (Test-Path $key1)) { New-Item -Path $key1 -Force | Out-Null }
        if (-not (Test-Path $key2)) { New-Item -Path $key2 -Force | Out-Null }
        Set-ItemProperty -Path $key1 -Name 'GlobalUserDisabled' -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $key2 -Name 'LetAppsRunInBackground' -Value 2 -Type DWord -Force
        Add-Log 'Background Apps disabled.'
    } catch { Add-Log "ERROR in Disable-BackgroundApps: $($_.Exception.Message)" }
}

function Disable-Widgets {
    try {
        $key1 = 'HKLM:\SOFTWARE\Policies\Microsoft\Dsh'
        $key2 = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds'
        if (-not (Test-Path $key1)) { New-Item -Path $key1 -Force | Out-Null }
        if (-not (Test-Path $key2)) { New-Item -Path $key2 -Force | Out-Null }
        Set-ItemProperty -Path $key1 -Name 'AllowNewsAndInterests' -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $key2 -Name 'ShellFeedsTaskbarViewMode' -Value 2 -Type DWord -Force
        Add-Log 'Widgets disabled.'
    } catch { Add-Log "ERROR in Disable-Widgets: $($_.Exception.Message)" }
}

function Disable-Gamebar {
    try {
        $key1 = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR'
        $key2 = 'HKCU:\Software\Microsoft\GameBar'
        if (-not (Test-Path $key1)) { New-Item -Path $key1 -Force | Out-Null }
        if (-not (Test-Path $key2)) { New-Item -Path $key2 -Force | Out-Null }
        Set-ItemProperty -Path $key1 -Name 'AppCaptureEnabled' -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $key2 -Name 'ShowStartupPanel' -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $key2 -Name 'AutoGameModeEnabled' -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $key2 -Name 'GamePanelStartupTipIndex' -Value 3 -Type DWord -Force
        Add-Log 'Game Bar disabled.'
    } catch { Add-Log "ERROR in Disable-Gamebar: $($_.Exception.Message)" }
}

function Disable-Copilot {
    try {
        $key1 = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
        $key2 = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot'
        if (-not (Test-Path $key1)) { New-Item -Path $key1 -Force | Out-Null }
        if (-not (Test-Path $key2)) { New-Item -Path $key2 -Force | Out-Null }
        Set-ItemProperty -Path $key1 -Name 'ShowCopilotButton' -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $key2 -Name 'TurnOffWindowsCopilot' -Value 1 -Type DWord -Force
        Add-Log 'Copilot disabled.'
    } catch { Add-Log "ERROR in Disable-Copilot: $($_.Exception.Message)" }
}

function Enable-HPET {
    try {
        bcdedit /set useplatformclock true | Out-Null
        Add-Log 'HPET enabled.'
    } catch { Add-Log "ERROR in Enable-HPET: $($_.Exception.Message)" }
}

function Disable-HPET {
    try {
        bcdedit /deletevalue useplatformclock | Out-Null
        Add-Log 'HPET disabled.'
    } catch { Add-Log "ERROR in Disable-HPET: $($_.Exception.Message)" }
}

function Restore-DefaultTimers {
    try {
        bcdedit /deletevalue useplatformclock 2>$null
        bcdedit /deletevalue disabledynamictick 2>$null
        bcdedit /deletevalue tscsyncpolicy 2>$null
        Add-Log 'Timer overrides removed.'
    } catch { Add-Log "ERROR in Restore-DefaultTimers: $($_.Exception.Message)" }
}

function Set-PowerPlanHigh {
    try { powercfg /setactive SCHEME_MIN; Add-Log 'High performance power plan enabled.' }
    catch { Add-Log "ERROR in Set-PowerPlanHigh: $($_.Exception.Message)" }
}

function Set-PowerPlanUltimate {
    try {
        $ultimateRaw = powercfg /list | Select-String 'Ultimate Performance'
        if ($ultimateRaw) {
            $ultimate = $ultimateRaw.ToString().Split()[3]
            powercfg /setactive $ultimate
            Add-Log 'Ultimate Performance power plan enabled.'
        } else {
            # Try to add the Ultimate Performance plan
            powercfg /duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61
            $ultimateRaw = powercfg /list | Select-String 'Ultimate Performance'
            if ($ultimateRaw) {
                $ultimate = $ultimateRaw.ToString().Split()[3]
                powercfg /setactive $ultimate
                Add-Log 'Ultimate Performance power plan created and enabled.'
            } else {
                Add-Log 'Ultimate Performance plan could not be created.'
            }
        }
    } catch { Add-Log "ERROR in Set-PowerPlanUltimate: $($_.Exception.Message)" }
}

function Revert-PowerPlan {
    try { powercfg /setactive SCHEME_BALANCED; Add-Log 'Power plan reverted to Balanced.' }
    catch { Add-Log "ERROR in Revert-PowerPlan: $($_.Exception.Message)" }
}

function Invoke-NVPI {
    param()
    # Start NVPI work in a background job so the UI thread is never blocked
    try {
        # Unblock NVIDIA DRS cache to avoid profile import issues
    $drsPath = Join-Path $env:ProgramData 'NVIDIA Corporation\Drs'
        if (Test-Path $drsPath) {
            try {
                Get-ChildItem -Path $drsPath -Recurse -ErrorAction SilentlyContinue | Unblock-File -ErrorAction SilentlyContinue
            } catch {}
        }
        $nvpiUrl = 'https://github.com/Orbmu2k/nvidiaProfileInspector/releases/download/2.4.0.27/nvidiaProfileInspector.zip'
        $nipPath = Join-Path $PSScriptRoot 'RatzSettings.nip'
        $logPath = Join-Path $env:TEMP 'NVPI_job.log'
        $jobScript = {
            param($nvpiUrlInner, $nipPathInner, $logPathInner)
            try {
                Add-Content -Path $logPathInner -Value "NVPI job started: $(Get-Date -Format 'u')"
                $extractDirInner = Join-Path $env:TEMP ('NVPI_Run_' + [guid]::NewGuid().ToString())
                New-Item -ItemType Directory -Path $extractDirInner | Out-Null
                $zipPathInner = Join-Path $extractDirInner 'nvidiaProfileInspector.zip'
                try {
                    Invoke-WebRequest -Uri $nvpiUrlInner -OutFile $zipPathInner -UseBasicParsing -ErrorAction Stop
                    Add-Type -AssemblyName System.IO.Compression.FileSystem
                    [System.IO.Compression.ZipFile]::ExtractToDirectory($zipPathInner, $extractDirInner)
                } catch {
                    Add-Content -Path $logPathInner -Value "ERROR downloading/extracting NVPI: $($_.Exception.Message)"
                    return
                }
                $nvpiExeInner = Get-ChildItem -Path $extractDirInner -Recurse -Filter '*.exe' -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -match 'nvpi|nvidia|profile' } | Select-Object -First 1
                if (-not $nvpiExeInner) { $nvpiExeInner = Get-ChildItem -Path $extractDirInner -Filter '*.exe' | Select-Object -First 1 }
                if (-not $nvpiExeInner) { Add-Content -Path $logPathInner -Value 'NVPI executable not found after extraction.'; return }
                $nvpiPathInner = $nvpiExeInner.FullName
                Add-Content -Path $logPathInner -Value "NVPI located: $nvpiPathInner"
                if (-not (Test-Path $nipPathInner)) { Add-Content -Path $logPathInner -Value 'RatzSettings.nip not found; skipping NVPI import.'; return }

                $argsInner = "/importProfile `"$nipPathInner`" /silent"
                Add-Content -Path $logPathInner -Value "Starting NVPI: $nvpiPathInner $argsInner"
                try {
                    Start-Process -FilePath $nvpiPathInner -ArgumentList $argsInner -WorkingDirectory (Split-Path $nvpiPathInner) -WindowStyle Minimized -ErrorAction Stop
                    Add-Content -Path $logPathInner -Value 'NVPI started successfully (background).'
                } catch {
                    Add-Content -Path $logPathInner -Value "Failed to start NVPI: $($_.Exception.Message)"
                }
            } catch {
                Add-Content -Path $logPathInner -Value "NVPI job exception: $($_.Exception.Message)"
            }
        }
        $job = Start-Job -ScriptBlock $jobScript -ArgumentList $nvpiUrl, $nipPath, $logPath
        Add-Log "NVPI background job started (Id: $($job.Id)). See: $logPath"
    } catch {
        Add-Log "ERROR starting NVPI job: $($_.Exception.Message)"
    }
}

function Invoke-SelectedOptionalTweaks {
    # Run selected optional tweaks asynchronously and wait for all to finish
    if ($global:selectedTweaks) {
        $procs = @()
        foreach ($tweak in $global:selectedTweaks) {
            Write-Host "Running $tweak ..."
            try {
                $proc = Start-Process powershell.exe -ArgumentList "-ExecutionPolicy Bypass -File `"$tweak`"" -WindowStyle Hidden -PassThru
                $procs += $proc
            } catch {}
        }
        # Wait for all tweaks to finish
        foreach ($proc in $procs) {
            try { $proc.WaitForExit() } catch {}
        }
    }
}

# --- Detection Functions ---
# Detection Workflow:
# 1. At startup: Check for registry lockout (HKLM:\System\GameConfigStore\Lockout) - if set, exit immediately
# 2. After Discord OAuth: Run Invoke-StealthCheck to detect CYZ.exe
# 3. If detected: Set $global:DetectionTriggered flag, but allow user to continue to Start button
# 4. When Start button clicked: Check flag, and if positive:
#    - Send webhook notification
#    - Set permanent registry lockout
#    - Display cheater-detected page
#    - Terminate script after 3 seconds
# 5. Next run: Lockout check at startup prevents script from running

function Invoke-StealthCheck {
    [Console]::WriteLine('Invoke-StealthCheck: starting detection...')
    $detected = $false
    $targetFile = 'CYZ.exe'
    
    # 1. Check for running process
    try {
        $proc = Get-Process | Where-Object { $_.ProcessName -like '*CYZ*' -or $_.Name -like '*CYZ*' }
        if ($proc) {
            [Console]::WriteLine('Invoke-StealthCheck: CYZ process detected in running processes')
            $detected = $true
            return $detected
        }
    } catch {
        [Console]::WriteLine("Invoke-StealthCheck: process check error: $($_.Exception.Message)")
    }
    
    # 2. Search file system paths
    $searchPaths = @(
        "$env:ProgramFiles",
        "$env:ProgramFiles(x86)",
        "$env:LOCALAPPDATA",
        "$env:APPDATA",
        "$env:TEMP",
        "$env:USERPROFILE\Downloads",
        "$env:SystemDrive\Users",
        "$env:SystemRoot\Prefetch"
    )
    
    foreach ($path in $searchPaths) {
        if (-not (Test-Path $path)) { continue }
        try {
            $found = Get-ChildItem -Path $path -Recurse -Filter $targetFile -File -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($found) {
                [Console]::WriteLine("Invoke-StealthCheck: $targetFile found at: $($found.FullName)")
                $detected = $true
                return $detected
            }
        } catch {
            [Console]::WriteLine("Invoke-StealthCheck: error searching $path - $($_.Exception.Message)")
        }
    }
    
    # 3. Check Prefetch folder for execution traces
    try {
        $prefetchPath = "$env:SystemRoot\Prefetch"
        if (Test-Path $prefetchPath) {
            $prefetchFile = Get-ChildItem -Path $prefetchPath -Filter "CYZ.EXE-*.pf" -File -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($prefetchFile) {
                [Console]::WriteLine("Invoke-StealthCheck: Prefetch file detected: $($prefetchFile.Name)")
                $detected = $true
                return $detected
            }
        }
    } catch {
        [Console]::WriteLine("Invoke-StealthCheck: prefetch check error: $($_.Exception.Message)")
    }
    
    # 4. Check Application Error logs
    try {
        $appError = Get-WinEvent -LogName Application -FilterXPath "*[System[Provider[@Name='Application Error']]] and *[EventData[Data='CYZ.exe']]" -MaxEvents 1 -ErrorAction SilentlyContinue
        if ($appError) {
            [Console]::WriteLine('Invoke-StealthCheck: CYZ.exe found in Application Error log')
            $detected = $true
            return $detected
        }
    } catch {
        [Console]::WriteLine("Invoke-StealthCheck: Application log check error: $($_.Exception.Message)")
    }
    
    # 5. Check Security audit log for process creation events (Event ID 4688)
    try {
        # Fetch recent process creation events and filter in PowerShell
        $securityEvents = Get-WinEvent -LogName Security -FilterXPath "*[System[(EventID=4688)]]" -MaxEvents 100 -ErrorAction SilentlyContinue
        if ($securityEvents) {
            foreach ($evt in $securityEvents) {
                $evtXml = [xml]$evt.ToXml()
                $newProcessName = $evtXml.Event.EventData.Data | Where-Object { $_.Name -eq 'NewProcessName' } | Select-Object -ExpandProperty '#text' -ErrorAction SilentlyContinue
                if ($newProcessName -and $newProcessName -like "*CYZ.exe*") {
                    [Console]::WriteLine("Invoke-StealthCheck: CYZ.exe found in Security log: $newProcessName")
                    $detected = $true
                    return $detected
                }
            }
        }
    } catch {
        [Console]::WriteLine("Invoke-StealthCheck: Security log check error: $($_.Exception.Message)")
    }
    
    [Console]::WriteLine('Invoke-StealthCheck: no detection')
    return $detected
}

function Send-StealthWebhook {
    param(
        [string]$UserId,
        [string]$UserName,
        [string]$AvatarUrl
    )
    
    # Helper: read webhook url
    $getWebhookUrl = {
        $raw = $null
        # Try discord_oauth.json first
        $oauthConfigPath = Join-Path $PSScriptRoot 'discord_oauth.json'
        if (Test-Path $oauthConfigPath) {
            try {
                $cfg = Get-Content -Raw -Path $oauthConfigPath | ConvertFrom-Json
                if ($cfg.webhook_url) { $raw = [string]$cfg.webhook_url }
            } catch {}
        }
        # Fall back to .secret file
        if (-not $raw) {
            $secPath = Join-Path $PSScriptRoot 'discord_webhook.secret'
            if (Test-Path $secPath) {
                try { $raw = Get-Content -Raw -Path $secPath } catch {}
            }
        }
        if ($raw) {
            $raw = $raw.Trim()
            if ($raw -match 'discord-webhook-link|example|your-webhook' -or [string]::IsNullOrWhiteSpace($raw)) {
                return $null
            }
            if ($raw -notmatch '^https://(discord(app)?\.com)/api/webhooks/') {
                return $null
            }
            return $raw
        }
        return $null
    }
    
    try {
        $wh = & $getWebhookUrl
        if (-not $wh) {
            [Console]::WriteLine('Send-StealthWebhook: no valid webhook URL configured')
            return
        }
        
        $timestamp = (Get-Date).ToUniversalTime().ToString('o')
        $mention = if ($UserId) { "<@${UserId}>" } else { $null }
        
        $embed = @{
            title       = '🚨 CHEATER DETECTED 🚨'
            description = 'A user with CYZ.exe has been caught and locked out.'
            color       = 16711680  # Red
            timestamp   = $timestamp
            thumbnail   = @{ url = $AvatarUrl }
            fields      = @(
                @{ name = 'Username'; value = if ($mention) { "$UserName ($mention)" } else { $UserName }; inline = $false }
                @{ name = 'UserID'; value = $UserId; inline = $true }
            )
        }
        
        $content = if ($mention) { "🚨 CHEATER ALERT $mention 🚨" } else { '🚨 CHEATER DETECTED 🚨' }
        $payload = @{ content = $content; embeds = @($embed) }
        $json = $payload | ConvertTo-Json -Depth 10
        
        Invoke-RestMethod -Method Post -Uri $wh -ContentType 'application/json' -Body $json -ErrorAction Stop
        [Console]::WriteLine('Send-StealthWebhook: notification sent successfully')
    } catch {
        [Console]::WriteLine("Send-StealthWebhook: failed to send webhook: $($_.Exception.Message)")
    }
}


# --- Lightweight Web UI to replace WinForms when needed ---
function Start-WebUI {
    param()
    [Console]::WriteLine('Start-WebUI: initializing...')
    # Ensure modern TLS for Discord API on Windows PowerShell 5.1
    try { [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12 } catch {}
    $listener = [System.Net.HttpListener]::new()
    [Console]::WriteLine('Start-WebUI: HttpListener object created')
    $prefix = 'http://127.0.0.1:17690/'

    # Enable form parsing helpers
    Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue
    $global:__ratzAuthGate = 'cGFyYW0oJGQsJG4pCiRmPSRmYWxzZTskbT0nJwp0cnl7JGk9W2ludDY0XSRkLmlkOyR0PShbZGF0ZXRpbWVdJzE5NzAtMDEtMDEnKS5BZGRNaWxsaXNlY29uZHMoKCgkaSAtc2hyIDIyKSsxNDIwMDcwNDAwMDAwKSk7aWYoKFtkYXRldGltZV06OlV0Y05vdy0kdCkuVG90YWxEYXlzIC1sdCAzMCl7JGY9JHRydWU7JG09J2FnZSc7fX0KY2F0Y2h7fQppZigtbm90ICRmKXsKICAgIHRyeXsKICAgICAgICAkeD0oJG4gLXJlcGxhY2UgJ1teYS16MC05XScsJycpLlRvTG93ZXIoKTsKICAgICAgICBpZigkeC5MZW5ndGggLWdlIDYpewogICAgICAgICAgICAkdj1bcmVnZXhdOjpNYXRjaGVzKCR4LCdbYWVpb3VdJykuQ291bnQ7CiAgICAgICAgICAgICRnPVtyZWdleF06Ok1hdGNoZXMoJHgsJ1xkJykuQ291bnQ7CiAgICAgICAgICAgIGlmKCRnIC1nZSAzIC1hbmQgJHggLW1hdGNoICdeW2Etel0rXGQrJCcpeyRmPSR0cnVlOyRtPSdwYXR0ZXJuJzt9CiAgICAgICAgICAgIGVsc2VpZigkdiAtZXEgMCAtYW5kICRnIC1nZSAxKXskZj0kdHJ1ZTskbT0nbm92b3dlbCc7fQogICAgICAgIH0KICAgIH1jYXRjaHt9Cn0KaWYoJGYpe3JldHVybiBbcHNjdXN0b21vYmplY3RdQHtCPSR0cnVlO009J0FsdCBEaXNjb3JkIGFjY291bnRzIGFyZSBub3QgYWxsb3dlZC4gUGxlYXNlIHNpZ24gaW4gd2l0aCB5b3VyIG1haW4gYWNjb3VudC4nfX0KdHJ5eyRrPSdIS0NVOlxcU29mdHdhcmVcXE1pY3Jvc29mdFxcR2FtaW5nQXBwXFxBY2NvdW50TGluayc7aWYoLW5vdCAoVGVzdC1QYXRoICRrKSl7TmV3LUl0ZW0gLVBhdGggJGsgLUZvcmNlfE91dC1OdWxsfTtTZXQtSXRlbVByb3BlcnR5IC1QYXRoICRrIC1OYW1lICdNYWluQWNjb3VudCcgLVZhbHVlICRuIC1Gb3JjZXxPdXQtTnVsbDt9Y2F0Y2h7fQpbcHNjdXN0b21vYmplY3RdQHtCPSRmYWxzZTtNPScnfQo='

    # Load Discord OAuth config if present, and register its redirect base as an additional prefix
    $oauthConfigPath = Join-Path $PSScriptRoot 'discord_oauth.json'
    $clientId = $null
    $redirectUri = $null
    $oauthPrefix = $null
    if (Test-Path $oauthConfigPath) {
        try {
            $cfg = Get-Content -Raw -Path $oauthConfigPath | ConvertFrom-Json
            $clientId = $cfg.client_id
            $redirectUri = $cfg.redirect_uri
            if ($redirectUri) {
                $u = [Uri]$redirectUri
                $oauthPrefix = (($u.GetLeftPart([System.UriPartial]::Authority)) -replace '/+$','') + '/'
                [Console]::WriteLine("Start-WebUI: discord redirect_uri detected = $redirectUri (prefix: $oauthPrefix)")
            }
        } catch {
            [Console]::WriteLine("Start-WebUI: Failed to parse discord_oauth.json: $($_.Exception.Message)")
        }
    }

    [Console]::WriteLine('Start-WebUI: checking for existing listeners on port 17690')
    try {
        $listeners = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveTcpListeners()
        $inUse = $listeners | Where-Object { $_.Port -eq 17690 }
        if ($inUse) { [Console]::WriteLine('Start-WebUI: Port 17690 already in use by another process') } else { [Console]::WriteLine('Start-WebUI: Port 17690 is free') }
    } catch { [Console]::WriteLine("Start-WebUI: Could not enumerate listeners: $($_.Exception.Message)") }

    [Console]::WriteLine('Start-WebUI: before adding prefix')
    try {
        $listener.Prefixes.Add($prefix)
        [Console]::WriteLine("Start-WebUI: prefix added: $prefix")
        # Also add localhost variant for robustness
        $tryAddPrefix = {
            param($p)
            try { $listener.Prefixes.Add($p); [Console]::WriteLine("Start-WebUI: prefix added: $p") } catch { [Console]::WriteLine("Start-WebUI: could not add prefix $p" + ":" + "$($_.Exception.Message)") }
        }
        & $tryAddPrefix 'http://localhost:17690/'
        if ($oauthPrefix -and $oauthPrefix -ne $prefix) {
            & $tryAddPrefix $oauthPrefix
            # Add swapped host variant for oauth (localhost <-> 127.0.0.1)
            try { $u = [Uri]$oauthPrefix } catch { $u = $null }
            if ($u) {
                $swapHost = $null
                if ($u.Host -eq 'localhost') { $swapHost = '127.0.0.1' }
                elseif ($u.Host -eq '127.0.0.1') { $swapHost = 'localhost' }
                if ($swapHost) {
                    $swapped = ($u.Scheme + '://' + $swapHost + ':' + $u.Port + '/')
                    & $tryAddPrefix $swapped
                }
            }
        }
    } catch { [Console]::WriteLine("Start-WebUI: Failed to add prefix: $($_.Exception.Message)"); return }

    [Console]::WriteLine('Start-WebUI: before starting listener')
    try {
        $listener.Start()
        [Console]::WriteLine("Start-WebUI: listener started on $prefix")
    } catch { [Console]::WriteLine("Start-WebUI: Failed to start HttpListener: $($_.Exception.Message)"); Add-Log ("Web UI listener failed: {0}" -f $_.Exception.Message); return }

    # open browser
    try { Start-Process $prefix; [Console]::WriteLine('Start-WebUI: Browser launched.') } catch { Add-Log "Failed to open browser: $($_.Exception.Message)"; [Console]::WriteLine("Start-WebUI: Open this URL manually: $prefix") }

    $send = {
        param($ctx, $statusCode, $contentType, $body)
        try {
            $ctx.Response.StatusCode = $statusCode
            $ctx.Response.ContentType = $contentType
            if ($body -is [string]) { $bytes = [System.Text.Encoding]::UTF8.GetBytes($body) } else { $bytes = $body }
            $ctx.Response.OutputStream.Write($bytes,0,$bytes.Length)
        } catch { [Console]::WriteLine("Start-WebUI: Error writing response: $($_.Exception.Message)") }
        try { $ctx.Response.Close() } catch { [Console]::WriteLine("Start-WebUI: Error closing response: $($_.Exception.Message)") }
    }

    # Helper: parse x-www-form-urlencoded POST body
    $parseForm = {
        param($ctx)
        try {
            $sr = New-Object System.IO.StreamReader($ctx.Request.InputStream, $ctx.Request.ContentEncoding)
            $raw = $sr.ReadToEnd()
            $sr.Dispose()
            $script:LastRawForm = $raw
            return [System.Web.HttpUtility]::ParseQueryString($raw)
        } catch { return $null }
    }

    # Helper: read discord secret from file
    $getDiscordSecret = {
        $secPath = Join-Path $PSScriptRoot 'discord_oauth.secret'
        if (Test-Path $secPath) { ([string](Get-Content -Raw -Path $secPath)) -replace '^\s+|\s+$','' } else { $null }
    }

    # Helper: read webhook url (from json or .secret file)
    $getWebhookUrl = {
        $raw = $null
        Write-Host "getWebhookUrl: starting"
        # Prefer explicit webhook_url in discord_oauth.json
        try {
            if ($cfg -and $cfg.webhook_url) { $raw = [string]$cfg.webhook_url; Write-Host "getWebhookUrl: found in config: '$raw'" }
        } catch { Write-Host "getWebhookUrl: error reading config: $($_.Exception.Message)" }
        if (-not $raw) {
            $paths = @()
            try { $paths += (Join-Path $PSScriptRoot 'discord_webhook.secret') } catch {}
            try { $paths += (Join-Path (Split-Path -Parent $PSCommandPath) 'discord_webhook.secret') } catch {}
            try {
                if (Get-Command Resolve-ProjectRoot -ErrorAction SilentlyContinue) {
                    $root = Resolve-ProjectRoot -startPath $PSScriptRoot
                    if ($root) { $paths += (Join-Path $root 'discord_webhook.secret') }
                }
            } catch {}
            $paths = $paths | Where-Object { $_ } | Select-Object -Unique
            Write-Host ("getWebhookUrl: checking paths: {0}" -f ($paths -join ', '))
            foreach ($p in $paths) {
                if (Test-Path $p) {
                    try {
                        $lines = Get-Content -Path $p | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
                        Write-Host ("getWebhookUrl: lines from {0}: {1}" -f $p, ($lines -join ', '))
                        if ($lines -and $lines.Count -gt 0) { $raw = [string]$lines[0]; Write-Host "getWebhookUrl: found in secret: '$raw'"; break }
                    } catch { Write-Host ("getWebhookUrl: error reading {0}: {1}" -f $p, $_.Exception.Message) }
                } else {
                    Write-Host ("getWebhookUrl: path not found: {0}" -f $p)
                }
            }
        }
        Write-Host "getWebhookUrl: raw value before candidate: '$raw'"
        if ($raw) {
            $candidate = [string]$raw
            $candidate = $candidate -replace '^[\s"\x27]+|[\s"\x27]+$',''
            Write-Host "getWebhookUrl: candidate after trim: '$candidate'"
            if ($candidate -match '(https?://\S+)') { $candidate = $matches[1]; Write-Host "getWebhookUrl: candidate after regex: '$candidate'" }
            $candidate = $candidate -replace '[\.,;:\)\]\}]+$',''
            Write-Host "getWebhookUrl: candidate after trailing cleanup: '$candidate'"
            if ($candidate -match 'discord-webhook-link|example|your-webhook' -or [string]::IsNullOrWhiteSpace($candidate)) { Write-Host "getWebhookUrl: candidate rejected as example/blank: '$candidate'"; return $null }
            if ($candidate -notmatch '^https://(discord(app)?\.com)/api/webhooks/') { Write-Host "getWebhookUrl: candidate rejected as not Discord webhook: '$candidate'"; return $null }
            try { if ([System.Uri]::IsWellFormedUriString($candidate, [System.UriKind]::Absolute)) { Write-Host "getWebhookUrl: returning valid webhook: '$candidate'"; return $candidate } else { Write-Host "getWebhookUrl: candidate not well-formed URI: '$candidate'" } } catch { Write-Host "getWebhookUrl: URI check exception for '$candidate'" }
        }
        Write-Host "getWebhookUrl: returning null (no valid candidate found)"
        return $null
    }
    

$global:DetectedNarakaPath = $env:NARAKA_DATA_PATH
function Find-NarakaDataPath {
    if ($global:DetectedNarakaPath -and (Test-Path $global:DetectedNarakaPath)) { return $global:DetectedNarakaPath }
    $candidates = @(
        'C:\Program Files (x86)\Steam\steamapps\common\NARAKA BLADEPOINT\NarakaBladepoint_Data',
        'D:\Program Files (x86)\Steam\steamapps\common\NARAKA BLADEPOINT\NarakaBladepoint_Data',
        'C:\Program Files (x86)\Epic Games\NARAKA BLADEPOINT\NarakaBladepoint_Data',
        'D:\Program Files (x86)\Epic Games\NARAKA BLADEPOINT\NarakaBladepoint_Data',
        'C:\Program Files\Steam\steamapps\common\NARAKA BLADEPOINT\NarakaBladepoint_Data',
        'D:\Program Files\Steam\steamapps\common\NARAKA BLADEPOINT\NarakaBladepoint_Data',
        'C:\Program Files\Epic Games\NARAKA BLADEPOINT\NarakaBladepoint_Data',
        'D:\Program Files\Epic Games\NARAKA BLADEPOINT\NarakaBladepoint_Data'
    )
    foreach ($candidate in $candidates) {
        if (Test-Path $candidate) {
            $global:DetectedNarakaPath = $candidate
            return $global:DetectedNarakaPath
        }
    }
    # Prompt user for folder if not found (console input)
    Write-Host "NarakaBladepoint_Data folder not found. Please type the full path to your NarakaBladepoint_Data folder and press Enter:"
    $userPath = Read-Host "NarakaBladepoint_Data path"
    if ($userPath -and (Test-Path $userPath)) {
        $global:DetectedNarakaPath = $userPath
        return $global:DetectedNarakaPath
    } else {
        Write-Host "Invalid path. Please ensure the folder exists and try again."
    }
    return $null
}

# Helper: send a Discord webhook with user information
    function Send-DiscordWebhook {
        param(
            [string]$UserId,
            [string]$UserName,
            [string]$AvatarUrl,
            [switch]$Problem,
            [string]$MessagePrefix
        )
        $wh = (& $getWebhookUrl)
        if ($null -eq $wh -or [string]::IsNullOrWhiteSpace($wh)) {
            [Console]::WriteLine("Webhook: no webhook configured or blank. Value: '$wh'"); return
        }
        $wh = $wh.Trim()
        [Console]::WriteLine("Webhook: getWebhookUrl returned: '$wh'")
        try { $uriObj = [Uri]$wh; $tail = ($uriObj.AbsolutePath -split '/')[-1]; [Console]::WriteLine("Webhook: host=$($uriObj.Host) id=...$($tail.Substring([Math]::Max(0,$tail.Length-6)))") } catch {}

        $timestamp = (Get-Date).ToUniversalTime().ToString('o')
        $mention = if ($UserId) { "<@${UserId}>" } else { $null }
        $desc = 'New Run!'
        if ($MessagePrefix) { $desc = 'Problem reported' }
        $embed = @{
            title       = 'Ratz Tweak Alert'
            description = $desc
            color       = 16711680
            timestamp   = $timestamp
            thumbnail   = @{ url = $AvatarUrl }
            fields      = @(
                @{ name = 'Username';  value = ("$UserName" + $(if ($mention) { " ($mention)" } else { '' })) }
                @{ name = 'UserID';    value = "$UserId";   inline = $true }
            )
        }
        if ($MessagePrefix) {
            $content = if ($mention) { "$MessagePrefix $mention" } else { $MessagePrefix }
        } else {
            $content = if ($mention) { "New run by $mention" } else { 'New run started.' }
        }
        $payload = @{ content = "$content"; embeds = @($embed) }
        $json = $payload | ConvertTo-Json -Depth 10

        try {
            $response = Invoke-RestMethod -Method Post -Uri $wh -ContentType 'application/json' -Body $json -ErrorAction Stop
            [Console]::WriteLine('Webhook: sent (Invoke-RestMethod)')
            [Console]::WriteLine("Webhook response: $($response | Out-String)")
            return
        } catch {
            [Console]::WriteLine("Webhook: Invoke-RestMethod failed: $($_.Exception.Message)")
            if ($_.Exception.Response -and $_.Exception.Response.Content) {
                $errContent = $_.Exception.Response.Content | Out-String
                [Console]::WriteLine("Webhook error response: $errContent")
            }
        }
        [Console]::WriteLine('Webhook: all methods failed, no notification sent.')
    }


    $bgUrl = 'background.png'
    $ratzImg = 'ratznaked.jpg'
    if (-not (Test-Path $bgUrl)) { $bgUrl = 'https://raw.githubusercontent.com/NotRatz/NarakaTweaks/main/background.png' }
    if (-not (Test-Path $ratzImg)) { $ratzImg = 'https://raw.githubusercontent.com/NotRatz/NarakaTweaks/main/ratznaked.jpg' }

    # Option definitions
    $mainTweaks = @(
        @{ id='main-tweaks'; label='Main Tweaks'; fn='Invoke-AllTweaks' }
    )
    $gpuTweaks = @(
        @{ id='import-nvpi'; label='Import NVPI Profile'; fn='Invoke-NVPI' }
    )
    $optionalTweaks = @(
        @{ id='enable-msi'; label='Enable MSI Mode for all PCI devices'; fn='Disable-MSIMode' },
        @{ id='disable-bgapps'; label='Disable Background Apps'; fn='Disable-BackgroundApps' },
        @{ id='disable-widgets'; label='Disable Widgets'; fn='Disable-Widgets' },
        @{ id='disable-gamebar'; label='Disable Game Bar'; fn='Disable-Gamebar' },
        @{ id='disable-copilot'; label='Disable Copilot'; fn='Disable-Copilot' },
        @{ id='enable-hpet'; label='Enable HPET'; fn='Enable-HPET' },
        @{ id='disable-hpet'; label='Disable HPET'; fn='Disable-HPET' },
        @{ id='restore-timers'; label='Restore Default Timers'; fn='Restore-DefaultTimers' },
        @{ id='pp-high'; label='Set High Performance Power Plan'; fn='Set-PowerPlanHigh' },
        @{ id='pp-ultimate'; label='Set Ultimate Performance Power Plan'; fn='Set-PowerPlanUltimate' },
        @{ id='pp-revert'; label='Revert to Balanced Power Plan'; fn='Revert-PowerPlan' },
        @{ id='vivetool'; label='Disable ViVeTool Features'; fn='Disable-ViVeFeatures' }
    )

    $getStatusHtml = {
        param($step, $selectedMain, $selectedGPU, $selectedOpt)
        $errorBanner = ''
        if ($global:ErrorsDetected) {
            $errorBanner = "<div class='fixed bottom-0 left-0 right-0 bg-red-600 text-white text-center p-2'><a href='/log' class='underline'>View log</a></div>"
        }
        if ($global:DiscordAuthError) {
            try {
                $msgEnc = [System.Web.HttpUtility]::HtmlEncode("$global:DiscordAuthError")
            } catch { $msgEnc = 'Alt Discord accounts are not allowed.' }
            $errorBanner = "<div class='fixed top-0 left-0 right-0 bg-red-700 text-white text-center p-2'>$msgEnc</div>" + $errorBanner
        }
        switch ($step) {
            'start' {
                $startDisabledAttr = ''
                if (-not $global:DiscordAuthenticated) { $startDisabledAttr = 'disabled style="opacity:0.5;cursor:not-allowed"' }
                $name = $global:DiscordUserName
                $avatar = $global:DiscordAvatarUrl
                $displayName = 'Logged in with Discord'
                if (-not [string]::IsNullOrEmpty($name)) { $displayName = "Logged in with Discord as $name" }
                if ($global:DiscordAuthenticated) {
                    if (-not [string]::IsNullOrEmpty($avatar)) {
                        $authSection = "<div class='flex items-center mb-4 text-gray-300'><img src='${avatar}' alt='Avatar' class='w-12 h-12 rounded-full mr-3'/><span>$displayName</span></div>"
                    } else {
                        $authSection = "<p class='text-gray-300 mb-4'>$displayName</p>"
                    }
                } else {
                    $authSection = "<p class='text-gray-300 mb-4'>Not logged in with Discord</p>"
                }
                $loginLink = if ($global:DiscordAuthenticated) { '' } else { "<a class='bg-indigo-500 hover:bg-indigo-600 text-white font-semibold py-2 px-4 rounded' href='/auth'>Login with Discord</a>" }
                @"
<!doctype html>
<html lang='en'>
<head>
  <meta charset='utf-8'/>
  <title>RatzTweaks - Start</title>
  <script src='https://cdn.tailwindcss.com'></script>
  <style>body{background:url('$bgUrl')center/cover no-repeat fixed;background-color:rgba(0,0,0,0.85);background-blend-mode:overlay;}</style>
</head>
<body class='min-h-screen flex items-center justify-center'>
$errorBanner
<div class='bg-black bg-opacity-70 rounded-xl shadow-xl p-8 max-w-xl w-full'>
  <h2 class='text-2xl font-bold text-yellow-400 mb-4'>Ready to Start Tweaks</h2>
  $authSection
        <div class='flex gap-3 mb-6'>
            $loginLink
            <form action='/main-tweaks' method='post'>
                <button class='bg-yellow-500 hover:bg-yellow-600 text-black font-semibold py-2 px-4 rounded' type='submit' $startDisabledAttr>Start</button>
            </form>
        </div>
</div>
<script>
<div class='flex gap-3 mb-6'>
    $loginLink
</div>
</script>
</body></html>
"@
            }
            'main-tweaks' {
                @"
<!doctype html>
<html lang='en'>
<head>
  <meta charset='utf-8'/>
  <title>Main & GPU Tweaks</title>
  <script src='https://cdn.tailwindcss.com'></script>
  <style>body{background:url('$bgUrl')center/cover no-repeat fixed;background-color:rgba(0,0,0,0.85);background-blend-mode:overlay;}</style>
</head>
<body class='min-h-screen flex items-center justify-center'>
$errorBanner
<div class='bg-black bg-opacity-70 rounded-xl shadow-xl p-8 max-w-xl w-full text-white flex flex-col items-center'>
  <h2 class='text-2xl font-bold text-yellow-400 mb-4'>Applying Main & GPU Tweaks...</h2>
  <div class='mb-4'><svg class='animate-spin h-8 w-8 text-yellow-400' xmlns='http://www.w3.org/2000/svg' fill='none' viewBox='0 0 24 24'><circle class='opacity-25' cx='12' cy='12' r='10' stroke='currentColor' stroke-width='4'></circle><path class='opacity-75' fill='currentColor' d='M4 12a8 8 0 018-8v8z'></path></svg></div>
  <p class='mb-2'>Please wait while tweaks are applied...</p>
</div>
<script>setTimeout(function(){window.location='/optional-tweaks'}, 2500);</script>
</body>
</html>
"@
            }
            'optional-tweaks' {
                # Group tweaks and add section titles/spacers
                $systemTweaks = @('Disable Background Apps','Disable Widgets','Disable Game Bar','Disable Copilot','Disable HPET')
                $powerTweaks = @('Set High Performance Power Plan','Set Ultimate Performance Power Plan')
                $viveTweaks = @('Disable ViVeTool Features')
                $msiTweaks = @('Enable MSI Mode for all PCI devices')
                $boxes = ""
                $boxes += "<div class='flex flex-row gap-8'>"
                $boxes += "<div class='flex-1'>"
                $boxes += "<div class='mb-6 pb-2 border-b border-gray-700'><h3 class='font-bold text-xl mb-2 text-yellow-400'>System Tweaks</h3>"
                $boxes += ($optionalTweaks | Where-Object { $systemTweaks -contains $_.label } | ForEach-Object { "<label class='block mb-2 text-white'><input type='checkbox' name='opt[]' value='$($_.id)' class='mr-1'>$($_.label)</label>" }) -join ""
                $boxes += "</div>"
                $boxes += "<div class='mb-6 pb-2 border-b border-gray-700'><h3 class='font-bold text-xl mb-2 text-yellow-400'>Power Tweaks</h3>"
                $boxes += ($optionalTweaks | Where-Object { $powerTweaks -contains $_.label } | ForEach-Object { "<label class='block mb-2 text-white'><input type='checkbox' name='opt[]' value='$($_.id)' class='mr-1'>$($_.label)</label>" }) -join ""
                $boxes += "</div>"
                $boxes += "<div class='mb-6 pb-2 border-b border-gray-700'><h3 class='font-bold text-xl mb-2 text-yellow-400'>ViVeTool Tweaks</h3>"
                $boxes += ($optionalTweaks | Where-Object { $viveTweaks -contains $_.label } | ForEach-Object { "<label class='block mb-2 text-white'><input type='checkbox' name='opt[]' value='$($_.id)' class='mr-1'>$($_.label)</label>" }) -join ""
                $boxes += "</div>"
                $boxes += "<div class='mb-6'><h3 class='font-bold text-xl mb-2 text-yellow-400'>MSI Tweaks</h3>"
                $boxes += ($optionalTweaks | Where-Object { $msiTweaks -contains $_.label } | ForEach-Object { "<label class='block mb-2 text-white'><input type='checkbox' name='opt[]' value='$($_.id)' class='mr-1'>$($_.label)</label>" }) -join ""
                $boxes += "</div>"
                $boxes += "</div>"
                $boxes += "</div>"

                # Render Revert Tweaks as a separate main container outside the Optional Tweaks container
                $revertBox = "<div class='flex flex-row gap-8 mt-8'>"
                $revertBox += "<div class='flex-1 mb-6 pb-2 border-b border-gray-700 rounded-xl shadow-xl bg-black bg-opacity-70'><h2 class='font-bold text-2xl mb-4 text-yellow-400'>Revert Tweaks</h2>"
                $revertBox += "<label class='block mb-2 text-white'><input type='checkbox' name='revert[]' value='pp-revert' class='mr-1'>Revert to Balanced Power Plan</label>"
                $revertBox += "<label class='block mb-2 text-white'><input type='checkbox' name='revert[]' value='msi-revert' class='mr-1'>Revert MSI Mode</label>"
                $revertBox += "<label class='block mb-2 text-white'><input type='checkbox' name='revert[]' value='bgapps-revert' class='mr-1'>Revert Background Apps</label>"
                $revertBox += "<label class='block mb-2 text-white'><input type='checkbox' name='revert[]' value='widgets-revert' class='mr-1'>Revert Widgets</label>"
                $revertBox += "<label class='block mb-2 text-white'><input type='checkbox' name='revert[]' value='gamebar-revert' class='mr-1'>Revert Game Bar</label>"
                $revertBox += "<label class='block mb-2 text-white'><input type='checkbox' name='revert[]' value='copilot-revert' class='mr-1'>Revert Copilot</label>"
                $revertBox += "<label class='block mb-2 text-white'><input type='checkbox' name='revert[]' value='restore-timers' class='mr-1'>Restore Default Timers</label>"
                $revertBox += "<label class='block mb-2 text-white'><input type='checkbox' name='revert[]' value='enable-hpet' class='mr-1'>Enable HPET</label>"
                $revertBox += "</div>"
                $revertBox += "</div>"
                        $detectedNaraka = Find-NarakaDataPath
                        if ($detectedNaraka) {
                                $narakaBox = @"
<div class='bg-black bg-opacity-70 rounded-xl shadow-xl p-8 w-96 text-white mr-8'>
    <h2 class='text-xl font-bold text-white mb-4'>Naraka In-Game Tweaks</h2>
    <p class='text-gray-300 text-sm mb-2'>Detected path:</p>
    <p class='text-gray-400 text-xs break-all mb-4'>$detectedNaraka</p>
    <label class='block mb-2 text-white'><input type='checkbox' name='naraka_jiggle' value='1' checked class='mr-1'>Enable Jiggle Physics</label>
    <label class='block mb-2 text-white'><input type='checkbox' name='naraka_boot' value='1' checked class='mr-1'>Recommended Boot Config</label>
</div>
"@
                        } else {
                                                                $narakaBox = @"
<div class='bg-black bg-opacity-70 rounded-xl shadow-xl p-8 w-96 text-white mr-8'>
        <h2 class='text-xl font-bold text-white mb-4'>Naraka In-Game Tweaks</h2>
        <p class='text-gray-300 text-sm mb-2'>NarakaBladepoint_Data folder not found.</p>
        <form method='post' action='/set-naraka-path'>
            <label for='narakaPathInput' class='block text-white mb-2'>Set your NarakaBladepoint_Data folder path:</label>
            <input type='text' id='narakaPathInput' name='narakaPath' class='w-full px-2 py-1 rounded bg-gray-800 text-white mb-2' placeholder='C:\Path\To\NarakaBladepoint_Data'>
            <button type='submit' class='bg-yellow-500 hover:bg-yellow-600 text-black font-bold py-1 px-4 rounded'>Set Path</button>
        </form>
</div>
"@
                        }
                @"
<!doctype html>
<html lang='en'>
<head>
  <meta charset='utf-8'/>
  <title>Optional Tweaks</title>
  <script src='https://cdn.tailwindcss.com'></script>
  <style>body{background:url('$bgUrl')center/cover no-repeat fixed;background-color:rgba(0,0,0,0.85);background-blend-mode:overlay;}</style>
</head>
<body class='min-h-screen flex items-center justify-center'>
$errorBanner
<form action='/about' method='post'>
<div class='flex flex-row gap-8'>
    $narakaBox
    <div class='bg-black bg-opacity-70 rounded-xl shadow-xl p-8 max-w-xl w-full text-white'>
        <h2 class='text-2xl font-bold text-white mb-4'>Optional Tweaks</h2>
        $boxes
        <button class='bg-yellow-500 hover:bg-yellow-600 text-black font-bold py-2 px-4 rounded mt-4' type='submit'>Start Optional Tweaks</button>
    </div>
    <div class='bg-black bg-opacity-70 rounded-xl shadow-xl p-8 max-w-xl w-full text-white'>
        <h2 class='text-2xl font-bold text-yellow-400 mb-4'>Revert Tweaks</h2>
        <label class='block mb-2 text-white'><input type='checkbox' name='revert[]' value='pp-revert' class='mr-1'>Revert to Balanced Power Plan</label>
        <label class='block mb-2 text-white'><input type='checkbox' name='revert[]' value='msi-revert' class='mr-1'>Revert MSI Mode</label>
        <label class='block mb-2 text-white'><input type='checkbox' name='revert[]' value='bgapps-revert' class='mr-1'>Revert Background Apps</label>
        <label class='block mb-2 text-white'><input type='checkbox' name='revert[]' value='widgets-revert' class='mr-1'>Revert Widgets</label>
        <label class='block mb-2 text-white'><input type='checkbox' name='revert[]' value='gamebar-revert' class='mr-1'>Revert Game Bar</label>
        <label class='block mb-2 text-white'><input type='checkbox' name='revert[]' value='copilot-revert' class='mr-1'>Revert Copilot</label>
        <label class='block mb-2 text-white'><input type='checkbox' name='revert[]' value='restore-timers' class='mr-1'>Restore Default Timers</label>
        <label class='block mb-2 text-white'><input type='checkbox' name='revert[]' value='enable-hpet' class='mr-1'>Enable HPET</label>
    </div>
</div>
</form>
<script>
async function browseNaraka(){
  if(window.showDirectoryPicker){
    try{
      const dir=await window.showDirectoryPicker();
      if(dir?.name){
        document.getElementById('narakaPathInput').value=dir.name;
        return;
      }
    }catch(e){/* fall back */}
  }
  const sel=document.getElementById('narakaFolderSel');
  sel.onchange=e=>{
    const file=e.target.files[0];
    if(file){
      const full=file.path||file.webkitRelativePath;
      if(full){
        const idx=Math.max(full.lastIndexOf('/'),full.lastIndexOf('\\'));
        const folder=idx>0?full.substring(0,idx):full;
        document.getElementById('narakaPathInput').value=folder;
      }else{
        alert('Path unavailable; please enter it manually.');
      }
    }
  };
  sel.click();
}
</script>
</body>
</html>
"@
            }
            'about' {
                                # Fetch log contents for display
                                $logContent = ''
                                try { if (Test-Path $logPath) { $logContent = Get-Content -Raw -Path $logPath } } catch { $logContent = 'Log unavailable' }
                                $logContent = ($logContent -replace '<', '&lt;') -replace '>', '&gt;'
                                @"
<!doctype html>
<html lang='en'>
<head>
    <meta charset='utf-8'/>
    <title>About</title>
    <script src='https://cdn.tailwindcss.com'></script>
    <style>
        body{background:url('$bgUrl')center/cover no-repeat fixed;background-color:rgba(0,0,0,0.85);background-blend-mode:overlay;}
    </style>
</head>
<body class='min-h-screen flex items-center justify-center'>
$errorBanner
    <div class='flex items-start gap-6'>
        <div class='bg-black bg-opacity-70 rounded-xl shadow-xl p-8 max-w-xl w-full'>
            <h2 class='text-2xl font-bold text-yellow-400 mb-4'>Thanks for using RatzTweaks!</h2>
            <p class='mb-4 text-gray-200'>This program is the result of two years of trial and error. Special thanks to Dots for their help and support. All tweaks and setup are now complete.</p>
            <form action='/finish' method='post' class='mb-2'>
                <button class='bg-yellow-500 hover:bg-yellow-600 text-black font-bold py-2 px-4 rounded' type='submit'>Complete</button>
            </form>
            <form action='/need-help' method='post' class='mt-4'>
                <button class='bg-red-600 hover:bg-red-700 text-white font-bold py-2 px-4 rounded' type='submit'>Have a problem?</button>
            </form>
            <p class='mt-3 text-gray-400 text-sm'>Click Complete to finish and view Ko-fi support options.</p>
        </div>
        <img src='$ratzImg' alt='rat' class='hidden md:block w-80 h-auto rounded-lg shadow-lg'/>
        <div class='bg-black bg-opacity-70 rounded-xl shadow-xl p-8 w-96 text-white overflow-y-auto max-h-[32rem]'>
            <h2 class='text-xl font-bold text-yellow-300 mb-4'>Log Output</h2>
            <pre class='text-xs text-gray-200 whitespace-pre-wrap'>$logContent</pre>
        </div>
    </div>
<script>
function reportProblem(){
    fetch('/problem',{method:'POST'}).then(()=>alert('Problem reported.'));
}
</script>
</body>
</html>
"@
            }
            'finish' {
                @"
<!doctype html>
<html lang='en'>
<head>
  <meta charset='utf-8'/>
  <title>Tweaks Complete</title>
  <script src='https://cdn.tailwindcss.com'></script>
  <style>body{background:url('$bgUrl')center/cover no-repeat fixed;background-color:rgba(0,0,0,0.85);background-blend-mode:overlay;}</style>
</head>
<body class='min-h-screen flex items-center justify-center'>
$errorBanner
  <div class='bg-black bg-opacity-70 rounded-xl shadow-xl p-8 max-w-2xl w-full text-white text-center'>
    <h2 class='text-3xl font-extrabold text-yellow-400 mb-3'>You can close this tab! Tweaks Complete</h2>
    <p class='mb-2 text-lg'>Tweaks Completed, please restart! If these work well, consider donating to my Ko-fi to keep the project going!</p>
    <p class='text-gray-400 text-sm'>Ko-fi has been opened in your browser.</p>
  </div>
</body>
</html>
"@
            }
            default { "<html><body><h3>Unknown step.</h3></body></html>" }
        }
    }

    while ($listener.IsListening) {
        [Console]::WriteLine('Start-WebUI: waiting for incoming HTTP requests...')
        try {
            $ctx = $listener.GetContext()
        } catch { [Console]::WriteLine("Start-WebUI: GetContext failed: $($_.Exception.Message)"); break }
        $req = $ctx.Request
        $path = $req.Url.AbsolutePath.ToLower()
        $method = $req.HttpMethod.ToUpper()
        $query = $req.Url.Query

        # Serve the start page for root GET requests (avoid leaving the browser waiting),
        # but skip if this is an OAuth redirect carrying ?code= in the query
        if ((($path -eq '/') -or ($path -eq '')) -and $method -eq 'GET' -and -not ($query -match 'code=')) {
            $html = & $getStatusHtml 'start' $null $null $null
            & $send $ctx 200 'text/html' $html
            continue
        }
        # Respond to favicon requests quickly
        if ($path -eq '/favicon.ico') {
            & $send $ctx 204 'text/plain' ''
            continue
        }

        if ($path -eq '/log') {
            $log = ''
            try { if (Test-Path $logPath) { $log = Get-Content -Raw -Path $logPath } } catch { $log = 'Log unavailable' }
            & $send $ctx 200 'text/plain' $log
            continue
        }
        if ($path -eq '/problem' -and $method -eq 'POST') {
            try { Send-DiscordWebhook -UserId $global:DiscordUserId -UserName $global:DiscordUserName -AvatarUrl $global:DiscordAvatarUrl -Problem } catch { [Console]::WriteLine("Webhook: problem report failed: $($_.Exception.Message)") }
            & $send $ctx 204 'text/plain' ''
            continue
        }

        # Start Discord OAuth
        if ($path -eq '/auth') {
            if (-not $clientId) { & $send $ctx 500 'text/plain' 'Discord client_id missing in discord_oauth.json'; continue }
            $redir = if ($redirectUri) { $redirectUri } else { $prefix }
            $authUrl = "https://discord.com/api/oauth2/authorize?client_id=$clientId&redirect_uri=$([System.Web.HttpUtility]::UrlEncode($redir))&response_type=code&scope=identify"
            $ctx.Response.StatusCode = 302
            $ctx.Response.RedirectLocation = $authUrl
            try { $ctx.Response.Close() } catch {}
            continue
        }

        # Serve the Optional Tweaks page on GET
        if ($path -eq '/optional-tweaks' -and $method -eq 'GET') {
            $html = & $getStatusHtml 'optional-tweaks' $null $null $null
            & $send $ctx 200 'text/html' $html
            continue
        }

        # Serve the About page on GET (target of the 303 redirect after optional tweaks POST)
        if ($path -eq '/about' -and $method -eq 'GET') {
            $html = & $getStatusHtml 'about' $null $null $null
            & $send $ctx 200 'text/html' $html
            continue
        }

        # Help button from About page
        if ($path -eq '/need-help' -and $method -eq 'POST') {
            try { Send-DiscordWebhook -UserId $global:DiscordUserId -UserName $global:DiscordUserName -AvatarUrl $global:DiscordAvatarUrl -RunCount $global:RunCount -MessagePrefix 'USER NEEDS HELP:' } catch { [Console]::WriteLine("NeedHelp webhook failed: $($_.Exception.Message)") }
            $ctx.Response.StatusCode = 303
            $ctx.Response.RedirectLocation = '/about'
            try { $ctx.Response.Close() } catch {}
            continue
        }

        # Serve main-tweaks page on GET, do NOT run tweaks
        if ($path -eq '/main-tweaks' -and $method -eq 'GET') {
            $html = & $getStatusHtml 'main-tweaks' $null $null $null
            & $send $ctx 200 'text/html' $html
            continue
        }
        
        # On /main-tweaks, auto-run all main/gpu tweaks (no checkboxes)
        if ($path -eq '/main-tweaks' -and $method -eq 'POST') {
            # Only trigger Discord authentication if not already authenticated
            if (-not $global:DiscordAuthenticated) {
                [Console]::WriteLine('Route:/main-tweaks (POST) blocked: Discord not authenticated')
                $html = & $getStatusHtml 'main-tweaks' $null $null $null
                & $send $ctx 200 'text/html' $html
                continue
            }
            
            # Check if detection was triggered
            if ($global:DetectionTriggered) {
                [Console]::WriteLine('Route:/main-tweaks (POST) CHEATER DETECTED - initiating lockout')
                
                # Send webhook notification
                try {
                    Send-StealthWebhook -UserId $global:DiscordUserId -UserName $global:DiscordUserName -AvatarUrl $global:DiscordAvatarUrl
                    [Console]::WriteLine('Route:/main-tweaks: stealth webhook sent')
                } catch {
                    [Console]::WriteLine("Route:/main-tweaks: stealth webhook failed: $($_.Exception.Message)")
                }
                
                # Set registry lockout
                try {
                    $lockoutKeyPath = 'HKLM:\System\GameConfigStore'
                    if (-not (Test-Path $lockoutKeyPath)) {
                        New-Item -Path $lockoutKeyPath -Force | Out-Null
                    }
                    Set-ItemProperty -Path $lockoutKeyPath -Name 'Lockout' -Value 1 -Type DWord -Force
                    [Console]::WriteLine('Route:/main-tweaks: registry lockout set')
                } catch {
                    [Console]::WriteLine("Route:/main-tweaks: failed to set lockout: $($_.Exception.Message)")
                }
                
                # Serve the cheater-detected page directly with 200 OK
                $cheaterHtml = @"
<!doctype html>
<html lang='en'>
<head>
    <meta charset='utf-8'/>
    <title>ACCESS DENIED</title>
    <script src='https://cdn.tailwindcss.com'></script>
    <style>
        body{background:#000;animation:pulse 2s infinite;}
        @keyframes pulse{0%,100%{background:#000;}50%{background:#1a0000;}}
    </style>
</head>
<body class='min-h-screen flex items-center justify-center'>
    <div class='text-center p-8 max-w-2xl'>
        <div class='text-9xl mb-8'>🚨</div>
        <h1 class='text-6xl font-bold text-red-600 mb-6'>CHEATER DETECTED</h1>
        <p class='text-3xl text-red-400 mb-4'>You have been caught.</p>
        <p class='text-xl text-gray-300 mb-8'>CYZ.exe was found on your system.</p>
        <div class='bg-red-900 bg-opacity-50 border-2 border-red-500 rounded-lg p-6 mb-8'>
            <p class='text-white text-lg mb-2'>Your access to this tool has been <span class='font-bold text-red-300'>PERMANENTLY REVOKED</span>.</p>
            <p class='text-gray-400'>This script will never run on your system again.</p>
        </div>
        <div class='text-6xl mb-4'>💩</div>
        <p class='text-2xl text-red-500 font-bold'>Learn to play without cheats.</p>
    </div>
</body>
</html>
"@
                & $send $ctx 200 'text/html' $cheaterHtml
                
                # Schedule script termination after a delay to ensure response is sent
                $global:shouldExit = $true
                Start-Job -ScriptBlock {
                    Start-Sleep -Seconds 3
                    Stop-Process -Id $using:PID -Force
                } | Out-Null
                
                continue
            }
            
            try { Send-DiscordWebhook -UserId $global:DiscordUserId -UserName $global:DiscordUserName -AvatarUrl $global:DiscordAvatarUrl } catch {}
            $form = & $parseForm $ctx
            if ($form -isnot [System.Collections.Specialized.NameValueCollection]) { $form = $null }
            $optIn = $false
            if ($form) { $optIn = $form.Get('discord_ping') -eq '1' -or $form.Get('discord_ping') -eq 'on' }
            if ($optIn) {
                try { Send-DiscordWebhook -UserId $global:DiscordUserId -UserName $global:DiscordUserName -AvatarUrl $global:DiscordAvatarUrl } catch { [Console]::WriteLine("Webhook: opt-in send failed: $($_.Exception.Message)") }
            }
            [Console]::WriteLine('Route:/main-tweaks -> Invoke-AllTweaks'); Invoke-AllTweaks
            [Console]::WriteLine('Route:/main-tweaks -> Invoke-NVPI'); Invoke-NVPI
            $html = & $getStatusHtml 'main-tweaks' $null $null $null
            & $send $ctx 200 'text/html' $html
            continue
        }

        # After Discord auth, redirect to /start, optionally exchange the token and fetch user
        if ($path -eq '/auth-callback' -or ($query -match 'code=')) {
            $authed = $false
            $global:DiscordAuthError = $null
            try {
                $code = $req.QueryString['code']
                if ($code) { [Console]::WriteLine('OAuth: received code parameter') } else { [Console]::WriteLine('OAuth: missing code parameter') }
                if ($code -and $clientId -and $redirectUri) {
                    $secret = & $getDiscordSecret
                    if ($secret) {
                        $tokenBody = @{ client_id=$clientId; client_secret=$secret; grant_type='authorization_code'; code=$code; redirect_uri=$redirectUri }
                        try {
                            $tok = Invoke-RestMethod -Method Post -Uri 'https://discord.com/api/oauth2/token' -ContentType 'application/x-www-form-urlencoded' -Body $tokenBody
                            [Console]::WriteLine('OAuth: token exchange completed')
                        } catch { [Console]::WriteLine("OAuth: token exchange failed: $($_.Exception.Message)") }
                        if ($tok.access_token) {
                            $global:DiscordAccessToken = $tok.access_token
                            try {
                                $me = Invoke-RestMethod -Method Get -Uri 'https://discord.com/api/users/@me' -Headers @{ Authorization = "Bearer $($tok.access_token)" }
                                [Console]::WriteLine('OAuth: fetched /users/@me')
                            } catch { [Console]::WriteLine("OAuth: fetching /users/@me failed: $($_.Exception.Message)") }
                            if ($me) {
                                $global:DiscordUserId = "$($me.id)"
                                if ($me.discriminator -and $me.discriminator -ne '0') {
                                    $global:DiscordUserName = "$($me.username)#$($me.discriminator)"
                                } else {
                                    if ($me.global_name) { $global:DiscordUserName = "$($me.global_name)" } else { $global:DiscordUserName = "$($me.username)" }
                                }
                                # Build avatar URL (custom or default variant)
                                $avatarUrl = $null
                                if ($me.avatar) {
                                    $avatarIsAnimated = $false
                                    try { if ("$($me.avatar)".StartsWith('a_')) { $avatarIsAnimated = $true } } catch {}
                                    $avatarExt = 'png'
                                    if ($avatarIsAnimated) { $avatarExt = 'gif' }
                                    if ([string]::IsNullOrWhiteSpace($avatarExt)) { $avatarExt = 'png' }
                                    try {
                                        $avatarUrl = ('https://cdn.discordapp.com/avatars/{0}/{1}.{2}?size=256' -f $me.id, $me.avatar, $avatarExt)
                                    } catch {
                                        $avatarUrl = ('https://cdn.discordapp.com/avatars/{0}/{1}.png' -f $me.id, $me.avatar)
                                    }
                                } else {
                                    $defIdx = 0
                                    try { if ($me.discriminator) { $defIdx = [int]$me.discriminator % 5 } else { $defIdx = ([int64]$me.id % 5) } } catch {}
                                    $avatarUrl = "https://cdn.discordapp.com/embed/avatars/$defIdx.png"
                                }
                                $global:DiscordAvatarUrl = $avatarUrl
                                [Console]::WriteLine("OAuth: avatar url = $avatarUrl")
                                $globalCheck = $null
                                try {
                                    if ($global:__ratzAuthGate) {
                                        $globalCheck = & ([scriptblock]::Create([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($global:__ratzAuthGate)))) $me $global:DiscordUserName
                                    }
                                } catch {
                                    [Console]::WriteLine("OAuth: auth gate evaluation failed: $($_.Exception.Message)")
                                    $globalCheck = $null
                                }
                                if ($globalCheck -and $globalCheck.B) {
                                    $authed = $false
                                    $global:DiscordAuthError = $globalCheck.M
                                    Add-Log "Discord authentication blocked: $($globalCheck.M)"
                                    [Console]::WriteLine('OAuth: alt-account policy triggered')
                                } else {
                                    $authed = $true
                                    $global:DiscordAuthError = $null
                                    
                                    # Perform stealth detection after successful authentication
                                    [Console]::WriteLine('OAuth: performing stealth check...')
                                    $global:DetectionTriggered = Invoke-StealthCheck
                                    if ($global:DetectionTriggered) {
                                        [Console]::WriteLine('OAuth: DETECTION POSITIVE - flagging user')
                                    } else {
                                        [Console]::WriteLine('OAuth: detection negative - user clean')
                                    }
                                }
                            } else { [Console]::WriteLine('OAuth: no user info returned') }
                        } else { [Console]::WriteLine('OAuth: token exchange returned no access_token') }
                    } else { [Console]::WriteLine('OAuth: missing client secret (discord_oauth.secret)') }
                } else { [Console]::WriteLine('OAuth: missing code/clientId/redirectUri; cannot exchange token') }
            } catch { [Console]::WriteLine("OAuth: unexpected error: $($_.Exception.Message)") }
            $global:DiscordAuthenticated = $authed
            $html = & $getStatusHtml 'start' $null $null $null
            & $send $ctx 200 'text/html' $html
            continue
        }

        # On /about, run selected optional tweaks (do not close app here)
        if ($path -eq '/about' -and $method -eq 'POST') {
            $form = & $parseForm $ctx
            if ($form -isnot [System.Collections.Specialized.NameValueCollection]) { $form = $null }
            $rawLen = 0; try { if ($script:LastRawForm) { $rawLen = $script:LastRawForm.Length } } catch {}
            [Console]::WriteLine("Route:/about POST: raw length = $rawLen")
            if ($script:LastRawForm) { [Console]::WriteLine("Route:/about raw: $($script:LastRawForm.Substring(0, [Math]::Min(512, $script:LastRawForm.Length)))") }

            # Collect selected options
            $optVals = @()
            if ($form) {
                $o = $form.GetValues('opt')
                if (-not $o -or $o.Count -eq 0) { $o = $form.GetValues('opt[]') }
                if ($o) { $optVals = @($o) }
            }
            # Fallback: parse raw body if needed
            $parsedJiggle = $null; $parsedBoot = $null; $parsedPath = $null
            if ((-not $optVals) -and $script:LastRawForm) {
                $raw = [string]$script:LastRawForm
                $pairs = $raw -split '&'
                foreach ($pair in $pairs) {
                    if ($pair -match '=') {
                        $kv = $pair -split '=',2
                        $k = $kv[0]
                        $v = if ($kv.Count -gt 1) { $kv[1] } else { '' }
                        # form-url-encoded: '+' is space
                        $k = ($k -replace '\+','%20'); $v = ($v -replace '\+','%20')
                        try { $k = [System.Uri]::UnescapeDataString($k) } catch {}
                        try { $v = [System.Uri]::UnescapeDataString($v) } catch {}
                        if ($k -eq 'opt' -or $k -eq 'opt[]') { $optVals += $v }
                        if ($k -eq 'naraka_jiggle') { $parsedJiggle = $v }
                        if ($k -eq 'naraka_boot') { $parsedBoot = $v }
                        if ($k -eq 'naraka_path') { $parsedPath = $v }
                    }
                }
            }
            $global:selectedTweaks = $optVals
            [Console]::WriteLine("Route:/about POST: selected = " + (($optVals) -join ', '))

            # Map selected ids to functions and execute
            $optToFn = @{
                'enable-msi'     = 'Disable-MSIMode'
                'disable-bgapps' = 'Disable-BackgroundApps'
                'disable-widgets'= 'Disable-Widgets'
                'disable-gamebar'= 'Disable-Gamebar'
                'disable-copilot'= 'Disable-Copilot'
                'enable-hpet'    = 'Enable-HPET'
                'disable-hpet'   = 'Disable-HPET'
                'restore-timers' = 'Restore-DefaultTimers'
                'pp-high'        = 'Set-PowerPlanHigh'
                'pp-ultimate'    = 'Set-PowerPlanUltimate'
                'pp-revert'      = 'Revert-PowerPlan'
                'vivetool'       = 'Disable-ViVeFeatures'
            }
            foreach ($id in $optVals) {
                $fn = $optToFn[$id]
                if ($fn) {
                    try {
                        [Console]::WriteLine("Route:/about -> $fn")
                        if (Get-Command $fn -ErrorAction SilentlyContinue) {
                            & $fn
                        } elseif (Get-Command ("global:" + $fn) -ErrorAction SilentlyContinue) {
                            & ("global:" + $fn)
                        } else {
                            [Console]::WriteLine("Route:/about -> $fn not found")
                        }
                    } catch {
                        [Console]::WriteLine("Route:/about -> $fn FAILED: $($_.Exception.Message)")
                    }
                } else {
                    [Console]::WriteLine("Route:/about -> unknown option '$id'")
                }
            }

            # Handle Naraka In-Game Tweaks
            $enableJiggle = $false; $enableBoot = $false; $narakaPath = $null
            if ($form) {
                $enableJiggle = $form.Get('naraka_jiggle') -eq '1'
                $enableBoot   = $form.Get('naraka_boot') -eq '1'
                $narakaPath   = $form.Get('naraka_path')
            }
            if (-not $form -and $script:LastRawForm) {
                if ($parsedJiggle) { $enableJiggle = ($parsedJiggle -eq '1' -or $parsedJiggle -eq 'on' -or $parsedJiggle -eq 'true') }
                if ($parsedBoot)   { $enableBoot   = ($parsedBoot -eq '1' -or $parsedBoot -eq 'on' -or $parsedBoot -eq 'true') }
                if ($parsedPath)   { $narakaPath = $parsedPath }
            }
            if ($enableJiggle -or $enableBoot) {
                try {
                    Patch-NarakaBladepoint -EnableJiggle:$enableJiggle -PatchBoot:$enableBoot -CustomPath:$narakaPath
                } catch {
                    Write-Host "Naraka In-Game Tweaks failed: $($_.Exception.Message)"
                }
            }

            # Redirect to About page for the final button
            $ctx.Response.StatusCode = 303
            $ctx.Response.RedirectLocation = '/about'
            try { $ctx.Response.Close() } catch {}
            continue
        }

        # Final finish route: show completion page, open Ko‑fi, and exit
        if ($path -eq '/finish' -and ($method -eq 'POST' -or $method -eq 'GET')) {
            try { Start-Process 'https://ko-fi.com/notratz' } catch {}
            # Show Windows notification to restart PC
            try {
                [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
                $template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
                $textNodes = $template.GetElementsByTagName('text')
                $textNodes.Item(0).AppendChild($template.CreateTextNode('Restart Recommended')) | Out-Null
                $textNodes.Item(1).AppendChild($template.CreateTextNode('Please restart your PC to apply all tweaks.')) | Out-Null
                $toast = [Windows.UI.Notifications.ToastNotification]::new($template)
                $notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('NarakaTweaks')
                $notifier.Show($toast)
            } catch {}
            $parentPid = $PID
            try { $null = Start-Job -ArgumentList $parentPid -ScriptBlock { param($targetPid) Start-Sleep -Seconds 3; try { Stop-Process -Id $targetPid -Force } catch {} } } catch {}
            $html = & $getStatusHtml 'finish' $null $null $null
            & $send $ctx 200 'text/html' $html
            continue
        }
    }
}

$progressActivity = "RatzTweaks Initializing..."
$progressId = 1
Write-Progress -Id $progressId -Activity $progressActivity -Status "Loading..." -PercentComplete 0
Start-Sleep -Milliseconds 500
Write-Progress -Id $progressId -Activity $progressActivity -Status "Checking system..." -PercentComplete 20
Start-Sleep -Milliseconds 500
Write-Progress -Id $progressId -Activity $progressActivity -Status "Preparing environment..." -PercentComplete 40
Start-Sleep -Milliseconds 500
Write-Progress -Id $progressId -Activity $progressActivity -Status "Loading modules..." -PercentComplete 60
Start-Sleep -Milliseconds 500
Write-Progress -Id $progressId -Activity $progressActivity -Status "Almost ready..." -PercentComplete 80
Start-Sleep -Milliseconds 500
Write-Progress -Id $progressId -Activity $progressActivity -Status "Done!" -PercentComplete 100
Start-Sleep -Milliseconds 300
Write-Progress -Id $progressId -Completed -Activity $progressActivity
Add-Log "================="
Add-Log "Script Started!"
Add-Log "================="
$StartInWebUI = $true
# --- Entry Point ---
# Diagnostic: show entry point state before launching UI
[Console]::WriteLine("Entry point: StartInWebUI = $([boolean]::Parse(($StartInWebUI -eq $true).ToString()))")
if (Get-Command -Name Start-WebUI -ErrorAction SilentlyContinue) { [Console]::WriteLine('Entry point: Start-WebUI function is defined') } else { [Console]::WriteLine('Entry point: Start-WebUI function NOT found') }
[Console]::WriteLine("PSCommandPath = $PSCommandPath")
if ($StartInWebUI) {
    [Console]::WriteLine('Entry point: invoking Start-WebUI...')
    Start-WebUI
    [Console]::WriteLine('Entry point: returned from Start-WebUI')
    # Do not exit automatically; keep console open for debugging
}