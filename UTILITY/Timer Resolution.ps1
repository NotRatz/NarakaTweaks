# Requires -RunAsAdministrator

# --- Elevate if needed ---
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process PowerShell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
    exit
}

$Host.UI.RawUI.WindowTitle = $myInvocation.MyCommand.Definition + " (Administrator)"
$Host.UI.RawUI.BackgroundColor = "Black"
$Host.PrivateData.ProgressBackgroundColor = "Black"
$Host.PrivateData.ProgressForegroundColor = "White"
Clear-Host

Write-Host "1. Timer Resolution: On (5040, 0.504 ms)"
Write-Host "2. Timer Resolution: Default / Remove service"

while ($true) {
    $choice = Read-Host " "
    if ($choice -match '^[1-2]$') {
        switch ($choice) {
            1 {
                Clear-Host
                Write-Host "Installing: Set Timer Resolution Service (forcing 5040) . . ."

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
            this.ServiceName = "STR";                  // Keep service name consistent
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
                SetMaximumResolution();   // Always-on mode if no .ini
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
                this.startWatch.Stop();
            base.OnStop();
            // Restore default on service stop
            try {
                uint actual = 0;
                NtSetTimerResolution(this.DefaultResolution, true, out actual);
            } catch {}
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
            // Force 5040 (0.504 ms) regardless of reported Maximum
            // If your platform can't go that low, the kernel clamps it.
            long counter = Interlocked.Increment(ref this.processCounter);
            if(counter <= 1)
            {
                uint actual = 0;
                try {
                    NtSetTimerResolution(5040, true, out actual);
                    if(null != this.EventLog)
                        try { this.EventLog.WriteEntry(String.Format("Requested=5040; Actual={0}", actual)); }
                        catch {}
                } catch {}
            }
        }

        void SetDefaultResolution()
        {
            long counter = Interlocked.Decrement(ref this.processCounter);
            if(counter < 1)
            {
                uint actual = 0;
                try {
                    NtSetTimerResolution(this.DefaultResolution, true, out actual);
                    if(null != this.EventLog)
                        try { this.EventLog.WriteEntry(String.Format("Restored default; Actual={0}", actual)); }
                        catch {}
                } catch {}
            }
        }
    }

    [RunInstaller(true)]
    public class WindowsServiceInstaller : Installer
    {
        public WindowsServiceInstaller()
        {
            ServiceProcessInstaller serviceProcessInstaller = new ServiceProcessInstaller();
            ServiceInstaller serviceInstaller = new ServiceInstaller();
            serviceProcessInstaller.Account = ServiceAccount.LocalSystem;
            serviceProcessInstaller.Username = null;
            serviceProcessInstaller.Password = null;
            serviceInstaller.DisplayName = "Set Timer Resolution Service";
            serviceInstaller.StartType = ServiceStartMode.Automatic;
            serviceInstaller.ServiceName = "STR";      // Must match ServiceBase.ServiceName
            this.Installers.Add(serviceProcessInstaller);
            this.Installers.Add(serviceInstaller);
        }
    }
}
"@

                $csPath  = "$env:SystemDrive\Windows\SetTimerResolutionService.cs"
                $exePath = "$env:SystemDrive\Windows\SetTimerResolutionService.exe"

                Set-Content -Path $csPath -Value $MultilineComment -Force

                $csc = "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
                if (-not (Test-Path $csc)) {
                    $csc = "C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe"
                }
                if (-not (Test-Path $csc)) {
                    Write-Host "ERROR: C# compiler (csc.exe) not found." -ForegroundColor Red
                    pause
                    exit
                }

                Start-Process -Wait $csc -ArgumentList "-out:$exePath $csPath" -WindowStyle Hidden
                Remove-Item $csPath -ErrorAction SilentlyContinue | Out-Null

                # Remove any old service variants
                foreach ($old in @("Set Timer Resolution Service","STR")) {
                    if (Get-Service -Name $old -ErrorAction SilentlyContinue) {
                        try {
                            Set-Service -Name $old -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
                            Stop-Service -Name $old -Force -ErrorAction SilentlyContinue | Out-Null
                            sc.exe delete $old | Out-Null
                        } catch {}
                    }
                }

                # Create consistent service name (STR) with a human DisplayName
                New-Service -Name "STR" -DisplayName "Set Timer Resolution Service" -BinaryPathName $exePath -StartupType Automatic -ErrorAction SilentlyContinue | Out-Null
                Start-Service -Name "STR" -ErrorAction SilentlyContinue | Out-Null

                Start-Process taskmgr.exe
                exit
            }
            2 {
                Clear-Host
                Write-Host "Stopping and removing service . . ."
                foreach ($svc in @("STR","Set Timer Resolution Service")) {
                    if (Get-Service -Name $svc -ErrorAction SilentlyContinue) {
                        try {
                            Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
                            Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue | Out-Null
                            sc.exe delete $svc | Out-Null
                        } catch {}
                    }
                }
                # Remove exe
                $exePath = "$env:SystemDrive\Windows\SetTimerResolutionService.exe"
                if (Test-Path $exePath) { Remove-Item $exePath -Force -ErrorAction SilentlyContinue | Out-Null }
                Start-Process taskmgr.exe
                exit
            }
        }
    } else {
        Write-Host "Invalid input. Please select a valid option (1-2)."
    }
}
