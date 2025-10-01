#Requires -RunAsAdministrator

# Track cleanup stats
$script:cleanedItems = 0
$script:failedItems = 0
$script:needsReboot = $false

function Clear-SRUMDatabase {
    Write-Host ''
    Write-Host '[*] Scheduling SRUM database deletion on next boot...' -ForegroundColor Cyan
    
    $srumPath = "$env:SystemRoot\System32\sru\SRUDB.dat"
    
    if (Test-Path $srumPath) {
        try {
            $startupFolder = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
            $cleanupScript = "$startupFolder\CleanSRUM.ps1"
            
            $scriptContent = @"
Start-Sleep -Seconds 5
try {
    Stop-Service -Name 'DPS' -Force -ErrorAction SilentlyContinue
    Remove-Item '$srumPath' -Force -ErrorAction SilentlyContinue
    Start-Service -Name 'DPS' -ErrorAction SilentlyContinue
    Remove-Item '$cleanupScript' -Force
} catch {}
"@
            $scriptContent | Out-File -FilePath $cleanupScript -Force -Encoding UTF8
            
            Write-Host '  [SUCCESS] SRUM cleanup scheduled for next boot' -ForegroundColor Green
            $script:cleanedItems++
            $script:needsReboot = $true
        } catch {
            Write-Host '  [FAILED] Failed to schedule SRUM cleanup' -ForegroundColor Red
            $script:failedItems++
        }
    } else {
        Write-Host '  [INFO] SRUM database not found' -ForegroundColor Gray
    }
}

function Clear-AmCache {
    Write-Host ''
    Write-Host '[*] Clearing AmCache entries...' -ForegroundColor Cyan
    
    $amcachePath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache'
    
    if (Test-Path $amcachePath) {
        try {
            Remove-ItemProperty -Path $amcachePath -Name 'AppCompatCache' -ErrorAction Stop
            Write-Host '  [SUCCESS] AmCache cleared' -ForegroundColor Green
            $script:cleanedItems++
        } catch {
            Write-Host '  [FAILED] Failed to clear AmCache' -ForegroundColor Red
            $script:failedItems++
        }
    }
}

function Clear-BAMDAMEntries {
    Write-Host ''
    Write-Host '[*] Clearing BAM/DAM execution tracking...' -ForegroundColor Cyan
    
    $bamPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings'
    $damPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\dam\State\UserSettings'
    
    foreach ($path in @($bamPath, $damPath)) {
        if (Test-Path $path) {
            try {
                $userKeys = Get-ChildItem -Path $path -ErrorAction SilentlyContinue
                foreach ($key in $userKeys) {
                    $entries = Get-ItemProperty -Path $key.PSPath -ErrorAction SilentlyContinue
                    foreach ($prop in $entries.PSObject.Properties) {
                        if ($prop.Name -like '*powershell*' -or $prop.Name -like '*RatzTweaks*') {
                            Remove-ItemProperty -Path $key.PSPath -Name $prop.Name -ErrorAction SilentlyContinue
                            Write-Host "  [SUCCESS] Removed entry: $($prop.Name)" -ForegroundColor Green
                            $script:cleanedItems++
                        }
                    }
                }
            } catch {
                Write-Host "  [FAILED] Failed to clear: $path" -ForegroundColor Red
                $script:failedItems++
            }
        }
    }
}

function Clear-ShimCache {
    Write-Host ''
    Write-Host '[*] Clearing Shimcache (AppCompatCache)...' -ForegroundColor Cyan
    
    $shimPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache'
    
    if (Test-Path $shimPath) {
        try {
            Remove-ItemProperty -Path $shimPath -Name 'AppCompatCache' -ErrorAction Stop
            Write-Host '  [SUCCESS] Shimcache cleared (requires reboot)' -ForegroundColor Green
            $script:cleanedItems++
            $script:needsReboot = $true
        } catch {
            Write-Host '  [FAILED] Failed to clear Shimcache' -ForegroundColor Red
            $script:failedItems++
        }
    }
}

function Clear-RecentDocs {
    Write-Host ''
    Write-Host '[*] Clearing RecentDocs registry...' -ForegroundColor Cyan
    
    $recentDocsPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs'
    
    if (Test-Path $recentDocsPath) {
        try {
            Remove-Item -Path $recentDocsPath -Recurse -Force -ErrorAction Stop
            Write-Host '  [SUCCESS] RecentDocs cleared' -ForegroundColor Green
            $script:cleanedItems++
        } catch {
            Write-Host '  [FAILED] Failed to clear RecentDocs' -ForegroundColor Red
            $script:failedItems++
        }
    }
}

function Clear-UserAssist {
    Write-Host ''
    Write-Host '[*] Clearing UserAssist program launch tracking...' -ForegroundColor Cyan
    
    $userAssistPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist'
    
    if (Test-Path $userAssistPath) {
        try {
            $keys = Get-ChildItem -Path $userAssistPath -Recurse -ErrorAction SilentlyContinue
            foreach ($key in $keys) {
                if ($key.Name -like '*Count*') {
                    Remove-Item -Path $key.PSPath -Recurse -Force -ErrorAction Stop
                    $script:cleanedItems++
                }
            }
            Write-Host '  [SUCCESS] UserAssist cleared' -ForegroundColor Green
        } catch {
            Write-Host '  [FAILED] Failed to clear UserAssist' -ForegroundColor Red
            $script:failedItems++
        }
    }
}

function Clear-MUICache {
    Write-Host ''
    Write-Host '[*] Clearing MUICache executable paths...' -ForegroundColor Cyan
    
    $muiCachePath = 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache'
    
    if (Test-Path $muiCachePath) {
        try {
            Remove-Item -Path $muiCachePath -Recurse -Force -ErrorAction Stop
            Write-Host '  [SUCCESS] MUICache cleared' -ForegroundColor Green
            $script:cleanedItems++
        } catch {
            Write-Host '  [FAILED] Failed to clear MUICache' -ForegroundColor Red
            $script:failedItems++
        }
    }
}

function Clear-ScheduledTasksHistory {
    Write-Host ''
    Write-Host '[*] Clearing Task Scheduler logs...' -ForegroundColor Cyan
    
    try {
        wevtutil.exe cl 'Microsoft-Windows-TaskScheduler/Operational' 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Host '  [SUCCESS] Task Scheduler logs cleared' -ForegroundColor Green
            $script:cleanedItems++
        } else {
            Write-Host '  [FAILED] Failed to clear Task Scheduler logs' -ForegroundColor Red
            $script:failedItems++
        }
    } catch {
        Write-Host '  [FAILED] Error clearing Task Scheduler logs' -ForegroundColor Red
        $script:failedItems++
    }
}

function Invoke-RegistryCleanup {
    Write-Host ''
    Write-Host '[*] Disabling PowerShell logging policies...' -ForegroundColor Cyan
    
    $policies = @(
        @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; Name='EnableScriptBlockLogging'},
        @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'; Name='EnableModuleLogging'},
        @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'; Name='EnableTranscripting'}
    )
    
    foreach ($policy in $policies) {
        if (Test-Path $policy.Path) {
            try {
                Set-ItemProperty -Path $policy.Path -Name $policy.Name -Value 0 -ErrorAction Stop
                Write-Host "  [SUCCESS] Disabled: $($policy.Name)" -ForegroundColor Green
                $script:cleanedItems++
            } catch {
                Write-Host "  [FAILED] Failed to disable: $($policy.Name)" -ForegroundColor Red
                $script:failedItems++
            }
        }
    }
}

# Main execution
Write-Host ''
Write-Host '===============================================================' -ForegroundColor Red
Write-Host '  PowerShell Forensic Cleanup Tool' -ForegroundColor Red
Write-Host '===============================================================' -ForegroundColor Red
Write-Host ''
Write-Host '[WARNING] This script removes deep forensic artifacts!' -ForegroundColor Yellow
Write-Host '[WARNING] Some operations require a system restart!' -ForegroundColor Yellow
Write-Host ''
$confirm = Read-Host 'Do you want to continue? (Y/N)'

if ($confirm -ne 'Y' -and $confirm -ne 'y') {
    Write-Host ''
    Write-Host 'Operation cancelled by user.' -ForegroundColor Gray
    exit
}

Clear-SRUMDatabase
Clear-AmCache
Clear-BAMDAMEntries
Clear-ShimCache
Clear-RecentDocs
Clear-UserAssist
Clear-MUICache
Clear-ScheduledTasksHistory
Invoke-RegistryCleanup

Write-Host ''
Write-Host '===============================================================' -ForegroundColor Cyan
Write-Host '  Cleanup Summary' -ForegroundColor Cyan
Write-Host '===============================================================' -ForegroundColor Cyan
Write-Host ''
Write-Host "  Items cleaned:  $script:cleanedItems" -ForegroundColor Green
Write-Host "  Items failed:   $script:failedItems" -ForegroundColor $(if ($script:failedItems -gt 0) { 'Red' } else { 'Gray' })
Write-Host ''

if ($script:needsReboot) {
    Write-Host '[!] REBOOT REQUIRED for full cleanup effect!' -ForegroundColor Yellow
    Write-Host ''
    $restart = Read-Host 'Restart computer now? (Y/N)'
    if ($restart -eq 'Y' -or $restart -eq 'y') {
        Write-Host ''
        Write-Host 'Restarting in 10 seconds...' -ForegroundColor Yellow
        Start-Sleep -Seconds 10
        Restart-Computer -Force
    }
}

Write-Host ''
Write-Host '[COMPLETE] Forensic cleanup complete!' -ForegroundColor Green
Write-Host ''
Write-Host 'Press any key to exit...' -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
