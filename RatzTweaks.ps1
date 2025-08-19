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
Start-Sleep -Milliseconds 1200
function Write-Host { param([Parameter(ValueFromRemainingArguments=$true)][object[]]$args) } # no-op
function Write-Output { param([Parameter(ValueFromRemainingArguments=$true)][object[]]$args) } # no-op
$InformationPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$ErrorActionPreference = 'SilentlyContinue'

# Ensure log path and PSCommandPath are defined even when run via iwr | iex
if (-not $PSCommandPath) { $PSCommandPath = Join-Path $PSScriptRoot 'RatzTweaks.ps1' }
$logPath = Join-Path $env:TEMP 'RatzTweaks_fatal.log'
if (-not $global:RatzLog) { $global:RatzLog = @() }

# --- Auto-download all required files if missing (for irm ... | iex users) ---
$needDownload = $false
if (-not (Test-Path (Join-Path $PSScriptRoot 'UTILITY')) -or -not (Test-Path (Join-Path $PSScriptRoot 'RatzSettings.nip')) -or -not (Test-Path (Join-Path $PSScriptRoot 'ratznaked.jpg'))) {
    $needDownload = $true
}
if ($needDownload) {
    $repoZipUrl = 'https://github.com/NotRatz/NarakaTweaks/archive/refs/heads/main.zip'
    $tempDir = Join-Path $env:TEMP ('NarakaTweaks_' + [guid]::NewGuid().ToString())
    $zipPath = Join-Path $env:TEMP ('NarakaTweaks-main.zip')
    Write-Host 'Downloading full NarakaTweaks package...'
    Invoke-WebRequest -Uri $repoZipUrl -OutFile $zipPath -UseBasicParsing
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $tempDir)
    Remove-Item $zipPath -Force
    $extractedRoot = Join-Path $tempDir 'NarakaTweaks-main'
    $mainScript = Join-Path $extractedRoot 'RatzTweaks.ps1'
    Write-Host 'Launching full RatzTweaks.ps1 from temp folder...'
    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$mainScript`" -WindowStyle Hidden"
    # Ensure the original process exits immediately to prevent double execution
    Stop-Process -Id $PID -Force
}
if ($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.Major -gt 5) {
    $msg = @"
RatzTweaks requires Windows PowerShell 5.1 (not PowerShell 7+).
WinForms UI and threading are not supported in pwsh.exe.
Please right-click and run this script with Windows PowerShell (powershell.exe).
"@
    Write-Host $msg -ForegroundColor Red
    [System.Windows.Forms.MessageBox]::Show($msg, 'RatzTweaks - Incompatible PowerShell', 'OK', [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
    exit 1
}
# Show-LogWindow: Displays the log in a scrollable window
function Show-LogWindow {

    $form = New-Object Windows.Forms.Form
    $form.Text = 'RatzTweaks Log'
    $form.Size = New-Object Drawing.Size(700, 500)
    $form.StartPosition = 'CenterScreen'
    $form.BackColor = [Drawing.Color]::Black
    $form.ForeColor = [Drawing.Color]::White

    $txtLog = New-Object Windows.Forms.TextBox
    $txtLog.Multiline = $true
    $txtLog.ReadOnly = $true
    $txtLog.ScrollBars = 'Vertical'
    $txtLog.Size = New-Object Drawing.Size(660, 380)
    $txtLog.Location = New-Object Drawing.Point(10, 10)
    $txtLog.BackColor = [Drawing.Color]::FromArgb(24,24,24)
    $txtLog.ForeColor = [Drawing.Color]::White
    $txtLog.Font = New-Object Drawing.Font('Consolas', 11)
    $txtLog.Text = $global:RatzLog -join "`r`n"
    $form.Controls.Add($txtLog)

    $btnClose = New-Object Windows.Forms.Button
    $btnClose.Text = 'Close'
    $btnClose.Size = New-Object Drawing.Size(120, 40)
    $btnClose.Location = New-Object Drawing.Point(280, 410)
    $btnClose.Font = New-Object Drawing.Font('Segoe UI', 12, [Drawing.FontStyle]::Bold)
    $btnClose.Add_Click({ $form.Close() })
    $form.Controls.Add($btnClose)

    $form.Topmost = $true
    $form.ShowDialog() | Out-Null
}
# RatzTweaks.ps1
# Main PowerShell script to combine all tweaks, UI, and automation


# Global .NET/WinForms unhandled exception handler (only in Windows PowerShell 5.1)
if ($PSVersionTable.PSEdition -eq 'Desktop' -and $PSVersionTable.Major -eq 5) {
    [System.AppDomain]::CurrentDomain.UnhandledException += {
        param($sender, $eventArgs)
        $ex = $eventArgs.ExceptionObject
        $fatalMsg = "UNHANDLED .NET EXCEPTION: $($ex.Message)"
        try {
            $logPath = Join-Path $env:TEMP 'RatzTweaks_fatal.log'
            Add-Content -Path $logPath -Value (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')'  ' + $fatalMsg
        } catch {}
        try { $global:RatzLog += (Get-Date -Format 'HH:mm:ss') + '  ' + $fatalMsg } catch {}
        try {
            if ($script:txtProgress) { $script:txtProgress.Lines += $fatalMsg }
        } catch {}
        try {
            if (-not (Get-EventLog -LogName Application -Source 'RatzTweaks' -ErrorAction SilentlyContinue)) {
                New-EventLog -LogName Application -Source 'RatzTweaks' -ErrorAction SilentlyContinue
            }
            Write-EventLog -LogName Application -Source 'RatzTweaks' -EntryType Error -EventId 1001 -Message $fatalMsg -ErrorAction SilentlyContinue
        } catch {}
        try { Write-Host $fatalMsg } catch {}
    }
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

function Test-Admin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal $currentUser
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $psi = New-Object System.Diagnostics.ProcessStartInfo 'powershell.exe'
        $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
        $psi.Verb = 'runas'
        [System.Diagnostics.Process]::Start($psi) | Out-Null
        exit
    }
}


# Helper: highlight active button (must be top-level)
function Set-ActiveTab {
    param($activeBtn, $btnMain, $btnGPU, $btnOptional, $btnAbout)
    $allBtns = @($btnMain, $btnGPU, $btnOptional, $btnAbout)
    foreach ($b in $allBtns) {
        $b.BackColor = [Drawing.Color]::FromArgb(48,48,48)
        $b.ForeColor = [Drawing.Color]::White
        $b.Enabled = $false
    }
    $activeBtn.BackColor = [Drawing.Color]::FromArgb(0,200,80)
    $activeBtn.ForeColor = [Drawing.Color]::Black
    $activeBtn.Enabled = $true
}

# Hide all panels (must be top-level)
function Hide-AllPanels {
    param($panelMain, $panelGPU, $panelOptional, $panelAbout)
    $panelMain.Visible = $false
    $panelGPU.Visible = $false
    $panelOptional.Visible = $false
    $panelAbout.Visible = $false
}

# Modern dark-themed, sidebar/tabbed UI inspired by Chris Titus Tech
function Show-IntroUI {

    $form = New-Object Windows.Forms.Form
    $form.Text = '' # Remove text for custom top bar
    $form.Size = New-Object Drawing.Size(900, 600)
    $form.StartPosition = 'CenterScreen'
    $form.FormBorderStyle = 'None' # Remove Windows title bar
    $form.MaximizeBox = $false
    $form.BackColor = [Drawing.Color]::Black
    $form.ForeColor = [Drawing.Color]::White

    # Custom Top Bar

    $topBar = New-Object Windows.Forms.Panel
    $topBar.Size = New-Object Drawing.Size(900, 40)
    $topBar.Location = New-Object Drawing.Point(0,0)
    $topBar.BackColor = [Drawing.Color]::Black
    $form.Controls.Add($topBar)

    $lblTitle = New-Object Windows.Forms.Label
    $lblTitle.Text = 'Rat Naraka Tweaks'
    $lblTitle.Font = New-Object Drawing.Font('Segoe UI', 16, [Drawing.FontStyle]::Bold)
    $lblTitle.ForeColor = [Drawing.Color]::White
    $lblTitle.AutoSize = $true
    $lblTitle.Location = New-Object Drawing.Point(20, 7)
    $topBar.Controls.Add($lblTitle)

    # Custom close button
    $btnClose = New-Object Windows.Forms.Button
    $btnClose.Text = 'X'
    $btnClose.Size = New-Object Drawing.Size(40, 32)
    $btnClose.Location = New-Object Drawing.Point(850, 4)
    $btnClose.BackColor = [Drawing.Color]::FromArgb(40,40,40)
    $btnClose.ForeColor = [Drawing.Color]::White
    $btnClose.FlatStyle = 'Flat'
    $btnClose.Font = New-Object Drawing.Font('Segoe UI', 14, [Drawing.FontStyle]::Bold)
    $btnClose.Add_Click({ $form.Close() })
    $topBar.Controls.Add($btnClose)

    # Allow dragging the window by the top bar
    $topBar.Add_MouseDown({
        $script:drag = $true
        $script:mouseX = [System.Windows.Forms.Cursor]::Position.X - $form.Left
        $script:mouseY = [System.Windows.Forms.Cursor]::Position.Y - $form.Top
    })
    $topBar.Add_MouseUp({ $script:drag = $false })
    $topBar.Add_MouseMove({
        if ($script:drag) {
            $form.Left = [System.Windows.Forms.Cursor]::Position.X - $script:mouseX
            $form.Top = [System.Windows.Forms.Cursor]::Position.Y - $script:mouseY
        }
    })

    # Sidebar panel
    $sidebar = New-Object Windows.Forms.Panel
    $sidebar.Size = New-Object Drawing.Size(180, 560)
    $sidebar.Location = New-Object Drawing.Point(0,40)
    $sidebar.BackColor = [Drawing.Color]::FromArgb(24,24,24)
    $form.Controls.Add($sidebar)

    # Main content panel
    $mainPanel = New-Object Windows.Forms.Panel
    $mainPanel.Size = New-Object Drawing.Size(700, 560)
    $mainPanel.Location = New-Object Drawing.Point(180,40)
    $mainPanel.BackColor = [Drawing.Color]::FromArgb(40,40,40)
    $form.Controls.Add($mainPanel)

    # Sidebar buttons
    $btnMain = New-Object Windows.Forms.Button
    $btnMain.Text = 'Main Tweaks'
    $btnMain.Size = New-Object Drawing.Size(160, 50)
    $btnMain.Location = New-Object Drawing.Point(10, 30)
    $btnMain.BackColor = [Drawing.Color]::FromArgb(48,48,48)
    $btnMain.ForeColor = [Drawing.Color]::White
    $btnMain.FlatStyle = 'Flat'
    $btnMain.Font = New-Object Drawing.Font('Segoe UI', 12, [Drawing.FontStyle]::Bold)
    $sidebar.Controls.Add($btnMain)

    $btnGPU = New-Object Windows.Forms.Button
    $btnGPU.Text = 'GPU Tweaks'
    $btnGPU.Size = New-Object Drawing.Size(160, 50)
    $btnGPU.Location = New-Object Drawing.Point(10, 90)
    $btnGPU.BackColor = [Drawing.Color]::FromArgb(48,48,48)
    $btnGPU.ForeColor = [Drawing.Color]::White
    $btnGPU.FlatStyle = 'Flat'
    $btnGPU.Font = New-Object Drawing.Font('Segoe UI', 12, [Drawing.FontStyle]::Bold)
    $sidebar.Controls.Add($btnGPU)

    $btnOptional = New-Object Windows.Forms.Button
    $btnOptional.Text = 'Optional Tweaks'
    $btnOptional.Size = New-Object Drawing.Size(160, 50)
    $btnOptional.Location = New-Object Drawing.Point(10, 150)
    $btnOptional.BackColor = [Drawing.Color]::FromArgb(48,48,48)
    $btnOptional.ForeColor = [Drawing.Color]::White
    $btnOptional.FlatStyle = 'Flat'
    $btnOptional.Font = New-Object Drawing.Font('Segoe UI', 12, [Drawing.FontStyle]::Bold)
    $sidebar.Controls.Add($btnOptional)

    $btnAbout = New-Object Windows.Forms.Button
    $btnAbout.Text = 'About'
    $btnAbout.Size = New-Object Drawing.Size(160, 50)
    $btnAbout.Location = New-Object Drawing.Point(10, 210)
    $btnAbout.BackColor = [Drawing.Color]::FromArgb(48,48,48)
    $btnAbout.ForeColor = [Drawing.Color]::White
    $btnAbout.FlatStyle = 'Flat'
    $btnAbout.Font = New-Object Drawing.Font('Segoe UI', 12, [Drawing.FontStyle]::Bold)
    $sidebar.Controls.Add($btnAbout)

    # Progress/Log area (larger)
    $txtProgress = New-Object Windows.Forms.TextBox
    $txtProgress.Multiline = $true
    $txtProgress.ReadOnly = $true
    $txtProgress.ScrollBars = 'Vertical'
    $txtProgress.Size = New-Object Drawing.Size(660, 140)
    $txtProgress.Location = New-Object Drawing.Point(20, 370)
    $txtProgress.BackColor = [Drawing.Color]::FromArgb(24,24,24)
    $txtProgress.ForeColor = [Drawing.Color]::White
    $txtProgress.Font = New-Object Drawing.Font('Consolas', 10)
    $mainPanel.Controls.Add($txtProgress)

    # Panels for each section
    $panelMain = New-Object Windows.Forms.Panel
    $panelMain.Size = New-Object Drawing.Size(660, 320)
    $panelMain.Location = New-Object Drawing.Point(20, 30)
    $panelMain.BackColor = $mainPanel.BackColor
    $mainPanel.Controls.Add($panelMain)

    $panelGPU = New-Object Windows.Forms.Panel
    $panelGPU.Size = $panelMain.Size
    $panelGPU.Location = $panelMain.Location
    $panelGPU.BackColor = $mainPanel.BackColor
    $panelGPU.Visible = $false
    $mainPanel.Controls.Add($panelGPU)

    $panelOptional = New-Object Windows.Forms.Panel
    $panelOptional.Size = $panelMain.Size
    $panelOptional.Location = $panelMain.Location
    $panelOptional.BackColor = $mainPanel.BackColor
    $panelOptional.Visible = $false
    $mainPanel.Controls.Add($panelOptional)

    $panelAbout = New-Object Windows.Forms.Panel
    $panelAbout.Size = $panelMain.Size
    $panelAbout.Location = $panelMain.Location
    $panelAbout.BackColor = $mainPanel.BackColor
    $panelAbout.Visible = $false
    $mainPanel.Controls.Add($panelAbout)

    # Main Tweaks Panel Content
    $lblMain = New-Object Windows.Forms.Label
    $lblMain.Text = "Welcome to RatzTweaks!`n`nThis utility will apply all main system tweaks, registry edits, and timer resolution optimizations.`n`nClick 'Start' to begin."
    $lblMain.Size = New-Object Drawing.Size(480, 120)
    $lblMain.Location = New-Object Drawing.Point(10, 30)
    $lblMain.Font = New-Object Drawing.Font('Segoe UI', 13, [Drawing.FontStyle]::Bold)
    $lblMain.ForeColor = [Drawing.Color]::White
    $panelMain.Controls.Add($lblMain)


    $btnStart = New-Object Windows.Forms.Button
    $btnStart.Text = 'Start'
    $btnStart.Size = New-Object Drawing.Size(120,48)
    $btnStart.Location = New-Object Drawing.Point(20, 220)
    $btnStart.Font = New-Object Drawing.Font('Segoe UI', 14, [Drawing.FontStyle]::Bold)
    $btnStart.BackColor = [Drawing.Color]::FromArgb(0,120,215)
    $btnStart.ForeColor = [Drawing.Color]::White
    $btnStart.FlatStyle = 'Flat'
    $panelMain.Controls.Add($btnStart)
    $btnStart.Add_Click({
        try {
            $btnStart.Enabled = $false
            Add-Log 'Start clicked: beginning flow...'
            $clientSecret = Get-DiscordSecret
            if (-not $clientSecret) {
                Add-Log 'Local encrypted secret not found; using embedded fallback secret for convenience.'
                $clientSecret = $EmbeddedDiscordClientSecret
            }
            Start-DiscordOAuthAndLog
            Add-Log 'Running main tweaks...'
            Invoke-AllTweaks
            Add-Log 'All tweaks applied.'
            Show-RestartPrompt
        } catch {
            Add-Log "ERROR in Start button flow: $($_.Exception.Message)"
        } finally {
            $btnStart.Enabled = $true
        }
    })

    # Add Revert Optional Tweaks button
    $btnRevert = New-Object Windows.Forms.Button
    $btnRevert.Text = 'Revert Optional Tweaks'
    $btnRevert.Size = New-Object Drawing.Size(220, 40)
    $btnRevert.Location = New-Object Drawing.Point(350, 185)
    $btnRevert.BackColor = [Drawing.Color]::FromArgb(200,40,40)
    $btnRevert.ForeColor = [Drawing.Color]::White
    $btnRevert.FlatStyle = 'Flat'
    $btnRevert.Font = New-Object Drawing.Font('Segoe UI', 11, [Drawing.FontStyle]::Bold)
    $btnRevert.Add_Click({
        try {
            Revert-OptionalTweaks
            Update-ProgressLog 'Optional tweaks reverted.'
        } catch {
            Update-ProgressLog ("ERROR reverting optional tweaks: " + $_.Exception.Message)
        }
    })
    $panelMain.Controls.Add($btnRevert)

    # GPU Tweaks Panel Content
    $lblGPU = New-Object Windows.Forms.Label
    $lblGPU.Text = "GPU Tweaks`n`nNvidia and AMD registry tweaks will be applied automatically."
    $lblGPU.Size = New-Object Drawing.Size(480, 80)
    $lblGPU.Location = New-Object Drawing.Point(10, 30)
    $lblGPU.Font = New-Object Drawing.Font('Segoe UI', 12, [Drawing.FontStyle]::Bold)
    $lblGPU.ForeColor = [Drawing.Color]::White
    $panelGPU.Controls.Add($lblGPU)

    # Optional Tweaks Panel Content (integrated selection UI)
    $lblOptional = New-Object Windows.Forms.Label
    $lblOptional.Text = "Optional Tweaks`n`nSelect additional tweaks to apply."
    $lblOptional.Size = New-Object Drawing.Size(600, 40)
    $lblOptional.Location = New-Object Drawing.Point(10, 10)
    $lblOptional.Font = New-Object Drawing.Font('Segoe UI', 13, [Drawing.FontStyle]::Bold)
    $lblOptional.ForeColor = [Drawing.Color]::White
    $panelOptional.Controls.Add($lblOptional)

    $utilityDir = Join-Path $PSScriptRoot 'UTILITY'
    # Exclude 'option 10.' from the selectable tweaks (by filename or by name)
    $ps1Files = Get-ChildItem -Path $utilityDir -Filter '*.ps1' |
        Where-Object { $_.Name -notlike '*Disable Run as Admin.ps1' -and $_.BaseName -notmatch '^(10\.|option 10)' }
    $optionalDescriptions = @{
        'MSI Mode' = 'Enables Message Signaled Interrupts for all PCI devices for improved latency.'
        'Disable Background Apps' = 'Prevents apps from running in the background to save resources.'
        'Disable Widgets' = 'Removes Windows taskbar widgets for a cleaner UI and less resource use.'
        'Disable Gamebar' = 'Disables the Xbox Game Bar overlay and background services.'
        'Disable Copilot' = 'Removes the Windows Copilot AI assistant from the taskbar.'
        'Disable Windows Features (ViVeTool)' = 'Disables specific experimental Windows features using ViVeTool.'
    }
    $checkboxes = @()
    $orderedPs1Files = @()
    $y = 60
    foreach ($file in $ps1Files) {
        $desc = $optionalDescriptions[$file.BaseName]
        $cb = New-Object Windows.Forms.CheckBox
        if ($desc) {
            $cb.Text = "$($file.BaseName) - $desc"
        } else {
            $cb.Text = $file.BaseName
        }
        $cb.Size = New-Object Drawing.Size(600,24)
        $cb.Location = New-Object Drawing.Point(30,$y)
        $cb.Font = New-Object Drawing.Font('Segoe UI',11)
        $panelOptional.Controls.Add($cb)
        $checkboxes += $cb
        $orderedPs1Files += $file
        $y += 30
    }
    # Add ViVeTool features as an optional tweak
    $descViVe = $optionalDescriptions['Disable Windows Features (ViVeTool)']
    $cbViVe = New-Object Windows.Forms.CheckBox
    $cbViVe.Text = "Disable Windows Features (ViVeTool) - $descViVe"
    $cbViVe.Size = New-Object Drawing.Size(600,24)
    $cbViVe.Location = New-Object Drawing.Point(30,$y)
    $cbViVe.Font = New-Object Drawing.Font('Segoe UI',11)
    $panelOptional.Controls.Add($cbViVe)
    $checkboxes += $cbViVe
    $orderedPs1Files += $null  # Placeholder for ViVeTool
    $y += 30
    $okBtn = New-Object Windows.Forms.Button
    $okBtn.Text = 'Apply Selected'
    $okBtn.Size = New-Object Drawing.Size(180,40)
    $okBtn.Location = New-Object Drawing.Point(240, ($y+10))
    $okBtn.Font = New-Object Drawing.Font('Segoe UI',12)
    $okBtn.Add_Click({
        try {
            $global:selectedTweaks = @()
            for ($i=0; $i -lt $checkboxes.Count; $i++) {
                if ($checkboxes[$i].Checked) {
                    if ($orderedPs1Files[$i] -eq $null) {
                        $global:selectedTweaks += 'ViVeToolFeatures'
                    } else {
                        $global:selectedTweaks += $orderedPs1Files[$i].FullName
                    }
                }
            }
            $okBtn.Enabled = $false
            $okBtn.Text = 'Applied!'
            # After user applies, continue the workflow
            Complete-Tweaks
        } catch [System.Management.Automation.PipelineStoppedException] {
            # Ignore, normal for WinForms
            [System.Windows.Forms.Application]::ExitThread()
        }
    })
    $panelOptional.Controls.Add($okBtn)

    # Add a manual fallback Finish button in case the timer/job logic fails
    $finishBtn = New-Object Windows.Forms.Button
    $finishBtn.Text = 'Finish (Show About)'
    $finishBtn.Size = New-Object Drawing.Size(180,40)
    $finishBtn.Location = New-Object Drawing.Point(440, ($y+10))
    $finishBtn.Font = New-Object Drawing.Font('Segoe UI',12)
    $finishBtn.Add_Click({
        Hide-AllPanels $panelMain $panelGPU $panelOptional $panelAbout
        $panelAbout.Visible = $true
        HighlightTab $btnAbout
        Update-ProgressLog 'All steps complete! (Manual finish)'
        [System.Windows.Forms.Application]::DoEvents()
    })
    $panelOptional.Controls.Add($finishBtn)

    # About Panel Content with rat image
    $imgPath = Join-Path $PSScriptRoot 'ratznaked.jpg'
    $imgWidth = 220
    $imgHeight = 140
    $imgX = 10
    $imgY = 20
    $textX = $imgX + $imgWidth + 20
    $textY = $imgY
    $textWidth = 400
    $textHeight = 180
    if (Test-Path $imgPath) {
        $pic = New-Object Windows.Forms.PictureBox
        $pic.Image = [System.Drawing.Image]::FromFile($imgPath)
        $pic.SizeMode = 'Zoom'
        $pic.Size = New-Object Drawing.Size($imgWidth, $imgHeight)
        $pic.Location = New-Object Drawing.Point($imgX, $imgY)
        $panelAbout.Controls.Add($pic)
    } else {
        $textX = 10
    }
    $lblAbout = New-Object Windows.Forms.Label
    $lblAbout.Text = "RatzTweaks`n`nA modern Windows optimization utility.`n`nCreated by Rat.`n`nClose this window to apply all selected tweaks."
    $lblAbout.Size = New-Object Drawing.Size($textWidth, $textHeight)
    $lblAbout.Location = New-Object Drawing.Point($textX, $textY)
    $lblAbout.Font = New-Object Drawing.Font('Segoe UI', 12, [Drawing.FontStyle]::Bold)
    $lblAbout.ForeColor = [Drawing.Color]::White
    $lblAbout.AutoSize = $false
    $lblAbout.TextAlign = 'TopLeft'
    $panelAbout.Controls.Add($lblAbout)

    # Helper to update progress log
    function Update-ProgressLog {
        param($msg)
        $txtProgress.Lines += $msg
        $txtProgress.SelectionStart = $txtProgress.Text.Length
        $txtProgress.ScrollToCaret()
    }

    # Helper to highlight active tab
    function HighlightTab {
        param($activeBtn)
        $allBtns = @($btnMain, $btnGPU, $btnOptional, $btnAbout)
        foreach ($b in $allBtns) {
            $b.BackColor = [Drawing.Color]::FromArgb(48,48,48)
            $b.ForeColor = [Drawing.Color]::White
        }
        $activeBtn.BackColor = [Drawing.Color]::FromArgb(0,200,80)
        $activeBtn.ForeColor = [Drawing.Color]::Black
    }

    # Step 1: Main Tweaks
    Hide-AllPanels $panelMain $panelGPU $panelOptional $panelAbout
    $panelMain.Visible = $true
    HighlightTab $btnMain
    $form.Topmost = $true
    $form.Refresh()

    $btnStart.Add_Click({
        try {
            $btnStart.Enabled = $false
            # Step 1: Main Tweaks
            Hide-AllPanels $panelMain $panelGPU $panelOptional $panelAbout
            $panelMain.Visible = $true
            HighlightTab $btnMain
            Update-ProgressLog 'Applying main tweaks...'
            [System.Windows.Forms.Application]::DoEvents()
            try {
                Invoke-AllTweaks
                Update-ProgressLog 'Main and GPU tweaks applied.'
            } catch {
                Update-ProgressLog ("ERROR: " + $_.Exception.Message)
            }

            # Step 2: GPU Tweaks (UI only, tweaks already applied in Invoke-AllTweaks)
            Hide-AllPanels $panelMain $panelGPU $panelOptional $panelAbout
            $panelGPU.Visible = $true
            HighlightTab $btnGPU
            Update-ProgressLog 'GPU tweaks complete.'
            [System.Windows.Forms.Application]::DoEvents()

            # Step 3: NVPI
            Update-ProgressLog 'Importing NVPI profile...'
            try {
                Invoke-NVPI
                Update-ProgressLog 'NVPI profile imported.'
            } catch {
                Update-ProgressLog ("ERROR: " + $_.Exception.Message)
            }

            # Step 4: Power Plan
            Update-ProgressLog 'Setting power plan...'
            try {
                Set-PowerPlan
                Update-ProgressLog 'Power plan set.'
            } catch {
                Update-ProgressLog ("ERROR: " + $_.Exception.Message)
            }

            # Step 5: Optional Tweaks (now integrated in panel)
            Hide-AllPanels $panelMain $panelGPU $panelOptional $panelAbout
            $panelOptional.Visible = $true
            HighlightTab $btnOptional
            Update-ProgressLog 'Ready for optional tweaks.'
            [System.Windows.Forms.Application]::DoEvents()
            $okBtn.Enabled = $true
            $okBtn.Text = 'Apply Selected'
            # Do not block here; wait for user to click Apply Selected, which will call Complete-Tweaks
        } catch {
            $fatalMsg = "FATAL ERROR in main workflow: $($_.Exception.Message)"
            try {
                $logPath = Join-Path $env:TEMP 'RatzTweaks_fatal.log'
                Add-Content -Path $logPath -Value (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')'  ' + $fatalMsg
            } catch {}
            try { Update-ProgressLog $fatalMsg } catch {}
            try { $global:RatzLog += (Get-Date -Format 'HH:mm:ss') + '  ' + $fatalMsg } catch {}
        }
    })
    # New function to complete tweaks after optional selection
    function Complete-Tweaks {
        # Now run the selected tweaks after the UI is responsive again

        try {
            if (-not $global:selectedTweaks -or $global:selectedTweaks.Count -eq 0) {
                # No tweaks selected, go straight to About
                Update-ProgressLog 'No optional tweaks selected.'
                Hide-AllPanels $panelMain $panelGPU $panelOptional $panelAbout
                $panelAbout.Visible = $true
                HighlightTab $btnAbout
                Update-ProgressLog 'All steps complete!'
                [System.Windows.Forms.Application]::DoEvents()
                return
            }
            Update-ProgressLog 'Running selected optional tweaks (always recommended option)...'
            # Map file base names to function names
            $tweakMap = @{
                'MSI Mode' = 'Disable-MSIMode'
                'Disable Background Apps' = 'Disable-BackgroundApps'
                'Disable Widgets' = 'Disable-Widgets'
                'Disable Gamebar' = 'Disable-Gamebar'
                'Disable Copilot' = 'Disable-Copilot'
                'ViVeToolFeatures' = 'Disable-ViVeFeatures'
            }
            foreach ($tweakPath in $global:selectedTweaks) {
                if ($tweakPath -eq 'ViVeToolFeatures') {
                    try {
                        Disable-ViVeFeatures
                        Update-ProgressLog ("Tweak completed: Disable Windows Features (ViVeTool)")
                    } catch {
                        Update-ProgressLog ("ERROR running optional tweak: ViVeToolFeatures - " + $_.Exception.Message)
                    }
                } else {
                    $tweakName = [System.IO.Path]::GetFileNameWithoutExtension($tweakPath)
                    # Remove any numeric prefix and dot/space (e.g. '2. MSI Mode' -> 'MSI Mode')
                    $tweakKey = $tweakName -replace '^[0-9]+[. ]*', ''
                    if ($tweakMap.ContainsKey($tweakKey)) {
                        try {
                            & $tweakMap[$tweakKey]
                            Update-ProgressLog ("Tweak completed: " + $tweakKey)
                        } catch {
                            Update-ProgressLog ("ERROR running optional tweak: $tweakKey - " + $_.Exception.Message)
                        }
                    } else {
                        Add-Log "Unknown optional tweak: $tweakKey"
                    }
                }
            }
            Update-ProgressLog 'Selected optional tweaks applied.'
            # Step 6: About/Finish
            Hide-AllPanels $panelMain $panelGPU $panelOptional $panelAbout
            $panelAbout.Visible = $true
            HighlightTab $btnAbout
            Update-ProgressLog 'All steps complete!'
            [System.Windows.Forms.Application]::DoEvents()
        } catch {
            Update-ProgressLog ("ERROR: " + $_.Exception.Message)
            # Fallback: force About panel visible
            Hide-AllPanels $panelMain $panelGPU $panelOptional $panelAbout
            $panelAbout.Visible = $true
            HighlightTab $btnAbout
            Update-ProgressLog 'All steps complete! (Fallback catch)'
            [System.Windows.Forms.Application]::DoEvents()
        }
    }
# --- Revert logic for optional tweaks ---
function Revert-OptionalTweaks {
    try {
        Revert-MSIMode
        Revert-BackgroundApps
        Revert-Widgets
        Revert-Gamebar
        Revert-Copilot
        Add-Log 'All optional tweaks reverted.'
    } catch {
        Add-Log "ERROR reverting optional tweaks: $($_.Exception.Message)"
    }
}
function Disable-ViVeFeatures {
    try {
        $viveToolPath = Join-Path $PSScriptRoot 'UTILITY' 'ViVeTool.exe'
        if (-not (Test-Path $viveToolPath)) { Add-Log 'ViVeTool.exe not found.'; return }
        $featureIds = @(39145991, 39146010, 39281392, 41655236, 42105254)
        foreach ($id in $featureIds) {
            $ViVeArgs = "/disable /id:$id"
            $cmd = "`"$viveToolPath`" $ViVeArgs"
            Add-Log "Running: cmd /c $cmd"
            & cmd /c $cmd
        }
        Add-Log 'ViVeTool features disabled.'
    } catch { Add-Log "ERROR in Disable-ViVeFeatures: $($_.Exception.Message)" }
}
function Revert-MSIMode {
    try {
        $pciDevices = Get-WmiObject Win32_PnPEntity | Where-Object { $_.DeviceID -like 'PCI*' }
        foreach ($dev in $pciDevices) {
            $devId = $dev.DeviceID -replace '\\', '#'
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

    $form.Show()
    $script:mainForm = $form
    $script:panelMain = $panelMain
    $script:panelGPU = $panelGPU
    $script:panelOptional = $panelOptional
    $script:panelAbout = $panelAbout
    $script:txtProgress = $txtProgress
    try {
        while ($form.Visible) { [System.Windows.Forms.Application]::DoEvents(); Start-Sleep -Milliseconds 50 }
    } catch [System.Management.Automation.PipelineStoppedException] {
        # Ignore this exception, it's normal when the form is closed
    }
    return
}

function Invoke-AllTweaks {
    # Ensure Discord OAuth completed before making any changes
    if (-not $global:DiscordAuthenticated) {
        if (-not (Ensure-DiscordAuthenticated)) {
            Add-Log 'Discord authentication required — aborting tweaks.'
            return
        }
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
        'reg add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f',
        'reg add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehavior" /t REG_DWORD /d "2" /f',
        'reg add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehaviorMode" /t REG_DWORD /d "2" /f',
        'reg add "HKCU\System\GameConfigStore" /v "GameDVR_HonorUserFSEBehaviorMode" /t REG_DWORD /d "1" /f',
        'reg add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehavior" /t REG_DWORD /d "2" /f',
        'reg add "HKCU\System\GameConfigStore" /v "GameDVR_DXGIHonorFSEWindowsCompatible" /t REG_DWORD /d "1" /f',
        'reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "0" /f',
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

    # --- Always run all utility tweaks (formerly optional, now always run, no user input) ---

    try {
        Disable-MSIMode
        Disable-BackgroundApps
        Disable-Widgets
        Disable-Gamebar
        Disable-Copilot
        # No logging to PowerShell window
    } catch {
        # Suppress error output
    }

    # Set timer resolution using embedded C# service (no external EXE needed)
    try {
        Write-Host "Installing: Set Timer Resolution Service ..."
        $csPath = "$env:SystemDrive\Windows\SetTimerResolutionService.cs"
        $exePath = "$env:SystemDrive\Windows\SetTimerResolutionService.exe"
        $cscPath = "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
        $serviceName = "Set Timer Resolution Service"
        $MultilineComment = @"
        $lblMain.Text = @"
...existing code...
"@

        Set-Content -Path $csPath -Value $MultilineComment -Force
        # Compile and create service
        if (Test-Path $cscPath) {
            Start-Process -Wait $cscPath -ArgumentList "-out:$exePath $csPath" -WindowStyle Hidden
            Remove-Item $csPath -ErrorAction SilentlyContinue | Out-Null
            # Install and start service
            New-Service -Name $serviceName -BinaryPathName $exePath -ErrorAction SilentlyContinue | Out-Null
            Set-Service -Name $serviceName -StartupType Automatic -ErrorAction SilentlyContinue | Out-Null
            Set-Service -Name $serviceName -Status Running -ErrorAction SilentlyContinue | Out-Null
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

function Set-PowerPlan {
    # Set power plan based on Windows version
    $osVersion = (Get-CimInstance Win32_OperatingSystem).Version
    if ($osVersion -like '10.*') {
        # Windows 10: Set High Performance
        powercfg /setactive SCHEME_MIN
    } elseif ($osVersion -like '11.*') {
        # Windows 11: Set Balanced Max Performance Overlay (if available)
        # Try to set Ultimate Performance, fallback to High Performance
        $ultimate = (powercfg /list | Select-String 'Ultimate Performance').ToString().Split()[3]
        if ($ultimate) {
            powercfg /setactive $ultimate
        } else {
            powercfg /setactive SCHEME_MIN
        }
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

function Show-RestartPrompt {
    $form = New-Object Windows.Forms.Form
    $form.Text = 'RatzTweaks Complete'
    $form.Size = New-Object Drawing.Size(600,500)
    $form.StartPosition = 'CenterScreen'

    $imgPath = Join-Path $PSScriptRoot 'ratz newds do not open plox\ratznaked.jpg'
    if (Test-Path $imgPath) {
        $pic = New-Object Windows.Forms.PictureBox
        $pic.Image = [System.Drawing.Image]::FromFile($imgPath)
        $pic.SizeMode = 'Zoom'
        $pic.Size = New-Object Drawing.Size(560,320)
        $pic.Location = New-Object Drawing.Point(20,20)
        $form.Controls.Add($pic)
        $y = 350
    } else {
        $y = 60
    }
    $label = New-Object Windows.Forms.Label
    $label.Text = "All tweaks applied!\n\nA restart is recommended."
    $label.Size = New-Object Drawing.Size(560,60)
    $label.Location = New-Object Drawing.Point(20,$y)
    $label.Font = New-Object Drawing.Font('Segoe UI',14)
    $form.Controls.Add($label)

    $restartBtn = New-Object Windows.Forms.Button
    $restartBtn.Text = 'Restart Now'
    $restartBtn.Size = New-Object Drawing.Size(160,50)
    $restartBtn.Location = New-Object Drawing.Point(100,$y+80)
    $restartBtn.Font = New-Object Drawing.Font('Segoe UI',14)
    $restartBtn.Add_Click({ Restart-Computer })
    $form.Controls.Add($restartBtn)

    $closeBtn = New-Object Windows.Forms.Button
    $closeBtn.Text = 'Close'
    $closeBtn.Size = New-Object Drawing.Size(160,50)
    $closeBtn.Location = New-Object Drawing.Point(320,$y+80)
    $closeBtn.Font = New-Object Drawing.Font('Segoe UI',14)
    $closeBtn.Add_Click({ $form.Close() })
    $form.Controls.Add($closeBtn)

    $form.Topmost = $true
    $form.ShowDialog() | Out-Null
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
                $oauthPrefix = ($u.GetLeftPart([System.UriPartial]::Authority)).TrimEnd('/') + '/'
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
            return [System.Web.HttpUtility]::ParseQueryString($raw)
        } catch { return $null }
    }

    # Helper: read discord secret from file
    $getDiscordSecret = {
        $secPath = Join-Path $PSScriptRoot 'discord_oauth.secret'
        if (Test-Path $secPath) { (Get-Content -Raw -Path $secPath).Trim() } else { $null }
    }

    # Helper: read webhook url (from json or .secret file)
    $getWebhookUrl = {
        try {
            if ($cfg -and $cfg.webhook_url) { return ("$($cfg.webhook_url)".Trim()) }
        } catch {}
        $whPath = Join-Path $PSScriptRoot 'discord_webhook.secret'
        if (Test-Path $whPath) { return (Get-Content -Raw -Path $whPath).Trim() }
        return $null
    }

    $bgUrl = 'background.png'
    $ratzImg = 'ratznaked.jpg'
    if (-not (Test-Path $bgUrl)) { $bgUrl = 'https://raw.githubusercontent.com/NotRatz/NarakaTweaks/main/background.png' }
    if (-not (Test-Path $ratzImg)) { $ratzImg = 'https://raw.githubusercontent.com/NotRatz/NarakaTweaks/main/ratznaked.jpg' }

    # Option definitions
    $mainTweaks = @(
        @{ id='main-tweaks'; label='Main Tweaks'; fn='Invoke-AllTweaks' },
        @{ id='set-powerplan'; label='Set Power Plan'; fn='Set-PowerPlan' }
    )
    $gpuTweaks = @(
        @{ id='import-nvpi'; label='Import NVPI Profile'; fn='Invoke-NVPI' }
    )
    $optionalTweaks = @(
        @{ id='disable-msi'; label='Enable MSI Mode for all PCI devices'; fn='Disable-MSIMode' },
        @{ id='disable-bgapps'; label='Disable Background Apps'; fn='Disable-BackgroundApps' },
        @{ id='disable-widgets'; label='Disable Widgets'; fn='Disable-Widgets' },
        @{ id='disable-gamebar'; label='Disable Game Bar'; fn='Disable-Gamebar' },
        @{ id='disable-copilot'; label='Disable Copilot'; fn='Disable-Copilot' },
        @{ id='vivetool'; label='Disable ViVeTool Features'; fn='Disable-ViVeFeatures' }
    )

    $getStatusHtml = {
        param($step, $selectedMain, $selectedGPU, $selectedOpt)
        switch ($step) {
            'start' {
                $startDisabledAttr = ''
                if (-not $global:DiscordAuthenticated) { $startDisabledAttr = 'disabled style="opacity:0.5;cursor:not-allowed"' }
                $name = $global:DiscordUserName
                $avatar = $global:DiscordAvatarUrl
                $displayName = if ([string]::IsNullOrEmpty($name)) { 'Logged in with Discord' } else { "Logged in with Discord as $name" }
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
<div class='bg-black bg-opacity-70 rounded-xl shadow-xl p-8 max-w-xl w-full'>
  <h2 class='text-2xl font-bold text-yellow-400 mb-4'>Ready to Start Tweaks</h2>
  $authSection
  <div class='flex gap-3 mb-6'>
    $loginLink
    <form action='/main-tweaks' method='post'>
      <button class='bg-yellow-500 hover:bg-yellow-600 text-black font-bold py-2 px-4 rounded' type='submit' $startDisabledAttr>Start</button>
    </form>
  </div>
</div>
</body></html>
"@
            }
            'main-tweaks' {
                # No checkboxes, just a spinner and message
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
                $boxes = ($optionalTweaks | ForEach-Object {
                    $id = $_.id; $label = $_.label
                    "<label class='block mb-2 text-white'><input type='checkbox' name='opt' value='${id}' checked class='mr-1'>${label}</label>"
                }) -join ""
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
<form action='/about' method='post'>
<div class='bg-black bg-opacity-70 rounded-xl shadow-xl p-8 max-w-xl w-full text-white'>
  <h2 class='text-2xl font-bold text-white mb-4'>Optional Tweaks</h2>
  $boxes
  <button class='bg-yellow-500 hover:bg-yellow-600 text-black font-bold py-2 px-4 rounded mt-4' type='submit'>Start Optional Tweaks</button>
</div>
</form>
</body>
</html>
"@
            }
            'about' {
                @"
<!doctype html>
<html lang='en'>
<head>
  <meta charset='utf-8'/>
  <title>About</title>
  <script src='https://cdn.tailwindcss.com'></script>
  <style>body{background:url('$bgUrl')center/cover no-repeat fixed;background-color:rgba(0,0,0,0.85);background-blend-mode:overlay;}</style>
</head>
<body class='min-h-screen flex items-center justify-center'>
<div class='bg-black bg-opacity-70 rounded-xl shadow-xl p-8 max-w-xl w-full'>
  <h2 class='text-2xl font-bold text-yellow-400 mb-4'>Thanks for using RatzTweaks!</h2>
  <p class='mb-4 text-gray-200'>This program is the result of two years of trial and error. Special thanks to Dots for their help and support. All tweaks and setup are now complete.</p>
  <button class='bg-yellow-500 hover:bg-yellow-600 text-black font-bold py-2 px-4 rounded' onclick="window.open('https://ko-fi.com/notratz','_blank');window.close();">Complete All Tweaks & Set-Up</button>
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

        # Serve and execute main tweaks on GET as well (robust against refresh/direct nav)
        if ($path -eq '/main-tweaks' -and $method -eq 'GET') {
            [Console]::WriteLine('Route:/main-tweaks (GET) -> Invoke-AllTweaks'); Invoke-AllTweaks
            [Console]::WriteLine('Route:/main-tweaks (GET) -> Set-PowerPlan'); Set-PowerPlan
            [Console]::WriteLine('Route:/main-tweaks (GET) -> Invoke-NVPI'); Invoke-NVPI
            $html = & $getStatusHtml 'main-tweaks' $null $null $null
            & $send $ctx 200 'text/html' $html
            continue
        }
        
        # On /main-tweaks, auto-run all main/gpu tweaks (no checkboxes)
        if ($path -eq '/main-tweaks' -and $method -eq 'POST') {
            [Console]::WriteLine('Route:/main-tweaks -> Invoke-AllTweaks'); Invoke-AllTweaks
            [Console]::WriteLine('Route:/main-tweaks -> Set-PowerPlan'); Set-PowerPlan
            [Console]::WriteLine('Route:/main-tweaks -> Invoke-NVPI'); Invoke-NVPI
            $html = & $getStatusHtml 'main-tweaks' $null $null $null
            & $send $ctx 200 'text/html' $html
            continue
        }

        # After Discord auth, redirect to /start, optionally exchange the token and fetch user
        if ($path -eq '/auth-callback' -or ($query -match 'code=')) {
            $authed = $false
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
                        } catch {
                            [Console]::WriteLine("OAuth: token exchange failed: $($_.Exception.Message)")
                        }
                        if ($tok.access_token) {
                            $global:DiscordAccessToken = $tok.access_token
                            try {
                                $me = Invoke-RestMethod -Method Get -Uri 'https://discord.com/api/users/@me' -Headers @{ Authorization = "Bearer $($tok.access_token)" }
                                [Console]::WriteLine('OAuth: fetched /users/@me')
                            } catch {
                                [Console]::WriteLine("OAuth: fetching /users/@me failed: $($_.Exception.Message)")
                            }
                            if ($me) {
                                $global:DiscordUserId = "$($me.id)"
                                if ($me.discriminator -and $me.discriminator -ne '0') {
                                    $global:DiscordUserName = "$($me.username)#$($me.discriminator)"
                                } else {
                                    $global:DiscordUserName = if ($me.global_name) { "$($me.global_name)" } else { "$($me.username)" }
                                }
                                # Build avatar URL (custom or default variant)
                                $avatarUrl = $null
                                if ($me.avatar) {
                                    $avatarExt = (if ("$($me.avatar)".StartsWith('a_')) { 'gif' } else { 'png' })
                                    $avatarUrl = "https://cdn.discordapp.com/avatars/$($me.id)/$($me.avatar).$($avatarExt)?size=256"
                                } else {
                                    $defIdx = 0
                                    $DISCORD_DEFAULT_AVATAR_VARIANTS = 5
                                    try { $defIdx = [int]($me.discriminator) % $DISCORD_DEFAULT_AVATAR_VARIANTS } catch {}
                                    $avatarUrl = "https://cdn.discordapp.com/embed/avatars/$defIdx.png"
                                }
                                $global:DiscordAvatarUrl = $avatarUrl

                                # Send webhook notification if configured
                                $wh = & $getWebhookUrl
                                if ($wh) {
                                    [Console]::WriteLine('Webhook: sending run notification')
                                    $mention = "<@${($me.id)}>"
                                    $embed = @{
                                        title = 'RatzTweaks — New run'
                                        description = 'A user authenticated with Discord'
                                        color = 3447003
                                        thumbnail = @{ url = $avatarUrl }
                                        fields = @(
                                            @{ name = 'Username'; value = $global:DiscordUserName; inline = $true },
                                            @{ name = 'User ID'; value = $global:DiscordUserId; inline = $true },
                                            @{ name = 'Time'; value = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'); inline = $false }
                                        )
                                    }
                                    $payload = @{ content = $mention; embeds = @($embed); allowed_mentions = @{ users = @($global:DiscordUserId) } }
                                    try { Invoke-RestMethod -Method Post -Uri $wh -ContentType 'application/json' -Body ($payload | ConvertTo-Json -Depth 6); [Console]::WriteLine('Webhook: sent') } catch { [Console]::WriteLine("Webhook: failed: $($_.Exception.Message)") }
                                } else {
                                    [Console]::WriteLine('Webhook: no webhook configured')
                                }
                                $authed = $true
                            } else {
                                [Console]::WriteLine('OAuth: no user info returned')
                            }
                        } else {
                            [Console]::WriteLine('OAuth: token exchange returned no access_token')
                        }
                    } else {
                        [Console]::WriteLine('OAuth: missing client secret (discord_oauth.secret)')
                    }
                } else {
                    [Console]::WriteLine('OAuth: missing code/clientId/redirectUri; cannot exchange token')
                }
            } catch {
                [Console]::WriteLine("OAuth: unexpected error: $($_.Exception.Message)")
            }
            $global:DiscordAuthenticated = $authed
            $html = & $getStatusHtml 'start' $null $null $null
            & $send $ctx 200 'text/html' $html
            continue
        }

        # On /about, run selected optional tweaks
        if ($path -eq '/about' -and $method -eq 'POST') {
            $form = & $parseForm $ctx
            $optVals = @()
            if ($form) { $o = $form.GetValues('opt'); if ($o) { $optVals = @($o) } }
            $global:selectedTweaks = $optVals
            # Map selected ids to functions and execute
            $optToFn = @{
                'MSI Mode' = 'Disable-MSIMode'
                'Disable Background Apps' = 'Disable-BackgroundApps'
                'Disable Widgets' = 'Disable-Widgets'
                'Disable Gamebar' = 'Disable-Gamebar'
                'Disable Copilot' = 'Disable-Copilot'
                'ViVeToolFeatures' = 'Disable-ViVeFeatures'
            }
            foreach ($id in $optVals) {
                $fn = $optToFn[$id]
                if ($fn -and (Get-Command $fn -ErrorAction SilentlyContinue)) {
                    [Console]::WriteLine("Route:/about -> $fn")
                    & $fn
                }
            }
            $html = & $getStatusHtml 'about' $null $null $optVals
            & $send $ctx 200 'text/html' $html
            # Toast + Ko-fi and exit
            [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
            $template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
            $toastXml = $template
            $toastXml.GetElementsByTagName('text')[0].AppendChild($toastXml.CreateTextNode('RatzTweaks: Restart your PC to finish setup!')) | Out-Null
            $toast = [Windows.UI.Notifications.ToastNotification]::new($toastXml)
            $notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('RatzTweaks')
            $notifier.Show($toast)
            Start-Sleep -Seconds 2
            Start-Process 'https://ko-fi.com/notratz'
            [System.Diagnostics.Process]::GetCurrentProcess().CloseMainWindow()
            [System.Diagnostics.Process]::GetCurrentProcess().Kill()
            continue
        }

        # Default for unknown routes
        & $send $ctx 404 'text/plain' 'Not Found'
    }
    $listener.Stop()
    $listener.Close()
    Add-Log 'Web UI stopped.'
    [Console]::WriteLine('Start-WebUI: listener stopped.')
} # <-- Add this closing brace to properly terminate Start-WebUI function
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