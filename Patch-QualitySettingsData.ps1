# Patch QualitySettingsData.txt to enable jiggle physics

$paths = @(
    'C:\Program Files (x86)\Steam\steamapps\common\NARAKA BLADEPOINT\NarakaBladepoint_Data\QualitySettingsData.txt',
    'D:\Program Files (x86)\Steam\steamapps\common\NARAKA BLADEPOINT\NarakaBladepoint_Data\QualitySettingsData.txt',
    'C:\Program Files (x86)\Epic Games\NARAKA BLADEPOINT\NarakaBladepoint_Data\QualitySettingsData.txt',
    'D:\Program Files (x86)\Epic Games\NARAKA BLADEPOINT\NarakaBladepoint_Data\QualitySettingsData.txt',
    'C:\Program Files\Steam\steamapps\common\NARAKA BLADEPOINT\NarakaBladepoint_Data\QualitySettingsData.txt',
    'D:\Program Files\Steam\steamapps\common\NARAKA BLADEPOINT\NarakaBladepoint_Data\QualitySettingsData.txt',
    'C:\Program Files\Epic Games\NARAKA BLADEPOINT\NarakaBladepoint_Data\QualitySettingsData.txt',
    'D:\Program Files\Epic Games\NARAKA BLADEPOINT\NarakaBladepoint_Data\QualitySettingsData.txt'
)
$found = $false
foreach ($qsPath in $paths) {
    if (Test-Path $qsPath) {
        $found = $true
        Write-Host "Found: $qsPath"
        $content = Get-Content -Raw -Path $qsPath
        if ($content -match '"characterAdditionalPhysics1"\s*:\s*false') {
            $patched = $content -replace '"characterAdditionalPhysics1"\s*:\s*false', '"characterAdditionalPhysics1": true'
            Set-Content -Path $qsPath -Value $patched
            Write-Host "Patched: characterAdditionalPhysics1 set to true."
        } elseif ($content -match '"characterAdditionalPhysics1"\s*:\s*true') {
            Write-Host "Already enabled: characterAdditionalPhysics1 is true."
        } else {
            Write-Host "ERROR: No jiggle flag found to toggle in $qsPath"
        }
        break
    }
}
if (-not $found) {
    Write-Host "ERROR: QualitySettingsData.txt not found in any known location."
    exit 1
}
