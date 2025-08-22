$gpuDevices = Get-PnpDevice -Class Display
foreach ($gpu in $gpuDevices) {
$instanceID = $gpu.InstanceId
# enable msi mode for all gpus regedit
reg add "HKLM\SYSTEM\ControlSet001\Enum\$instanceID\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f | Out-Null
}
# display msi mode for all gpus
foreach ($gpu in $gpuDevices) {
$instanceID = $gpu.InstanceId
$regPath = "Registry::HKLM\SYSTEM\ControlSet001\Enum\$instanceID\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties"
try {
$msiSupported = Get-ItemProperty -Path $regPath -Name "MSISupported" -ErrorAction Stop
Write-Output "$instanceID"
Write-Output "MSISupported: $($msiSupported.MSISupported)"
} catch {
Write-Output "$instanceID"
Write-Output "MSISupported: Not found or error accessing the registry."
}
}
Write-Host ""
Write-Host "Restart to apply . . ."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
exit