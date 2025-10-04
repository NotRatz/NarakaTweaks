# Test for enhanced Get-SteamAccounts function
# This test validates that the function correctly extracts Steam username and last played time

Write-Host "=== Steam Accounts Enhancement Test ===" -ForegroundColor Cyan
Write-Host ""

# Create a mock Steam directory structure
$tempDir = if ($env:TEMP) { $env:TEMP } else { "/tmp" }
$testSteamPath = Join-Path $tempDir "test_steam_$(Get-Random)"
$testUserData = Join-Path $testSteamPath "userdata"

# Clean up if exists
if (Test-Path $testSteamPath) {
    Remove-Item -Path $testSteamPath -Recurse -Force
}

Write-Host "Creating test Steam directory at: $testSteamPath" -ForegroundColor Gray

# Create test structure
New-Item -Path $testUserData -ItemType Directory -Force | Out-Null

# Test account 1: Complete data with PersonaName and LastPlayed in VDF
$steamId1 = "12345678"
$account1Path = Join-Path $testUserData $steamId1
$config1Path = Join-Path $account1Path "config"
$naraka1Path = Join-Path $account1Path "1665360"

New-Item -Path $config1Path -ItemType Directory -Force | Out-Null
New-Item -Path $naraka1Path -ItemType Directory -Force | Out-Null

$vdfContent1 = @"
"UserLocalConfigStore"
{
	"Software"
	{
		"Valve"
		{
			"Steam"
			{
				"Apps"
				{
					"1665360"
					{
						"LastPlayed"		"1696348931"
						"Playtime"		"123456"
					}
				}
				"friends"
				{
					"PersonaName"		"PlayerOne"
					"MostRecentPC"		"12345678901234567"
				}
			}
		}
	}
}
"@

Set-Content -Path (Join-Path $config1Path "localconfig.vdf") -Value $vdfContent1

# Test account 2: Has PersonaName but no LastPlayed in VDF, has Naraka folder (should use folder time)
$steamId2 = "87654321"
$account2Path = Join-Path $testUserData $steamId2
$config2Path = Join-Path $account2Path "config"
$naraka2Path = Join-Path $account2Path "1665360"

New-Item -Path $config2Path -ItemType Directory -Force | Out-Null
New-Item -Path $naraka2Path -ItemType Directory -Force | Out-Null

$vdfContent2 = @"
"UserLocalConfigStore"
{
	"Software"
	{
		"Valve"
		{
			"Steam"
			{
				"friends"
				{
					"PersonaName"		"PlayerTwo"
				}
			}
		}
	}
}
"@

Set-Content -Path (Join-Path $config2Path "localconfig.vdf") -Value $vdfContent2

# Test account 3: No VDF file at all (should show Unknown and Never)
$steamId3 = "11111111"
$account3Path = Join-Path $testUserData $steamId3
New-Item -Path $account3Path -ItemType Directory -Force | Out-Null

# Test account 4: Has VDF but no Naraka folder (should show Never)
$steamId4 = "99999999"
$account4Path = Join-Path $testUserData $steamId4
$config4Path = Join-Path $account4Path "config"

New-Item -Path $config4Path -ItemType Directory -Force | Out-Null

$vdfContent4 = @"
"UserLocalConfigStore"
{
	"Software"
	{
		"Valve"
		{
			"Steam"
			{
				"friends"
				{
					"PersonaName"		"PlayerThree"
				}
			}
		}
	}
}
"@

Set-Content -Path (Join-Path $config4Path "localconfig.vdf") -Value $vdfContent4

Write-Host "Test directory setup complete" -ForegroundColor Green
Write-Host ""

# Now test the function by inlining it for testing
function Get-SteamAccounts-Test {
    param([string[]]$SteamPaths)
    
    $steamAccounts = @()
    
    foreach ($basePath in $SteamPaths) {
        if (Test-Path $basePath) {
            try {
                $userFolders = Get-ChildItem -Path $basePath -Directory -ErrorAction SilentlyContinue
                foreach ($folder in $userFolders) {
                    # Folder name should be numeric (Steam ID)
                    if ($folder.Name -match '^\d+$') {
                        $steamId = $folder.Name
                        $profileUrl = "https://steamcommunity.com/profiles/[U:1:$steamId]"
                        
                        # Default values
                        $userName = 'Unknown'
                        $lastPlayed = 'Never'
                        
                        # Try to get username and last played from localconfig.vdf
                        $localConfigPath = Join-Path $basePath "$steamId\config\localconfig.vdf"
                        if (Test-Path $localConfigPath) {
                            try {
                                $vdfContent = Get-Content -Path $localConfigPath -Raw -ErrorAction SilentlyContinue
                                
                                # Extract PersonaName
                                if ($vdfContent -match "`"PersonaName`"\s+`"([^`"]+)`"") {
                                    $userName = $Matches[1]
                                }
                                
                                # Extract LastPlayed for Naraka Bladepoint (App ID 1665360)
                                if ($vdfContent -match "`"1665360`"[^}]*`"LastPlayed`"\s+`"(\d+)`"") {
                                    $unixTime = [long]$Matches[1]
                                    try {
                                        $dateTime = [DateTimeOffset]::FromUnixTimeSeconds($unixTime).LocalDateTime
                                        $lastPlayed = $dateTime.ToString('yyyy-MM-dd HH:mm:ss')
                                    } catch {}
                                }
                            } catch {}
                        }
                        
                        # Fallback: Use folder modification time if LastPlayed is still 'Never'
                        if ($lastPlayed -eq 'Never') {
                            $narakaFolderPath = Join-Path $basePath "$steamId\1665360"
                            if (Test-Path $narakaFolderPath) {
                                try {
                                    $folderItem = Get-Item $narakaFolderPath -ErrorAction SilentlyContinue
                                    if ($folderItem) {
                                        $lastPlayed = $folderItem.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
                                    }
                                } catch {}
                            }
                        }
                        
                        $steamAccounts += @{
                            SteamID = $steamId
                            UserName = $userName
                            LastPlayed = $lastPlayed
                            ProfileUrl = $profileUrl
                        }
                    }
                }
            } catch {
                Write-Host "Error scanning $basePath - $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }
    
    return $steamAccounts
}

Write-Host "Running Get-SteamAccounts test..." -ForegroundColor Cyan
$accounts = Get-SteamAccounts-Test -SteamPaths @($testUserData)

Write-Host ""
Write-Host "=== Test Results ===" -ForegroundColor Green
Write-Host "Found $($accounts.Count) account(s)"
Write-Host ""

$testsPassed = 0
$testsFailed = 0

# Test 1: Check account with full data
$acc1 = $accounts | Where-Object { $_.SteamID -eq $steamId1 }
Write-Host "Test 1: Account with PersonaName and LastPlayed in VDF" -ForegroundColor Yellow
if ($acc1 -and $acc1.UserName -eq "PlayerOne" -and $acc1.LastPlayed -eq "2023-10-03 16:02:11") {
    Write-Host "  ✓ PASS: Username='$($acc1.UserName)', LastPlayed='$($acc1.LastPlayed)'" -ForegroundColor Green
    $testsPassed++
} else {
    Write-Host "  ✗ FAIL: Expected UserName='PlayerOne' and LastPlayed='2023-10-03 16:02:11'" -ForegroundColor Red
    Write-Host "         Got UserName='$($acc1.UserName)' and LastPlayed='$($acc1.LastPlayed)'" -ForegroundColor Red
    $testsFailed++
}

# Test 2: Check account with PersonaName but using folder time for LastPlayed
$acc2 = $accounts | Where-Object { $_.SteamID -eq $steamId2 }
Write-Host "Test 2: Account with PersonaName, LastPlayed from folder time" -ForegroundColor Yellow
if ($acc2 -and $acc2.UserName -eq "PlayerTwo" -and $acc2.LastPlayed -ne "Never") {
    Write-Host "  ✓ PASS: Username='$($acc2.UserName)', LastPlayed='$($acc2.LastPlayed)' (from folder)" -ForegroundColor Green
    $testsPassed++
} else {
    Write-Host "  ✗ FAIL: Expected UserName='PlayerTwo' and LastPlayed from folder time" -ForegroundColor Red
    Write-Host "         Got UserName='$($acc2.UserName)' and LastPlayed='$($acc2.LastPlayed)'" -ForegroundColor Red
    $testsFailed++
}

# Test 3: Check account with no VDF
$acc3 = $accounts | Where-Object { $_.SteamID -eq $steamId3 }
Write-Host "Test 3: Account without VDF file" -ForegroundColor Yellow
if ($acc3 -and $acc3.UserName -eq "Unknown" -and $acc3.LastPlayed -eq "Never") {
    Write-Host "  ✓ PASS: Username='$($acc3.UserName)', LastPlayed='$($acc3.LastPlayed)'" -ForegroundColor Green
    $testsPassed++
} else {
    Write-Host "  ✗ FAIL: Expected UserName='Unknown' and LastPlayed='Never'" -ForegroundColor Red
    Write-Host "         Got UserName='$($acc3.UserName)' and LastPlayed='$($acc3.LastPlayed)'" -ForegroundColor Red
    $testsFailed++
}

# Test 4: Check account with VDF but no Naraka folder
$acc4 = $accounts | Where-Object { $_.SteamID -eq $steamId4 }
Write-Host "Test 4: Account with PersonaName but no Naraka folder" -ForegroundColor Yellow
if ($acc4 -and $acc4.UserName -eq "PlayerThree" -and $acc4.LastPlayed -eq "Never") {
    Write-Host "  ✓ PASS: Username='$($acc4.UserName)', LastPlayed='$($acc4.LastPlayed)'" -ForegroundColor Green
    $testsPassed++
} else {
    Write-Host "  ✗ FAIL: Expected UserName='PlayerThree' and LastPlayed='Never'" -ForegroundColor Red
    Write-Host "         Got UserName='$($acc4.UserName)' and LastPlayed='$($acc4.LastPlayed)'" -ForegroundColor Red
    $testsFailed++
}

Write-Host ""
Write-Host "=== Discord Webhook Format Test ===" -ForegroundColor Cyan
if ($accounts.Count -gt 0) {
    $steamLines = $accounts | ForEach-Object {
        "**$($_.UserName)** ([$($_.SteamID)]($($_.ProfileUrl)))`nLast Played: $($_.LastPlayed)"
    }
    $steamValue = $steamLines -join "`n`n"
    Write-Host "Expected Discord field format:" -ForegroundColor Gray
    Write-Host $steamValue
    Write-Host ""
}

# Cleanup
Write-Host "=== Cleaning up test directory ===" -ForegroundColor Gray
Remove-Item -Path $testSteamPath -Recurse -Force

# Summary
Write-Host ""
Write-Host "=== Test Summary ===" -ForegroundColor Cyan
Write-Host "Tests Passed: $testsPassed" -ForegroundColor Green
Write-Host "Tests Failed: $testsFailed" -ForegroundColor $(if ($testsFailed -gt 0) { "Red" } else { "Green" })

if ($testsFailed -eq 0) {
    Write-Host ""
    Write-Host "All tests passed! ✓" -ForegroundColor Green
    exit 0
} else {
    Write-Host ""
    Write-Host "Some tests failed! ✗" -ForegroundColor Red
    exit 1
}
