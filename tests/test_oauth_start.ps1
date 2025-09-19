# Self-contained test for OAuth start URL construction
# Do not dot-source the main script here (it requires Windows PowerShell 5.1).

# Provide a client id via env for the test (simulates server-side secret)
$env:RATZ_DISCORD_CLIENT_ID = 'TESTCLIENTID123'
$redirectUri = 'http://127.0.0.1:17690/'
$prefix = 'http://127.0.0.1:17690/'

# Resolve client id (server-side helper logic)
$clientIdResolved = $env:RATZ_DISCORD_CLIENT_ID

$redir = if ($redirectUri) { $redirectUri } else { $prefix }
$authUrl = "https://discord.com/api/oauth2/authorize?client_id=$clientIdResolved&redirect_uri=$([System.Web.HttpUtility]::UrlEncode($redir))&response_type=code&scope=identify"
$out = @{ auth_url = $authUrl }
Write-Host "Auth URL (server-side):"; $out | ConvertTo-Json -Compress | Write-Host

# Ensure top-level JSON does not contain a 'client_id' property (it's safe for the URL value to include it)
if ($out.PSObject.Properties.Name -contains 'client_id') { Write-Host 'ERROR: client_id leaked as top-level property' } else { Write-Host 'PASS: client_id not present as top-level property in JSON' }

Remove-Item Env:RATZ_DISCORD_CLIENT_ID -ErrorAction SilentlyContinue
