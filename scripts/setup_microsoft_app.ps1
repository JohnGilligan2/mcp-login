#Requires -Version 7.0
<#
.SYNOPSIS
  Create the Microsoft app that mcp-login uses for "Continue with Microsoft".

.DESCRIPTION
  ONE multi-tenant app registration in your tenant:
    - sign-in audience: any organization's Microsoft account AND personal
      Microsoft accounts (AzureADandPersonalMicrosoftAccount), so customers use
      THEIR OWN account; nothing is created in your directory for them
    - redirect URI <your issuer>/callback/microsoft
    - delegated Microsoft Graph openid, email, profile
    - optional ID-token claims `email` and `xms_edov`. mcp-login accepts a work
      account's email ONLY when xms_edov (email domain owner verified) is true,
      which closes the "nOAuth" impersonation hole
    - requestedAccessTokenVersion = 2 (required for personal accounts)
    - a client secret, written to a FILE and never printed, so it cannot end up
      in a chat transcript or a screenshot

  NOT an MCP server app, so none of the two-app / access_as_user rules apply:
  this app only proves identity to mcp-login. Who may use which server is
  mcp-login's clients.json.

  Customer consent: many organizations only allow users to consent to apps
  from a Microsoft-VERIFIED PUBLISHER. Without publisher verification (needs a
  Microsoft Partner / MPN id, set in the Entra portal, not by this script),
  some customer staff will see "Need admin approval". Google has no equivalent
  block for basic scopes.

  DRY RUN BY DEFAULT. IDEMPOTENT: re-running reuses the app and re-asserts its
  settings; a new secret is only minted when none exists or -NewSecret is given.

.EXAMPLE
  pwsh ./scripts/setup_microsoft_app.ps1 -TenantId contoso.onmicrosoft.com -RedirectUri https://login.example.com/callback/microsoft -UseDeviceCode
  (same again with -Apply)
#>
[CmdletBinding()]
param(
    [switch] $Apply,
    [switch] $NewSecret,
    [switch] $UseDeviceCode,
    [Parameter(Mandatory)] [string] $TenantId,
    [Parameter(Mandatory)] [string] $RedirectUri,
    [string] $AppName     = 'MCP Sign-in',
    [string] $SecretFile  = (Join-Path $HOME '.mcp-login/microsoft-client-secret.txt'),
    [string] $IdFile      = (Join-Path $HOME '.mcp-login/microsoft-app.txt')
)
$ErrorActionPreference = 'Stop'
$GraphAppId = '00000003-0000-0000-c000-000000000000'
function Say($m, $c = 'Gray') { Write-Host $m -ForegroundColor $c }

$connectArgs = @{ Scopes = @('Application.ReadWrite.All'); TenantId = $TenantId }
if ($UseDeviceCode) { $connectArgs['UseDeviceCode'] = $true }
# NOT piped to Out-Null: that swallows the device-code prompt.
Connect-MgGraph @connectArgs -NoWelcome
$ctx = Get-MgContext
Say "Connected to tenant $($ctx.TenantId) as $($ctx.Account)" Cyan

$existing = @(Get-MgApplication -Filter "displayName eq '$AppName'" -ErrorAction SilentlyContinue)
if ($existing.Count -gt 1) { throw "More than one app named '$AppName'. Resolve by hand." }
$app = $existing | Select-Object -First 1

$graphSp = Get-MgServicePrincipal -Filter "appId eq '$GraphAppId'"
$want = @{}
foreach ($v in 'openid', 'email', 'profile') {
    $s = $graphSp.Oauth2PermissionScopes | Where-Object Value -eq $v
    if (-not $s) { throw "Could not resolve Microsoft Graph scope '$v'" }
    $want[$v] = [string]$s.Id
}

Say "`nPLAN" Magenta
Say ("  app          : {0}" -f $(if ($app) { "reuse '$AppName' (appId $($app.AppId))" } else { "create '$AppName'" }))
Say  "  audience     : AzureADandPersonalMicrosoftAccount (any org + personal accounts)"
Say  "  redirect URI : $RedirectUri"
Say  "  Graph        : openid, email, profile (delegated)"
Say  "  ID token     : optional claims email + xms_edov; token version 2"
$hasSecret = [bool]$app -and (($app.PasswordCredentials | Measure-Object).Count -gt 0)
Say ("  secret       : {0}" -f $(if ($hasSecret -and -not $NewSecret) { 'keep existing (pass -NewSecret to mint another)' } else { "mint one, write to $SecretFile (never printed)" }))
if (-not $Apply) { Say "`nDRY RUN. Nothing changed. Re-run with -Apply." Yellow; return }

if (-not $app) {
    $app = New-MgApplication -DisplayName $AppName -SignInAudience 'AzureADandPersonalMicrosoftAccount' `
        -Api @{ RequestedAccessTokenVersion = 2 } -Web @{ RedirectUris = @($RedirectUri) }
    Say "Created app $($app.AppId)" Green
}

# Raw PATCH for the nested collections (the Graph SDK serializes them badly).
$body = @{
    signInAudience         = 'AzureADandPersonalMicrosoftAccount'
    api                    = @{ requestedAccessTokenVersion = 2 }
    web                    = @{ redirectUris = @($RedirectUri) }
    optionalClaims         = @{ idToken = @(
        [ordered]@{ name = 'email';    essential = $false; additionalProperties = @() }
        [ordered]@{ name = 'xms_edov'; essential = $false; additionalProperties = @() }
    ) }
    requiredResourceAccess = @(@{
        resourceAppId  = $GraphAppId
        resourceAccess = @($want.Values | ForEach-Object { [ordered]@{ id = $_; type = 'Scope' } })
    })
} | ConvertTo-Json -Depth 10
Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/v1.0/applications/$($app.Id)" `
    -Body $body -ContentType 'application/json' | Out-Null
Say "Settings applied" Green

if (-not (Get-MgServicePrincipal -Filter "appId eq '$($app.AppId)'" -ErrorAction SilentlyContinue)) {
    New-MgServicePrincipal -AppId $app.AppId | Out-Null
    Say "Service principal created" Green
}

if (-not $hasSecret -or $NewSecret) {
    $dir = Split-Path $SecretFile -Parent
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $pw = Add-MgApplicationPassword -ApplicationId $app.Id -PasswordCredential @{
        DisplayName = 'mcp-login'; EndDateTime = (Get-Date).AddMonths(24) }
    Set-Content -Path $SecretFile -Value $pw.SecretText -NoNewline -Encoding utf8
    Say "Secret written to $SecretFile (not shown)" Green
}

# --- verify, read back from Entra ---------------------------------------------
$a = Get-MgApplication -ApplicationId $app.Id
$bad = @()
function Check($label, $ok) { if ($ok) { Say "  OK    $label" Green } else { Say "  WRONG $label" Red; $script:bad += $label } }
Say "`nVERIFY" Cyan
Check 'audience = any org + personal accounts' ($a.SignInAudience -eq 'AzureADandPersonalMicrosoftAccount')
Check 'token version 2' ($a.Api.RequestedAccessTokenVersion -eq 2)
Check "redirect URI $RedirectUri" ($a.Web.RedirectUris -contains $RedirectUri)
$claims = @($a.OptionalClaims.IdToken | ForEach-Object Name)
Check 'optional claim email' ($claims -contains 'email')
Check 'optional claim xms_edov' ($claims -contains 'xms_edov')
$granted = @($a.RequiredResourceAccess | Where-Object ResourceAppId -eq $GraphAppId | ForEach-Object { $_.ResourceAccess.Id })
Check 'Graph openid/email/profile declared' (@($want.Values | Where-Object { $granted -notcontains $_ }).Count -eq 0)
Check 'has a secret' ((Get-MgApplication -ApplicationId $app.Id).PasswordCredentials.Count -ge 1)

$idText = "MICROSOFT_CLIENT_ID=$($a.AppId)`nAPP_OBJECT_ID=$($a.Id)`nAPP_NAME=$AppName`nSECRET_FILE=$SecretFile`n"
$dir = Split-Path $IdFile -Parent
if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
Set-Content -Path $IdFile -Value $idText -Encoding utf8

Say "`n$(if ($bad) { "$($bad.Count) CHECK(S) FAILED" } else { 'All checks passed.' })" $(if ($bad) { 'Red' } else { 'Green' })
Say "MICROSOFT_CLIENT_ID = $($a.AppId)   (safe to share; also in $IdFile)" Cyan
Say "The secret is in $SecretFile. Do not paste it anywhere; load it from the file." Cyan
Say "Consider Microsoft publisher verification (Entra portal > App registrations > $AppName > Branding) to avoid 'Need admin approval' in customer tenants." Yellow
