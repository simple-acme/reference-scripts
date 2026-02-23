<#
.SYNOPSIS
CZECHIA.COM DNS-01 validation script for simple-acme / win-acme.

.DESCRIPTION
Creates and deletes DNS TXT records using the CZECHIA.COM DNS REST API.

Compatible with:
  --validationmode dns-01
  --validation script

API documentation:
https://api.czechia.com/swagger/index.html

.NOTES
- publishZone is hardcoded to 1 (required for authoritative NS publishing)
- API header required: AuthorizationToken
- Falls back to environment variable CZ_AUTHORIZATIONTOKEN
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("create","delete")]
    [string]$Action,

    [Parameter(Mandatory=$true)]
    [string]$ZoneName,

    [Parameter(Mandatory=$true)]
    [Alias("NodeName")]
    [string]$RecordName,

    [Parameter(Mandatory=$true)]
    [Alias("TxtValue")]
    [string]$Token,

    [Parameter(Mandatory=$false)]
    [string]$AuthorizationToken,

    [Parameter(Mandatory=$false)]
    [string]$ApiBaseUrl = "https://api.czechia.com",

    [Parameter(Mandatory=$false)]
    [int]$Ttl = 3600
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# -------- Authorization handling --------

if ([string]::IsNullOrWhiteSpace($AuthorizationToken)) {
    $AuthorizationToken = $env:CZ_AUTHORIZATIONTOKEN
}

if ([string]::IsNullOrWhiteSpace($AuthorizationToken)) {
    Write-Error "AuthorizationToken not provided and CZ_AUTHORIZATIONTOKEN not set."
    exit 1
}

# -------- Normalization --------

$ApiBaseUrl = $ApiBaseUrl.TrimEnd("/")
$ZoneName = $ZoneName.Trim().TrimEnd(".").ToLowerInvariant()
$RecordName = $RecordName.Trim().TrimEnd(".")
$Token = $Token.Trim()

# Convert FQDN to relative hostName if needed
$hostName = $RecordName
if ($hostName.ToLowerInvariant().EndsWith("." + $ZoneName)) {
    $hostName = $hostName.Substring(0, $hostName.Length - ($ZoneName.Length + 1))
}
$hostName = $hostName.TrimEnd(".")

if ([string]::IsNullOrWhiteSpace($hostName)) {
    Write-Error "Derived hostName is empty. RecordName='$RecordName' ZoneName='$ZoneName'."
    exit 1
}

# -------- API call --------

$Url = "$ApiBaseUrl/api/DNS/$ZoneName/TXT"

$Body = @{
    hostName    = $hostName
    text        = $Token
    ttl         = [int]$Ttl
    publishZone = 1
} | ConvertTo-Json -Compress

$Headers = @{
    "AuthorizationToken" = $AuthorizationToken
    "Content-Type"       = "application/json"
}

$Method = if ($Action -eq "create") { "POST" } else { "DELETE" }

try {
    Invoke-RestMethod -Method $Method -Uri $Url -Headers $Headers -Body $Body -TimeoutSec 30 | Out-Null
}
catch {
    Write-Error "CZECHIA.COM DNS $Action failed: $($_.Exception.Message)"
    exit 1
}

exit 0
