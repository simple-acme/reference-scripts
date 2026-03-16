<#
.SYNOPSIS
    Dynv6 DNS-01 PowerShell script for simple-acme (wacs.exe)

.DESCRIPTION
    This script is used by simple-acme to create and delete TXT records
    for DNS-01 validation using Dynv6 API.

    simple-acme configuration:
        - Validation Method: Perform validation challenge with your own script
        - Challenge Type: DNS
        - Script Path: Full path to this PS1 file
        - Create Arguments: create {Identifier} {RecordName} {Token} {ZoneName}
        - Delete Arguments: delete {Identifier} {RecordName} {Token} {ZoneName}

.PARAMETER 1
    Action: create / delete

.PARAMETER 2
    Identifier: FQDN being validated (e.g., baz.dynv6.net)

.PARAMETER 3
    RecordName: Full TXT record name (_acme-challenge.baz.dynv6.net)

.PARAMETER 4
    Token: TXT record value

.PARAMETER 5
    ZoneName (optional): It will default to Dynv6 domain (e.g., dynv6.net)
#>

param(
    [Parameter(Mandatory=$true)][string]$Action,
    [Parameter(Mandatory=$true)][string]$Identifier,
    [Parameter(Mandatory=$true)][string]$RecordName,
    [Parameter(Mandatory=$true)][string]$Token,
    [Parameter(Mandatory=$false)][string]$ZoneName
)

# ---------------- CONFIGURATION ----------------
# See https://dynv6.com/keys
# See https://dynv6.com/docs/apis
# See https://dynv6.github.io/api-spec/
# Place here your token, zone id and zone FQDN
$Dynv6Token = "foo"
$Dynv6ZoneId = "bar"
$Dynv6Zone = "baz.dynv6.net"

# See https://dynv6.github.io/api-spec/#tag/records
$ApiBase = "https://dynv6.com/api/v2/zones/$Dynv6ZoneId/records"
$Headers = @{
    "Authorization" = "Bearer $Dynv6Token"
    "Content-Type"  = "application/json"
}

# Log file path (relative to script location)
$LogFile = Join-Path -Path $PSScriptRoot -ChildPath "dynv6_dns.log"

# Function to write log with timestamp
function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp - $Message"
    Add-Content -Path $LogFile -Value $logMessage
    Write-Host $Message
}

# If the full record ends with the zone, remove the zone part
if ($RecordName.EndsWith($Dynv6Zone)) {
    $RelativeName = $RecordName.Substring(0, $RecordName.Length - $Dynv6Zone.Length)
    $RelativeName = $RelativeName.TrimEnd(".")
} else {
    $RelativeName = $RecordName
}

function Create-TxtRecord {
    param($Name, $Value)
    $Body = @{
        name = $Name
        type = "TXT"
        data = $Value
        ttl  = 60
    } | ConvertTo-Json

    Write-Log "Creating TXT record: $Name -> $Value"
    try {
        Invoke-RestMethod -Uri $ApiBase -Method Post -Headers $Headers -Body $Body
        Write-Log "Successfully created TXT record: $Name -> $Value"
    } catch {
        Write-Log "Error creating TXT record: $_"
        throw
    }
    Start-Sleep -Seconds 15
}

function Delete-TxtRecord {
    param($Name, $Value)
    Write-Log "Deleting TXT record: $Name -> $Value"
    try {
        $records = Invoke-RestMethod -Uri $ApiBase -Method Get -Headers $Headers
        foreach ($rec in $records) {
            if ($rec.type -eq "TXT" -and $rec.name -eq $Name -and $rec.data -eq $Value) {
                $url = "$ApiBase/$($rec.id)"
                Invoke-RestMethod -Uri $url -Method Delete -Headers $Headers
                Write-Log "Successfully deleted TXT record: $Name -> $Value"
                return
            }
        }
        Write-Log "TXT record not found: $Name -> $Value"
    } catch {
        Write-Log "Error deleting TXT record: $_"
        throw
    }
}

# ---------------- MAIN -----------------
Write-Log "Script started with Action='$Action', Identifier='$Identifier', RecordName='$RecordName', Token='$Token', ZoneName='$ZoneName'"

switch ($Action.ToLower()) {
    "create" { Create-TxtRecord -Name $RelativeName -Value $Token }
    "delete" { Delete-TxtRecord -Name $RelativeName -Value $Token }
    default { Write-Log "Unknown action: $Action" }
}

Write-Log "Script finished."
