<#
.SYNOPSIS
    DNS TXT validation script for simple-acme/win-acme using Webnames.ca CORE REST API

.DESCRIPTION
    This script handles DNS TXT record creation and deletion for ACME/Let's Encrypt challenge validation via Webnames.ca,
    a (really good) domain registrar and DNS hosting company that I work for.
        
    See https://www.webnames.ca/_/swagger/index.html for Webnames API documentation.
    See https://simple-acme.com/reference/plugins/validation/dns/script for simple-acme script validation documentation.
        
    The script was tested with win-acme v2.2.9.1701 but should also be compatible with the recent simple-acme fork. 
        
    Author: Jordan Rieger - jordan@webnames.ca - June 2025

    Copyright 2025 Webnames.ca

    MIT License:

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation 
    files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, 
    modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the 
    Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE 
    WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR 
    COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, 
    ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

.PARAMETER Action
    Either "create" or "delete" depending on whether to add or remove the DNS TXT record.
        
.PARAMETER ZoneName
    The registerable domain (root hostname) of the hostname being validated. E.g. if the hostname being validated is sub.example.com,
    then the ZoneName would be example.com. Passed as {ZoneName} from simple-acme.
        
.PARAMETER RecordName
    Full TXT record hostname (e.g., _acme-challenge.sub.example.com). Passed as {RecordName} from simple-acme.
        
.PARAMETER Token
    Value of the TXT record, e.g. DGyRejmCefe7v4NfDGDKfA. Passed as {Token} from simple-acme.
        
.PARAMETER APIUsername
    Webnames.ca CORE API username, e.g. myaccount_APIUser_20250611134435_3f533f2b.
        
.PARAMETER APIKey
    Webnames.ca CORE API key, e.g. odsifj30$49j4ggg_340fqivm9j. It is recommended to store this in the simple-acme secret vault and 
    pass it as a replaced argument, e.g. {vault://json/WebnamesAPIKey}. It is also recommended to store the key surrounded with 
    double-quotes and escaped inline with backticks before any non-alphanumeric characters, to allow simple-acme to substitute it 
    without problems. E.g. the key odsifj30$49j4ggg_340fqivm9j should be stored in the secret vault as "odsifj30`$49j4ggg_340fqivm9j".
        
.PARAMETER APIBaseURLOverride
    Optional: override the API base URL. E.g. instead of https://www.webnames.ca/_/APICore, for the testing environment, 
    use https://staging.webnames.ca/_/APICore.

.EXAMPLE
    # Direct script execution:
    PS> & '.\Webnames.ps1' -Action create `
                           -ZoneName wntest202506191536jr.ca `
                           -RecordName _acme-challenge.wntest202506191536jr.ca `
                           -Token DGyRejmCefe7v4NfDGDKfA `
                           -APIUsername myaccount_APIUser_20250611134435_3f533f2b `
                           -APIKey "odsifj3049j4ggg_340fqivm9j" `

    # Execution via simple-acme or win-acme:
    & .\wacs.exe --accepttos `
                 --target manual `
                 --host sub.wntest202506191536jr.ca `
                 --validationmode dns-01 `
                 --validation script `
                 --dnsscript ".\Webnames.ps1" `
                 --dnscreatescriptarguments '-Action create -ZoneName {ZoneName} -RecordName {RecordName} -Token {Token} -APIUsername myaccount_APIUser_20250611134435_3f533f2b -APIKey {vault://json/WebnamesAPIKey} --dnsdeletescriptarguments  '-Action delete -ZoneName {ZoneName} -RecordName {RecordName} -Token {Token} -APIUsername myaccount_APIUser_20250611134435_3f533f2b -APIKey {vault://json/WebnamesAPIKey}'
#>

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("create", "delete")]
    [string]$Action,
    
    [Parameter(Mandatory=$true)]
    [string]$ZoneName,
    
    [Parameter(Mandatory=$true)]
    [string]$RecordName,
    
    [Parameter(Mandatory=$true)]
    [string]$Token,
    
    [Parameter(Mandatory=$true)]
    [string]$APIUsername,
    
    [Parameter(Mandatory=$true)]
    [string]$APIKey,
    
    [Parameter(Mandatory=$false)]
    [string]$APIBaseURLOverride
)

Set-StrictMode -Version Latest                       # Do not allow undeclared variables
$ErrorActionPreference = "Stop"                      # Stop this script if calls to sub-scripts fail.
$PSNativeCommandUseErrorActionPreference = $true     # Stop this script if native commands fail.

function Create-Or-Remove-DNS-TXT-Record {
    param(
        [bool]$bCreate,
        [string]$sZoneName,
        [string]$sRecordName,
        [string]$sToken
    )
    
    $sAction = If ($bCreate) { 'create' } else { 'delete' }
    Write-Log "Attempting to $sAction DNS TXT record $sRecordName with value: $sToken"

    $sAPIBaseURL = if ($APIBaseURLOverride) { $APIBaseURLOverride } else { "https://www.webnames.ca/_/APICore" }

    $oHeaders = @{
        "API-User" = $APIUsername
        "API-Key" = $APIKey
    }
    
    $sZoneName = [uri]::EscapeDataString($sZoneName)
    $sRecordName = [uri]::EscapeDataString($sRecordName)
    $sToken = [uri]::EscapeDataString($sToken)
            
    $sURLPath = If ($bCreate) { 'add' } else { 'delete' };
    $sHTTPMethod = If ($bCreate) { 'POST' } else { 'DELETE' };

    $sURL = "$sAPIBaseURL/domains/$sZoneName/$sURLPath-txt-record?hostName=$sRecordName&txt=$sToken"

    Write-Log "HTTPMethod: $sHTTPMethod; URL: $sURL"

    try {
        # ACTUAL API CALL HAPPENS HERE:
        $oResponse = Invoke-RestMethod -Uri $sURL -Method $sHTTPMethod -Headers $oHeaders
    }
    catch {
        
        $iStatusCode = $_.Exception.Response.StatusCode.value__

        if ($iStatusCode -ne 404) {
            $oResponseStream = $_.Exception.Response.GetResponseStream()
            $srResponse = New-Object System.IO.StreamReader($oResponseStream)
            $sErrorBody = $srResponse.ReadToEnd()
            $srResponse.Close()
            Write-Error $sErrorBody
        }

        throw
    }
}

function Write-Log {
    param([string]$sMessage, [string]$sLevel = "INFO")
    $sTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"

    if ($sLevel -eq "INFO") {
        Write-Host "[$sTimestamp] [$sLevel] $sMessage"
    } else {
        Write-Error "[$sTimestamp] [$sLevel] $sMessage"
    }
}

# Main execution
Write-Log "Starting DNS validation script"
Write-Log "Action: $Action"
Write-Log "DomainName: $ZoneName"
Write-Log "HostName: $RecordName"
Write-Log "Token: $Token"
Write-Log "APIUsername: $APIUsername"
Write-Log "APIBaseURLOverride: $APIBaseURLOverride"

$success = $false

switch ($Action.ToLower()) {

    "create" {
        Create-Or-Remove-DNS-TXT-Record -bCreate $true -sZoneName $ZoneName -sRecordName $RecordName -sToken $Token
    }
    
    "delete" {
        Create-Or-Remove-DNS-TXT-Record -bCreate $false -sZoneName $ZoneName -sRecordName $RecordName -sToken $Token
    }
    
    default {
        Write-Log "Invalid action: $Action" -sLevel "ERROR"
        exit 1
    }
}

Write-Log "Great success."
