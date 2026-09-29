<#
.SYNOPSIS
Imports a cert from simple-acme renewal into Entra ID application proxy for a specific application that is using it. This way wildcard certificates are not required.

.DESCRIPTION
Note that this script is intended to be run via the install script plugin from simple-acme via the batch script wrapper. As such, we use positional parameters to avoid issues with using a dash in the cmd line. 

Uses Microsoft Graph API instead of deprecated AzureAD module.

.PARAMETER PfxPath
The absolute path to the pfx file that will be uploaded to Entra ID. Typically use '{CacheFile}'

.PARAMETER PfxPass
The password for the pfx file. Typically use '{CachePassword}'

.PARAMETER TenantId
The Entra ID tenant ID (GUID).

.PARAMETER ClientId
The application (client) ID of the app registration used to authenticate against Entra ID. The app must have the
'Application.ReadWrite.All' application permission granted and admin-consented in the tenant.

There are 2 suggested ways to do this:
1. Generate a secret for each proxied application and pass the client ID 
   of each app registration.
2. If you have several proxied applications, and want to avoid having many
   individual secrets: 
   - Create an app registration in your tenant solely used to manage the certificates 
     of proxied applications.
   - Create a secret
   - Grant 'Application.ReadWrite.OwnedBy' as Application to this app registration.
   - Add this app registration as owner of each individual proxied application.

.PARAMETER ClientSecret
Secret used to connect with your ClientId.

.PARAMETER TargetAppId
The Application (client) ID of the Enterprise Application whose certificate should be updated.
Find this value in Entra ID > Enterprise Applications > <your app> > Application ID.

.EXAMPLE
ImportEntraIDApplicationProxy-SingleApp.ps1 <PfxPath> <PfxPass> <TenantId> <ClientId> <ClientSecret> <TargetAppId>

.NOTES
This uses the Microsoft Graph API instead of the deprecated Azure AD module which no longer works.
Unfortunately, the graph API doesn't have good (or any really) documentation about managing certificates.
#>

param(
    [Parameter(Position=0,Mandatory=$true)][string]$PfxPath,
    [Parameter(Position=1,Mandatory=$true)][string]$PfxPass,
    [Parameter(Position=2,Mandatory=$true)][string]$TenantId,
    [Parameter(Position=3,Mandatory=$true)][string]$ClientId,
    [Parameter(Position=4,Mandatory=$true)][string]$ClientSecret,
    [Parameter(Position=5,Mandatory=$true)][string]$TargetAppId
)

# Force pwsh.exe execution
# While so far Powershell Graph modules should work with Windows Powershell 5,
# in practise they are far less reliable than on Microsoft Powershell.
#
# Consider setting PowershellExecutablePath to pwsh.exe in settings.json
if ($PSVersionTable.PSEdition -ne 'Core') {
    & pwsh.exe -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath @args
    exit $LASTEXITCODE
}

if (!(Get-Command "Connect-MgGraph" -ErrorAction SilentlyContinue)) {
    Throw "Microsoft.Graph.Authentication module, install with 'Install-Module -Name Microsoft.Graph.Authentication -Scope AllUsers'"
}

if (!(Get-Command "Get-MgBetaApplication" -ErrorAction SilentlyContinue)) {
    Throw "Missing Microsoft.Beta.Graph.Applications module, install with 'Install-Module -Name Microsoft.Graph.Beta.Applications -Scope AllUsers'"
}

# Connect to Microsoft Graph using ClientId/ClientSecret
$SecureSecret = ConvertTo-SecureString -String $ClientSecret -AsPlainText -Force
$ClientSecretCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $ClientId, $SecureSecret
$null = Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $ClientSecretCredential -NoWelcome

$app = Get-MgApplication -Filter "AppId eq '$TargetAppId'" -ErrorAction Stop
if (-not $app) { Throw "No application found with Application ID '$TargetAppId'." }

# Read certificate and convert to Base64
$certBytes = [System.IO.File]::ReadAllBytes($PfxPath)
$certBase64 = [System.Convert]::ToBase64String($certBytes)

$certParams = @{
    onPremisesPublishing = @{
        verifiedCustomDomainKeyCredential = @{
            type  = "X509CertAndPassword"
            value = $certBase64
        }
        verifiedCustomDomainPasswordCredential = @{
            value = $PfxPass
        }
    }
}

"Updating certificate for $($app.DisplayName)"
Update-MgBetaApplication -ApplicationId $app.Id -BodyParameter $certParams

$null = Disconnect-MgGraph
