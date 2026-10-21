# Requires -Version 5.0
# Requires -Module ActiveDirectory

<#
.SYNOPSIS
Imports a cert from WASC renewal into Exchange services, and enables it for SMTP. It also runs commands needed to configure
connectors and the hybrid configuration object.

.DESCRIPTION
Note that this script is intended to be run via the install script plugin from WASC via the batch script wrapper. As such, we use positional parameters to avoid issues with using a dash in the cmd line.
It is intended to be run on a single server. If you have multiple servers, you will need to run this script on each server that has Exchange installed and is part of the hybrid configuration.

Documentation referenced from https://technet.microsoft.com/en-us/library/aa997231(v=exchg.160).aspx

Proper information should be available here

https://github.com/simple-acme/simple-acme/wiki/Install-Script

or more generally, here

https://github.com/simple-acme/simple-acme/wiki/Example-Scripts

.PARAMETER NewCertThumbprint
The exact thumbprint of the cert to be enabled.

.PARAMETER ReceiveConnectorName
By default the script will configure the "Default Frontend <hostname>" receive connector for the current server. If you have
a different receive connector that you want to configure, you can specify it here. The script will attempt to find a receive
connector with this name and configure it with the new certificate.:

.PARAMETER SendConnectorName
By default the script will configure the send connector with the name starting with 'Outbound to Office 365*'. If you have a
different send connector that you want to configure, you can specify it here. The script will attempt to find a send connector
with this name and configure it with the new certificate.

.PARAMETER LeaveOldExchangeCerts
A bool (as an int, since bools are difficult to pass through as parameters) to determine if old exchange certs with the same CN should be deleted.

1 - Leaves old Exchange certs
0 - Deletes old Exchange certs

.PARAMETER DebugOn
Include this switch parameter to write debug outputs for troubleshooting

.EXAMPLE

ImportExchangeHybridSMTP.ps1 -NewCertThumbprint <certThumbprint>

Enables the new certificate for SMTP and configures the default send and receive connectors for the current server with the new certificate.

.EXAMPLE

ImportExchangeHybridSMTP.ps1 -NewCertThumbprint <certThumbprint> -ReceiveConnectorName "Inbound from Office 365"

Enables the new certificate for SMTP and configures the specified receive connector and the default send connector for the current server with the new certificate.

.EXAMPLE

ImportExchangeHybridSMTP.ps1 -NewCertThumbprint <certThumbprint> -ReceiveConnectorName "Inbound from Office 365" -SendConnectorName "Outbound to Office 365" -LeaveOldExchangeCerts 1

Enables the new certificate for SMTP and configures the specified receive and send connectors for the current server with the new certificate. Leaves old Exchange certs with the same CN.

.NOTES

#>

param(
	[Parameter(Position=0,Mandatory=$true)]
	[string]$NewCertThumbprint,
	[Parameter(Position=1,Mandatory=$false)]
	[string]$ReceiveConnectorName = "$($env:COMPUTERNAME)\Default Frontend $($env:COMPUTERNAME)",
	[Parameter(Position=2,Mandatory=$false)]
	[string]$SendConnectorName = '*Outbound to Office 365*',
	[Parameter(Position=3,Mandatory=$false)]
	[switch]$DebugOn
)

if($DebugOn){
	$DebugPreference = "Continue"
}

If($OSVersion -eq "Windows Server 2008 R2 Standard")
{
	Write-LogFile -Message "Please upgrade Powershell version. See this URL for details: https://github.com/simple-acme/simple-acme/issues/1104"
	exit
}

# Use the script name as the base for the logfile name, add a timestamp to it.
[System.IO.FileInfo]$ScriptName = $MyInvocation.MyCommand.Name
[System.IO.FileInfo]$LogfileName = ($ScriptName.BaseName + "_{0:yyyyMMdd-HHmmss}.log" -f [DateTime]::Now)

# Combine the script directory and logfile name to create the full path of the logfile
[System.IO.FileInfo]$script:LogFileFullPath = Join-Path -Path $PSScriptRoot -ChildPath $LogfileName

# Set start and stop messages for the logfile
[string]$Script:LogFileStart = "{0:dd.MM.yyyy H:mm:ss} : {1}" -f [DateTime]::Now, "Logging started"
[string]$Script:LogFileStop = "Logging stopped"

# Set logging variables to control the initial logging behavior
$Script:LoggingEnabled = $true
$Script:FileLoggingEnabled = $false
$Script:ConsoleLoggingEnabled = $true

function Write-LogFile
{
    # Logging function, used for progress and error logging
    # Uses the globally (script scoped) configured variables 'LogFileFullPath' to identify the logfile, 'LoggingEnabled' to enable/disable logging
    # 'FileLoggingEnabled' to enable/disable file based logging
    # 'ConsoleLoggingEnabled' to enable/disable console based logging
    [CmdLetBinding()]

    param
    (
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [System.Management.Automation.ErrorRecord]$ErrorInfo = $null
    )

    # Prefix the string to write with the current Date and Time, add error message if present...
    if ($ErrorInfo)
    {
        $logLine = "{0:dd.MM.yyyy H:mm:ss} : ERROR : {1} The error is: {2}" -f [DateTime]::Now, $Message, $ErrorInfo.Exception.Message
    }

    Else
    {
        $logLine = "{0:dd.MM.yyyy H:mm:ss} : INFO : {1}" -f [DateTime]::Now, $Message
    }

    function Write-LogToConsole
    {
        # If an errorinfo was given, format the output in red
        If ($ErrorInfo)
        {
            Write-Host -ForegroundColor Red -Object $logLine
        }

        Else
        {
            Write-Host -Object $logLine
        }
    }

    function Write-LogToFile
    {
        # Create the Script:LogfileFullPath and folder structure if it doesn't exist
        if (-not (Test-Path $script:LogFileFullPath -PathType Leaf))
        {
            New-Item -ItemType File -Path $script:LogFileFullPath -Force -Confirm:$false -WhatIf:$false | Out-Null
            Add-Content -Value $Script:LogFileStart -Path $script:LogFileFullPath -Encoding UTF8 -WhatIf:$false -Confirm:$false
        }

        # Write to Script:LogfileFullPath
        Add-Content -Value $logLine -Path $script:LogFileFullPath -Encoding UTF8 -WhatIf:$false -Confirm:$false
    }

    # If logging is enabled...
    if ($Script:LoggingEnabled)
    {
        # If file based and console based logging is enabled, write to the logfile and to the console
        if ($Script:FileLoggingEnabled -and $Script:ConsoleLoggingEnabled)
        {
            Write-LogToFile
            Write-LogToConsole
        }

        # If file based logging is not enabled, but console based logging is enabled, output the log line to the console
        elseif ($Script:ConsoleLoggingEnabled)
        {
            Write-LogToConsole
        }
    }
}

# Print debugging info to make sure the parameters arrived
Write-LogFile -Message "NewCertThumbprint: $NewCertThumbprint"
Write-LogFile -Message "ReceiveConnectorName: $ReceiveConnectorName"
Write-LogFile -Message "SendConnectorName: $SendConnectorName"

# Get Server FQDN for the current server. This is used to connect to the Exchange server.
$ServerFQDN = ([System.Net.Dns]::GetHostByName(($env:computerName))).Hostname

# Connect to Exchange Server
# This code checks if a connection to an Exchange server exists. If no connection exists, it loads the Exchange Management Shell (EMS) and tries to connect to the local Exchange Server.
# Check if a connection to an exchange server exists. If no connection exists, load EMS and connect
if (-NOT (Get-PSSession | Where-Object ConfigurationName -EQ "Microsoft.Exchange"))
{
	# Define EMS script path
	$EMSModuleFile = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup -ErrorAction SilentlyContinue).MsiInstallPath + "bin\RemoteExchange.ps1"

	# If the EMS Module wasn't found
	if ([System.String]::IsNullOrEmpty($EMSModuleFile) -or -Not (Test-Path $EMSModuleFile))
	{
		# Write Error and exit the script
		Write-LogFile -Message -Message "Exchange Management Shell script not found. Please make sure Exchange Management Tools are installed on this server. Exiting script."
		Throw
	}

	else
	{
		# Load Exchange Management Shell
		try
		{
			# Dot source the EMS Script
			. $($EMSModuleFile) -ErrorAction Stop
			Write-LogFile -Message -Object "Successfully loaded Exchange Management Shell script."
		}

		catch
		{
			Write-LogFile -Message -Message "Unable to load Exchange Management Shell script. Exiting script." -ErrorInfo $_
			Throw
		}

		# Connect to Exchange Server
		try
		{
			Connect-ExchangeServer -ServerFqdn $ServerFQDN -ClientApplication:ManagementShell -ErrorAction Stop
			Write-LogFile -Message -Object "Successfully connected to Exchange Server $($ServerFQDN)."
		}

		catch
		{
			Write-LogFile -Message -Message "Unable to connect to Exchange Server. Exiting script." -ErrorInfo $_
			Throw
		}
	}
}

# Test if all required Cmdlets are there
$RequiredCmdlets = @("Enable-ExchangeCertificate", "Get-ExchangeCertificate", "Get-SendConnector", "Set-SendConnector", "Get-ReceiveConnector", "Set-ReceiveConnector", "Set-HybridConfiguration")
foreach ($Cmdlet in $RequiredCmdlets)
{
	$Command = Get-Command $Cmdlet -errorAction SilentlyContinue
	if ($null -eq $Command)
	{
		Write-LogFile -Message "Cmdlet '$Cmdlet' not found. This cmdlet is required for the script to function. Exiting script."
		Break
	}
}

# Check if connectors and hybrid configuration object exist. If one of this objects isn't found, we will throw an error and exit the script.
$SendConnector = Get-SendConnector -Identity $SendConnectorName -ErrorAction SilentlyContinue
if ($null -eq $SendConnector)
{
	Write-LogFile -Message "Send connector with name '$SendConnectorName' not found. Exiting script."
	Break
}

Else
{
	Write-LogFile -Message "Send connector with name '$SendConnectorName' found. Proceeding..."
}

$ReceiveConnector = Get-ReceiveConnector -Identity $ReceiveConnectorName -ErrorAction SilentlyContinue
if ($null -eq $ReceiveConnector)
{
	Write-LogFile -Message "Receive connector with name '$ReceiveConnectorName' not found. Exiting script."
	Break
}

Else
{
	Write-LogFile -Message "Receive connector with name '$ReceiveConnectorName' found. Proceeding..."
}

$HybridConfiguration = Get-HybridConfiguration -ErrorAction SilentlyContinue
if ($null -eq $HybridConfiguration)
{
	Write-LogFile -Message "Hybrid configuration object not found. Exiting script."
	Break
}

Else
{
	Write-LogFile -Message "Hybrid configuration object found. Proceeding..."
}

# Check if the new certificate is recognized by Exchange
# This will only give back certificates that have a private key and are in the local machine store.
# This way we make sure the new certificate is available and usable by Exchange.
$ExchangeCert = Get-ExchangeCertificate -Thumbprint $NewCertThumbprint -ErrorAction SilentlyContinue
if ($null -eq $ExchangeCert)
{
	Write-LogFile -Message "Certificate with thumbprint '$NewCertThumbprint' not found in Exchange. Exiting script."
	Throw
}

# Retrieve the current default SMTP certificate for later restoration.
$DN = (Get-Exchangeserver $env:computername).distinguishedname
$CurrentSMTPCert = (Get-ADObject -Identity $DN -Properties msExchServerInternalTLSCert).msExchServerInternalTLSCert
$CurrentThumbprint = (New-Object system.security.cryptography.x509certificates.x509certificate2 -ArgumentList @(,$CurrentSMTPCert)).Thumbprint

# Enable new certificate for SMTP.
Write-LogFile -Message "Trying to enable Certificate $($ExchangeCert.Thumbprint) for service SMTP..."
try
{
	# Enable the new certificate for SMTP. This is required for Exchange to accept the new certificate for
	# connector configuration. The -Force parameter is used to avoid prompts for confirmation. However, this
	# will overwrite the current default SMTP certificate, so we will restore the default binding later.
	Enable-ExchangeCertificate -Services SMTP -Thumbprint $ExchangeCert.Thumbprint -Force -ErrorAction Stop
	Write-LogFile -Message "Certificate $($ExchangeCert.Thumbprint) successfully enabled for service SMTP."
}

Catch
{
	Write-LogFile -Message "Error enabling certificate $($ExchangeCert.Thumbprint) for service SMTP." -ErrorInfo $_
	Throw
}

# Restore the previous default SMTP certificate.
Write-LogFile -Message "Trying to restore previous default SMTP certificate binding for certificate with Thumbprint $($CurrentThumbprint)..."
Try
{
	# Restore the previous default SMTP certificate. This is required to avoid issues with Exchange services that rely on the default SMTP certificate.
	# Our new certificate will (should be) still be enabled for SMTP.
	Enable-ExchangeCertificate -Services SMTP -Thumbprint $CurrentThumbprint -Force -ErrorAction Stop -WarningAction SilentlyContinue
	Write-LogFile -Message "Previous default SMTP certificate with Thumbprint $($CurrentThumbprint) restored successfully."
}

Catch
{
	Write-LogFile -Message "Error restoring previous default SMTP certificate with Thumbprint $($CurrentThumbprint)." -ErrorInfo $_
	Throw
}

# Delete the old certificate if it exists and has the same subject as the new certificate.
# Check if the new certificate is still enabled for SMTP. If not, we will throw an error and exit the script.
$NewCertEnabledForSMTP = (Get-ExchangeCertificate -Thumbprint $NewCertThumbprint).Services -contains "SMTP"
if (-not $NewCertEnabledForSMTP)
{
	Write-LogFile -Message "New certificate with thumbprint '$NewCertThumbprint' is not enabled for SMTP. Exiting script."
	Throw
}

# New certificate is enabled for SMTP, we can proceed with deleting the old certificate if it exists and has the same subject as the new certificate.
Else
{
	Write-LogFile -Message "New certificate with thumbprint '$NewCertThumbprint' is enabled for SMTP."

	# Try to get the old certifiacte
	[array]$ExistingCertificates = Get-ExchangeCertificate | Where-Object -FilterScript {$_.Subject -eq $cert.Subject -and $_.Thumbprint -ne $NewCertThumbprint}
	if ($ExistingCertificates.count -eq 0)
	{
		Write-LogFile -Message "No existing certificate found with the same subject as the new certificate. Skipping removal of existing certificate."
	}

	else
	{
		Write-LogFile -Message "$($ExistingCertificates.count) existing certificate(s) found with the same subject as the new certificate. Attempting to remove existing certificate(s)..."

		# First we need to remove the certificate string from send/receive connectors and hybrid configuration. If the new certificate contains
		# the same CN and Issuer as the old certificate, Exchange will block removing the old one. By removing the certificate
		# string from connectors and hybrid configuration object, we are able to remove the old certificate.
		Write-LogFile -Message "Trying to remove certificate configuration string from send connector $($SendConnectorName)."
		Try
		{
			Get-SendConnector $SendConnectorName | Set-SendConnector -TlsCertificateName $Null -ErrorAction Stop -WarningAction SilentlyContinue
			Write-LogFile -Message "Successfully removed certificate configuration string from send connector $($SendConnectorName)."
		}

		Catch
		{
			Write-LogFile -Message "Error removing certificate configuration string from send connector $($SendConnectorName)." -ErrorInfo $_
			Throw
		}

		Write-LogFile -Message "Trying to remove certificate configuration string from receive connector $($ReceiveConnectorName)."
		Try
		{
			Get-ReceiveConnector $ReceiveConnectorName | Set-ReceiveConnector -TlsCertificateName $Null -ErrorAction Stop -WarningAction SilentlyContinue
			Write-LogFile -Message "Successfully removed certificate configuration string from receive connector $($ReceiveConnectorName)."
		}

		Catch
		{
			Write-LogFile -Message "Error removing certificate configuration string from receive connector $($ReceiveConnectorName)." -ErrorInfo $_
			Throw
		}

		Write-LogFile -Message "Trying to remove certificate configuration string from hybrid configuration object."
		Try
		{
			Set-HybridConfiguration -TlsCertificateName $Null -ErrorAction Stop -WarningAction SilentlyContinue
			Write-LogFile -Message "Successfully removed certificate configuration string from hybrid configuration object."
		}

		Catch
		{
			Write-LogFile -Message "Error removing certificate configuration string from hybrid configuration object." -ErrorInfo $_
			Throw
		}

		# Since we are changing attributes in AD, we need to wait for replication to occur before we can update the send/receive connectors
		# and hybrid configuration with the new certificate. We will wait for 60 seconds to allow for replication to occur in the same AD site.
		Write-LogFile -Message "Waiting 60 seconds for AD replication to complete..."
		Start-Sleep -Seconds 60

		# There is a chance that multiple old certificates exist with the same subject as the new certificate. We will remove all of them.
		Foreach ($Cert in $ExistingCertificates)
		{
			# Remove old certificate from Exchange server.
			Write-LogFile -Message "Trying to remove existing certificate with Thumbprint $($Cert.Thumbprint) from Exchange..."
			Try
			{
				Remove-ExchangeCertificate -Thumbprint $Cert.Thumbprint -Confirm:$false -ErrorAction Stop -WarningAction SilentlyContinue
				Write-LogFile -Message "Existing certificate with Thumbprint $($Cert.Thumbprint) successfully removed from Exchange Server."
			}

			Catch
			{
				Write-LogFile -Message "Error removing existing certificate with Thumbprint $($Cert.Thumbprint) from Exchange Server." -ErrorInfo $_
				Throw
			}
		}
	}
}
# Update connectors and hybrid configuration object with the new certificate.
# Preparing the new 'TlsCertificateName' for the send/receive connectors and hybrid configuration. This is a string in the format of "<Issuer><Subject>".
$TLSCertName = "<I>$($ExchangeCert.Issuer)<S>$($ExchangeCert.Subject)"
Write-LogFile -Message "New 'TlsCertificateName' for send/receive connectors and hybrid configuration object: $($TLSCertName)"

# Now we can update send/receive connectors and hybrid configuration object with the new certificate string.
Write-LogFile -Message "Trying to update send connector $($SendConnectorName) with the value of $($TLSCertName)"
Try
{
	Get-SendConnector $SendConnectorName | Set-SendConnector -TlsCertificateName $TLSCertName -WarningAction SilentlyContinue
	Write-LogFile -Message "Successfully updated the send connector $($SendConnectorName) with the value of $($TLSCertName)"
}

Catch
{
	Write-LogFile -Message "Error updating the send connector $($SendConnectorName) with the value of $($TLSCertName)." -ErrorInfo $_
	Throw
}

Write-LogFile -Message "Trying to update receive connector $($ReceiveConnectorName) for the current server with the value of $($TLSCertName)"
Try
{
	Get-ReceiveConnector $ReceiveConnectorName | Set-ReceiveConnector -TlsCertificateName $TLSCertName -WarningAction SilentlyContinue
	Write-LogFile -Message "Successfully updated the receive connector $($ReceiveConnectorName) with the value of $($TLSCertName)"
}

Catch
{
	Write-LogFile -Message "Error updating the receive connector $($ReceiveConnectorName) with the value of $($TLSCertName)." -ErrorInfo $_
	Throw
}

Write-LogFile -Message "Trying to update the hybrid configuration object with the value of $($TLSCertName)"
Try
{
	Set-HybridConfiguration -TlsCertificateName $TLSCertName -WarningAction SilentlyContinue
	Write-LogFile -Message "Successfully updated the hybrid configuration object with the value of $($TLSCertName)"
}

Catch
{
	Write-LogFile -Message "Error updating the hybrid configuration object with the value of $($TLSCertName)." -ErrorInfo $_
	Throw
}

Write-LogFile -Message "New certificate with thumbprint $($NewCertThumbprint) has been successfully imported into Exchange services and enabled for SMTP."
Write-LogFile -Message "Send/receive connectors and hybrid configuration object have been updated with the new certificate string $($TLSCertName)."
Write-LogFile -Message "$($ExistingCertificates.count) existing certificate(s) have been removed."
