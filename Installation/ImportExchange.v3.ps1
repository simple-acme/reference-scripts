<#
.SYNOPSIS
Imports and enables an ACME certificate issued by simple-acme (WACS) for Exchange Server services.

.DESCRIPTION
This script is intended to be called by the simple-acme (WACS) installation script
plugin after a certificate has been issued or renewed. It uses positional parameters
only, because simple-acme passes the script arguments as a single string.

The script performs the following steps:

1. Validates all parameters.
2. Locates the certificate in Cert:\LocalMachine\My on the local server, or imports
   it from the PFX file provided by simple-acme.
3. Connects to the Exchange Management Shell of the local server.
4. Optionally reads the current transport certificate of each target server.
5. Enables the certificate for the selected services on the local server.
6. Optionally imports and enables the certificate on all other Exchange mailbox
   servers. The certificate is only imported on servers where it does not exist yet.
7. Optionally restores the previous transport certificate on each server.
8. Optionally removes older certificates with the same subject.

The script writes no console output unless -DebugOn is used. The result is returned
to the calling automation as an exit code. All actions are written to a daily log
file in the script directory.

.PARAMETER NewCertThumbprint
Position 0. Thumbprint of the certificate to enable. Whitespace is removed. When a
PFX file is used, the imported certificate must have this thumbprint.

.PARAMETER ExchangeServices
Position 1. Comma-separated list of Exchange services to enable the certificate for.
Supported values: IIS, SMTP, POP, IMAP, UM, UMCallRouter.
UM and UMCallRouter are only available on Exchange Server 2016.

.PARAMETER LeaveOldExchangeCerts
Position 2. 1 (default) keeps older Exchange certificates with the same subject.
0 removes them on every server where the new certificate was enabled successfully.
A restored transport certificate is never removed.

.PARAMETER CertificatePath
Position 3. Full path to the PFX file provided by simple-acme. Only required when the
certificate is not yet present with a private key in Cert:\LocalMachine\My, or when
the certificate has to be distributed to additional servers.

.PARAMETER PfxPassword
Position 4. Password of the PFX file. Required together with CertificatePath.

.PARAMETER FriendlyName
Position 5. Optional friendly name for the imported certificate.

.PARAMETER DeployToAllMailboxServers
Position 6. 0 (default) enables the certificate on the local server only.
1 additionally imports and enables the certificate on all other Exchange mailbox
servers running Exchange Server 2016 or later.

.PARAMETER RestoreTransportCertificate
Position 7. 0 (default) leaves the new certificate as default transport certificate.
1 restores the transport certificate that was configured on each server before the
new certificate was enabled. Only applies when SMTP is part of ExchangeServices.

.PARAMETER DebugOn
Writes debug output, including all log entries and error details, to the console.

.EXAMPLE
.\ImportExchange.v3.ps1 <Thumbprint> IIS,SMTP

Enables a certificate that already exists in the local certificate store for IIS
and SMTP on the local server.

.EXAMPLE
.\ImportExchange.v3.ps1 <Thumbprint> IIS,SMTP 0 C:\Certs\cert.pfx <PfxPassword> 'Exchange ACME' 1 1

Imports the certificate from the PFX file, enables it on all Exchange mailbox
servers, restores the previous transport certificate on each server, and removes
older certificates with the same subject.

.EXAMPLE
.\ImportExchange.v3.ps1 <Thumbprint> IIS,SMTP 1 '' '' '' 1 0 -DebugOn
$LASTEXITCODE

Test run with console output. Empty strings keep the PFX positions free, so that
the following values are bound to positions 6 and 7.

.EXAMPLE
Script arguments for the simple-acme installation step:

'{CertThumbprint}' 'IIS,SMTP' 1 '{CacheFile}' '{CachePassword}' '{CertFriendlyName}' 1 1

.INPUTS
None. The script does not accept pipeline input.

.OUTPUTS
None. The script returns an exit code:

 0  Success
 1  Unexpected error
 2  Invalid parameters
 3  Certificate store unavailable
 4  Certificate not found or without private key
 5  PFX import failed
 6  Exchange session or permissions
 7  Enable-ExchangeCertificate failed on the local server
 8  Cleanup of old certificates failed
 9  Deployment to at least one additional mailbox server failed
10  Transport certificate could not be read or restored

If several partial failures occur, the most severe code is returned (9, 10, 8).

.NOTES
Version: 3.0

Requirements
- PowerShell 5.1. On older versions the script stops with exit code 1 before
  any action is taken, and no log entry is written.
- Exchange Server 2016 or later.

Logging
- Log file: ImportExchange_yyyyMMdd.log in the script directory.
- Server names are always logged in upper case.
- The PFX password is never written to the log.
- The executing account requires write access to the script directory.

Permissions of the executing account

1. Exchange RBAC
   Recommended: a dedicated role group with the management role
   "Exchange Server Certificates", scoped to the target servers.

   Local server only:
   New-ManagementScope -Name 'ACME SERVERNAME' -ServerRestrictionFilter { Name -eq 'SERVERNAME' }

   All mailbox servers (DeployToAllMailboxServers = 1):
   New-ManagementScope -Name 'ACME Mailbox Servers' -ServerRestrictionFilter { ServerRole -like '*Mailbox*' }

   New-RoleGroup -Name 'ACME Certificate Management' `
     -Roles 'Exchange Server Certificates' `
     -CustomConfigWriteScope 'ACME Mailbox Servers' `
     -Members svc-acme

   RestoreTransportCertificate = 1 requires Get-TransportService. Verify with
   Get-ManagementRoleEntry 'Exchange Server Certificates\Get-TransportService'
   and add a read role such as 'View-Only Configuration' if required.

   Alternative: membership in the built-in role group "Server Management".
   Avoid "Organization Management" for automated tasks.

2. Remote PowerShell
   RemotePowerShellEnabled must be $true for the executing account.

3. Local permissions
   Member of the local Administrators group on the Exchange server
   (required by simple-acme to write to LocalMachine\My and to set private key ACLs).

4. Scheduled task context
   The simple-acme scheduled task runs as SYSTEM by default. In that case the remote
   session authenticates as the computer account. Test the installation step in this
   context or configure the task to run as the dedicated service account.

5. Batch wrapper
   Call the script with powershell.exe -File and end the wrapper with
   exit /b %ERRORLEVEL%. With -Command, every exit code other than 0 becomes 1.

Distribution without PFX file
   Without CertificatePath and PfxPassword, the certificate is exported temporarily
   from the local store for distribution. This requires an exportable private key.
   The temporary file is removed at the end of the run.

Version history
2.0  Initial release.
2.1  Corrected PFX parameter binding and import; added validation, safer
     certificate cleanup, explicit failure reporting, and session cleanup.
3.0  Added defined exit codes for automation and silent operation outside
     debug mode; added error handling for the certificate provider and store;
     added optional deployment to all Exchange mailbox servers (position 6);
     added optional restore of the previous transport certificate (position 7);
     the certificate is only imported on servers where it does not exist yet;
     added a daily log file in the script directory with server names in upper
     case; Exchange cmdlet warnings are written to the log; certificate checks
     run before the Exchange session is created; requires PowerShell 5.1;
     removed the Windows Server 2008 R2 check and the RenewalId parameter.

.LINK
https://learn.microsoft.com/powershell/module/exchangepowershell/enable-exchangecertificate

.LINK
https://learn.microsoft.com/powershell/module/exchangepowershell/import-exchangecertificate

.LINK
https://learn.microsoft.com/powershell/module/exchangepowershell/get-transportservice

.LINK
https://github.com/simple-acme/simple-acme/wiki/Install-Script

.LINK
https://github.com/simple-acme/simple-acme/wiki/Example-Scripts
#>

#Requires -Version 5.1

param(
	[Parameter(Position=0)]
	[string]
	$NewCertThumbprint,

	[Parameter(Position=1)]
	[string]
	$ExchangeServices,

	[Parameter(Position=2)]
	[string]
	$LeaveOldExchangeCerts = '1',

	[Parameter(Position=3)]
	[string]
	$CertificatePath,

	[Parameter(Position=4)]
	[string]
	$PfxPassword,

	[Parameter(Position=5)]
	[string]
	$FriendlyName,

	[Parameter(Position=6)]
	[string]
	$DeployToAllMailboxServers = '0',

	[Parameter(Position=7)]
	[string]
	$RestoreTransportCertificate = '0',

	[switch]$DebugOn
)

# Console output is limited to debug mode. Warnings of the Exchange cmdlets
# are captured explicitly and written to the log file.
if ($DebugOn) {
	$DebugPreference = 'Continue'
}
else {
	$WarningPreference = 'SilentlyContinue'
	$ProgressPreference = 'SilentlyContinue'
}

# Exit codes returned to the calling automation:
#   0 = Success
#   1 = Unexpected error
#   2 = Invalid parameters
#   3 = Certificate store unavailable
#   4 = Certificate not found or without private key
#   5 = PFX import failed
#   6 = Exchange session or permissions
#   7 = Enable-ExchangeCertificate failed on the local server
#   8 = Cleanup of old certificates failed
#   9 = Deployment to at least one additional mailbox server failed
#  10 = Transport certificate could not be read or restored
$ExitCode = 0
$Session = $null
$ExchangeModule = $null
$TempPfxFile = $null

# Log file in the script directory, one file per day.
$LogDirectory = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($LogDirectory)) {
	$LogDirectory = (Get-Location).Path
}
$LogFile = Join-Path -Path $LogDirectory -ChildPath ('ImportExchange_{0}.log' -f (Get-Date -Format 'yyyyMMdd'))

function Write-Log {
	# Appends a timestamped entry to the log file. Logging must never break the script.
	param(
		[Parameter(Mandatory=$true, Position=0)]
		[string]
		$Message,

		[ValidateSet('INFO', 'WARN', 'ERROR')]
		[string]
		$Level = 'INFO'
	)
	$Line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
	# Console output only in debug mode.
	Write-Debug ('[{0}] {1}' -f $Level, $Message)
	try {
		Add-Content -LiteralPath $LogFile -Value $Line -Encoding UTF8 -ErrorAction Stop
	}
	catch {
		Write-Debug ('Failed to write to log file {0}: {1}' -f $LogFile, $_.Exception.Message)
	}
}

function Stop-WithCode {
	# Throws a terminating error that carries the exit code for the central handler.
	param(
		[Parameter(Mandatory=$true, Position=0)]
		[int]
		$Code,

		[Parameter(Mandatory=$true, Position=1)]
		[string]
		$Message
	)
	$Exception = [System.Exception]::new($Message)
	$Exception.Data['ExitCode'] = $Code
	throw $Exception
}

function Get-TransportCertificateThumbprint {
	# Returns the thumbprint of the certificate currently configured as the default
	# certificate of the transport service (InternalTransportCertificateThumbprint).
	param(
		[Parameter(Mandatory=$true, Position=0)]
		[string]
		$ServerName
	)
	$TransportService = Get-TransportService -Identity $ServerName -ErrorAction Stop
	return "$($TransportService.InternalTransportCertificateThumbprint)".Trim()
}

function Restore-TransportCertificate {
	# Re-enables the previously configured transport certificate as default SMTP certificate.
	# Returns $true on success or when nothing needs to be restored, otherwise $false.
	param(
		[Parameter(Mandatory=$true, Position=0)]
		[string]
		$ServerName,

		[Parameter(Position=1)]
		[string]
		$Thumbprint
	)
	if ([string]::IsNullOrWhiteSpace($Thumbprint)) {
		Write-Log ('{0}: No transport certificate was configured before. Nothing to restore.' -f $ServerName)
		return $true
	}
	if ($Thumbprint -eq $Certificate.Thumbprint) {
		Write-Log ('{0}: The ACME certificate already was the transport certificate. Nothing to restore.' -f $ServerName)
		return $true
	}
	try {
		Enable-ExchangeCertificate -Server $ServerName -Services SMTP -Thumbprint $Thumbprint -Force -ErrorAction Stop -WarningVariable RestoreWarnings
		foreach ($Warning in $RestoreWarnings) {
			Write-Log ('{0}: {1}' -f $ServerName, $Warning.Message) -Level WARN
		}
		Write-Log ('Transport certificate {0} restored on {1}.' -f $Thumbprint, $ServerName)
		return $true
	}
	catch {
		Write-Log ('Restoring transport certificate {0} on {1} failed: {2}' -f $Thumbprint, $ServerName, $_.Exception.Message) -Level ERROR
		return $false
	}
}

# Server names are normalized to upper case once, so that log entries are consistent.
$LocalServer = $env:COMPUTERNAME.ToUpperInvariant()

Write-Log ('Run started on {0}.' -f $LocalServer)

try {
	#region Parameter validation (exit code 2)

	if ([string]::IsNullOrWhiteSpace($NewCertThumbprint)) {
		Stop-WithCode 2 'NewCertThumbprint is required.'
	}
	# Ensure that the NewCertThumbprint is a valid 40-character hexadecimal string.
	$NewCertThumbprint = $NewCertThumbprint -replace '\s', ''
	if ($NewCertThumbprint -notmatch '^[0-9a-fA-F]{40}$') {
		Stop-WithCode 2 'NewCertThumbprint must be a 40-character hexadecimal certificate thumbprint.'
	}

	if ([string]::IsNullOrWhiteSpace($ExchangeServices)) {
		Stop-WithCode 2 'ExchangeServices is required.'
	}
	$ServiceEntries = @($ExchangeServices -split ',' | ForEach-Object { $_.Trim() })
	$Services = @($ServiceEntries | Where-Object { $_ })
	$AllowedServices = @('IIS', 'SMTP', 'POP', 'IMAP', 'UM', 'UMCallRouter') # UM and UMCallRouter are legacy Exchange services
	$InvalidServices = @($Services | Where-Object { $_ -notin $AllowedServices })
	# Ensure that the provided Exchange services are non-empty.
	if ($Services.Count -eq 0 -or $ServiceEntries.Count -ne $Services.Count) {
		Stop-WithCode 2 'ExchangeServices must contain non-empty comma-separated service names.'
	}
	# Ensure that the provided Exchange services are valid.
	if ($InvalidServices.Count -gt 0) {
		Stop-WithCode 2 ('ExchangeServices must be a comma-separated list of: {0}. Invalid value(s): {1}.' -f
			($AllowedServices -join ', '), ($InvalidServices -join ', '))
	}
	# Ensure that the provided Exchange services are not duplicated.
	if (@($Services | Select-Object -Unique).Count -ne $Services.Count) {
		Stop-WithCode 2 'ExchangeServices must not contain duplicate service names.'
	}

	if ($LeaveOldExchangeCerts -notmatch '^[01]$') {
		Stop-WithCode 2 'LeaveOldExchangeCerts must be 0 or 1.'
	}

	if ($DeployToAllMailboxServers -notmatch '^[01]$') {
		Stop-WithCode 2 'DeployToAllMailboxServers must be 0 or 1.'
	}

	if ($RestoreTransportCertificate -notmatch '^[01]$') {
		Stop-WithCode 2 'RestoreTransportCertificate must be 0 or 1.'
	}

	# Ensure that the PFX import arguments are either all supplied or none are supplied.
	$PfxArgumentsSupplied = -not [string]::IsNullOrWhiteSpace($CertificatePath) -or
		-not [string]::IsNullOrWhiteSpace($PfxPassword) -or
		-not [string]::IsNullOrWhiteSpace($FriendlyName)
	if ($PfxArgumentsSupplied -and
		([string]::IsNullOrWhiteSpace($CertificatePath) -or
		 [string]::IsNullOrWhiteSpace($PfxPassword))) {
		Stop-WithCode 2 'PFX import requires CertificatePath and PfxPassword.'
	}

	#endregion

	$DeploymentScope = if ($DeployToAllMailboxServers -eq '1') { 'all mailbox servers' } else { 'local server only' }

	Write-Debug ('PowerShell version: {0}' -f $PSVersionTable.PSVersion)
	Write-Debug ('Log file: {0}' -f $LogFile)

	# Restoring the transport certificate is only relevant when SMTP is part of the services.
	$RestoreTransport = $RestoreTransportCertificate -eq '1' -and $Services -contains 'SMTP'

	Write-Log ('Thumbprint: {0}. Services: {1}. Scope: {2}. Remove old certificates: {3}. Restore transport certificate: {4}.' -f
		$NewCertThumbprint, ($Services -join ','), $DeploymentScope, ($LeaveOldExchangeCerts -eq '0'), $RestoreTransport)
	if ($RestoreTransportCertificate -eq '1' -and -not $RestoreTransport) {
		Write-Log 'SMTP is not part of the services. Restoring the transport certificate is not required.'
	}

	#region Certificate store (exit code 3)

	$CertificateStore = 'Cert:\LocalMachine\My'

	# Ensure that the certificate provider and the Cert: drive are available.
	# The drive is provided by Microsoft.PowerShell.Security and may be missing when
	# module autoloading is disabled or the session runs in a restricted context.
	$CertDrive = Get-PSDrive -Name Cert -ErrorAction SilentlyContinue
	if (-not $CertDrive -or $CertDrive.Provider.Name -ne 'Certificate') {
		Write-Debug 'Cert: drive not found. Importing Microsoft.PowerShell.Security.'
		try {
			Import-Module -Name Microsoft.PowerShell.Security -ErrorAction Stop
		}
		catch {
			Stop-WithCode 3 ('The PowerShell certificate provider could not be loaded: {0}' -f $_.Exception.Message)
		}

		$CertDrive = Get-PSDrive -Name Cert -ErrorAction SilentlyContinue
		if (-not $CertDrive -or $CertDrive.Provider.Name -ne 'Certificate') {
			Stop-WithCode 3 'The Cert: drive is unavailable. The local certificate store cannot be accessed.'
		}
	}

	if (-not (Test-Path -LiteralPath $CertificateStore)) {
		Stop-WithCode 3 ('The certificate store {0} does not exist or is not accessible.' -f $CertificateStore)
	}

	try {
		$Certificate = @(
			Get-ChildItem -LiteralPath $CertificateStore -ErrorAction Stop |
				Where-Object { $_.Thumbprint -eq $NewCertThumbprint }
		)
	}
	catch {
		Stop-WithCode 3 ('Failed to read the certificate store {0}: {1}' -f $CertificateStore, $_.Exception.Message)
	}

	#endregion

	#region Locate or import certificate on the local server (exit codes 4 and 5)

	if ($Certificate.Count -gt 1) {
		Stop-WithCode 4 ('Multiple certificates with thumbprint {0} were found in {1}.' -f
			$NewCertThumbprint, $CertificateStore)
	}

	if ($Certificate.Count -eq 0 -or -not $Certificate[0].HasPrivateKey) {
		if (-not $PfxArgumentsSupplied) {
			if ($Certificate.Count -eq 0) {
				Stop-WithCode 4 ('Certificate {0} was not found in {1}. Provide the WACS PFX parameters to import it.' -f
					$NewCertThumbprint, $CertificateStore)
			}
			Stop-WithCode 4 ('Certificate {0} is in {1} but has no private key. Provide the WACS PFX parameters to import it.' -f
				$NewCertThumbprint, $CertificateStore)
		}

		$PfxFile = $CertificatePath
		if (-not (Test-Path -LiteralPath $PfxFile -PathType Leaf)) {
			Stop-WithCode 5 ('WACS PFX file was not found: {0}' -f $PfxFile)
		}

		Write-Debug ('Importing certificate from WACS PFX file: {0}' -f $PfxFile)
		try {
			$SecurePfxPassword = ConvertTo-SecureString -String $PfxPassword -AsPlainText -Force
			$ImportedCertificates = @(
				Import-PfxCertificate -FilePath $PfxFile -CertStoreLocation $CertificateStore -Password $SecurePfxPassword -ErrorAction Stop
			)
		}
		catch {
			Stop-WithCode 5 ('Failed to import the WACS PFX file {0}: {1}' -f $PfxFile, $_.Exception.Message)
		}

		$Certificate = @($ImportedCertificates | Where-Object { $_.Thumbprint -eq $NewCertThumbprint })
		if ($Certificate.Count -ne 1) {
			Stop-WithCode 5 ('The WACS PFX did not import exactly one certificate with thumbprint {0}.' -f
				$NewCertThumbprint)
		}
		if (-not $Certificate[0].HasPrivateKey) {
			Stop-WithCode 5 ('The imported certificate {0} does not have a private key.' -f $NewCertThumbprint)
		}
		if (-not [string]::IsNullOrWhiteSpace($FriendlyName)) {
			$Certificate[0].FriendlyName = $FriendlyName
		}
		Write-Log ('Certificate {0} imported on {1} from PFX file {2}.' -f $NewCertThumbprint, $LocalServer, $PfxFile)
	}
	else {
		Write-Log ('Certificate {0} already present in the local store on {1}. Import skipped.' -f
			$NewCertThumbprint, $LocalServer)
	}

	# Normalize to a single certificate object for the following steps.
	$Certificate = $Certificate[0]
	Write-Log ('Certificate subject: {0}. Valid until: {1}.' -f $Certificate.Subject, $Certificate.NotAfter.ToString('yyyy-MM-dd'))

	#endregion

	#region Exchange session and target servers (exit code 6)

	try {
		$ServerFQDN = [System.Net.Dns]::GetHostByName($LocalServer).HostName
		$ConnectionUri = 'http://{0}/PowerShell/' -f $ServerFQDN
		$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $ConnectionUri -ErrorAction Stop
		$ExchangeModule = Import-PSSession -Session $Session -DisableNameChecking -ErrorAction Stop
	}
	catch {
		Stop-WithCode 6 ('Failed to connect to the Exchange Management Shell: {0}' -f $_.Exception.Message)
	}

	if (-not (Get-Command Enable-ExchangeCertificate -ErrorAction SilentlyContinue)) {
		Stop-WithCode 6 'Enable-ExchangeCertificate is unavailable. Verify that the Exchange Management Shell is accessible and the account has appropriate permissions.'
	}

	if ($RestoreTransport -and -not (Get-Command Get-TransportService -ErrorAction SilentlyContinue)) {
		Stop-WithCode 6 'Get-TransportService is unavailable. The account requires read permissions for the transport configuration to restore the transport certificate.'
	}

	$RemoteServers = @()
	if ($DeployToAllMailboxServers -eq '1') {
		try {
			# Mailbox servers running Exchange 2016 or later, excluding the local server.
			$RemoteServers = @(
				Get-ExchangeServer -ErrorAction Stop |
					Where-Object {
						$_.IsMailboxServer -and
						"$($_.AdminDisplayVersion)" -like 'Version 15.*' -and
						$_.Name -ne $LocalServer
					} |
					Sort-Object -Property Name |
					ForEach-Object { "$($_.Name)".ToUpperInvariant() }
			)
		}
		catch {
			Stop-WithCode 6 ('Failed to enumerate Exchange mailbox servers: {0}' -f $_.Exception.Message)
		}
		Write-Log ('Additional mailbox servers: {0}.' -f $(if ($RemoteServers.Count -gt 0) { $RemoteServers -join ', ' } else { 'none' }))
	}

	#endregion

	$SucceededServers = [System.Collections.Generic.List[string]]::new()
	$FailedServers = [System.Collections.Generic.List[string]]::new()
	$CleanupFailedServers = [System.Collections.Generic.List[string]]::new()
	$RestoreFailedServers = [System.Collections.Generic.List[string]]::new()
	# Transport certificate thumbprint per server, captured before the ACME certificate is enabled.
	$TransportCertificates = @{}

	#region Enable certificate on the local server (exit codes 7 and 10)

	if ($RestoreTransport) {
		try {
			$TransportCertificates[$LocalServer] = Get-TransportCertificateThumbprint $LocalServer
			Write-Log ('Current transport certificate on {0}: {1}.' -f $LocalServer, $TransportCertificates[$LocalServer])
		}
		catch {
			# Abort before any change, otherwise the transport certificate could not be restored.
			Stop-WithCode 10 ('Failed to read the transport certificate on {0}: {1}' -f $LocalServer, $_.Exception.Message)
		}
	}

	try {
		Enable-ExchangeCertificate -Server $LocalServer -Services $Services -Thumbprint $Certificate.Thumbprint -Force -ErrorAction Stop -WarningVariable EnableWarnings
		foreach ($Warning in $EnableWarnings) {
			Write-Log ('{0}: {1}' -f $LocalServer, $Warning.Message) -Level WARN
		}
	}
	catch {
		Write-Log ('Enabling certificate {0} on {1} failed: {2}' -f $Certificate.Thumbprint, $LocalServer, $_.Exception.Message) -Level ERROR
		Stop-WithCode 7 ('Enable-ExchangeCertificate failed on {0}: {1}' -f $LocalServer, $_.Exception.Message)
	}
	$SucceededServers.Add($LocalServer)
	Write-Log ('Certificate {0} enabled on {1} for services: {2}.' -f $Certificate.Thumbprint, $LocalServer, ($Services -join ','))

	if ($RestoreTransport) {
		if (-not (Restore-TransportCertificate $LocalServer $TransportCertificates[$LocalServer])) {
			$RestoreFailedServers.Add($LocalServer)
		}
	}

	#endregion

	#region Deploy to additional mailbox servers (exit code 9)

	if ($RemoteServers.Count -gt 0) {
		# The PFX data for Import-ExchangeCertificate is prepared only when the first server
		# actually needs an import. If the certificate already exists on all servers
		# (e.g. a certificate issued minutes ago is reused), no PFX data is required.
		$PfxData = $null
		$DeployPassword = $null
		$PfxPreparationError = $null

		foreach ($ServerName in $RemoteServers) {
			Write-Debug ('Deploying certificate to {0}.' -f $ServerName)
			try {
				if ($RestoreTransport) {
					# Read before any change. A failure skips this server via the catch block.
					$TransportCertificates[$ServerName] = Get-TransportCertificateThumbprint $ServerName
					Write-Log ('Current transport certificate on {0}: {1}.' -f $ServerName, $TransportCertificates[$ServerName])
				}

				$Existing = @(
					Get-ExchangeCertificate -Server $ServerName -ErrorAction Stop |
						Where-Object { $_.Thumbprint -eq $Certificate.Thumbprint }
				)
				if ($Existing.Count -gt 0) {
					# Import only when the certificate does not exist on the server yet.
					# HasPrivateKey is not evaluated here: the object returned for a remote server
					# through the Exchange remote session does not reliably reflect the private key.
					# Enable-ExchangeCertificate fails with a clear error if the key is really missing.
					Write-Debug ('{0}: HasPrivateKey reported by Get-ExchangeCertificate: {1}' -f $ServerName, $Existing[0].HasPrivateKey)
					Write-Log ('Certificate {0} already present on {1}. Import skipped.' -f $Certificate.Thumbprint, $ServerName)
				}
				else {
					if (-not $PfxData) {
						if ($PfxPreparationError) {
							throw ('The certificate could not be prepared for distribution: {0}' -f $PfxPreparationError)
						}
						try {
							if ($PfxArgumentsSupplied) {
								$DeployPassword = ConvertTo-SecureString -String $PfxPassword -AsPlainText -Force
								$PfxData = [System.IO.File]::ReadAllBytes($CertificatePath)
							}
							else {
								# No WACS PFX available: export the certificate temporarily. Requires an exportable private key.
								$TempPfxFile = Join-Path -Path $env:TEMP -ChildPath ('ImportExchange_{0}.pfx' -f [guid]::NewGuid())
								$DeployPassword = ConvertTo-SecureString -String ([guid]::NewGuid().ToString()) -AsPlainText -Force
								Export-PfxCertificate -Cert $Certificate -FilePath $TempPfxFile -Password $DeployPassword -ErrorAction Stop | Out-Null
								$PfxData = [System.IO.File]::ReadAllBytes($TempPfxFile)
							}
						}
						catch {
							# Remember the error, so that the remaining servers fail fast without a new attempt.
							$PfxPreparationError = 'Provide the WACS PFX parameters or use an exportable private key. {0}' -f $_.Exception.Message
							throw ('The certificate could not be prepared for distribution: {0}' -f $PfxPreparationError)
						}
					}

					$ImportParameters = @{
						Server      = $ServerName
						FileData    = $PfxData
						Password    = $DeployPassword
						ErrorAction = 'Stop'
					}
					if (-not [string]::IsNullOrWhiteSpace($FriendlyName)) {
						$ImportParameters['FriendlyName'] = $FriendlyName
					}
					Import-ExchangeCertificate @ImportParameters | Out-Null
					Write-Log ('Certificate {0} imported on {1}.' -f $Certificate.Thumbprint, $ServerName)
				}

				Enable-ExchangeCertificate -Server $ServerName -Services $Services -Thumbprint $Certificate.Thumbprint -Force -ErrorAction Stop -WarningVariable EnableWarnings
				foreach ($Warning in $EnableWarnings) {
					Write-Log ('{0}: {1}' -f $ServerName, $Warning.Message) -Level WARN
				}
				Write-Log ('Certificate {0} enabled on {1} for services: {2}.' -f $Certificate.Thumbprint, $ServerName, ($Services -join ','))
				$SucceededServers.Add($ServerName)

				if ($RestoreTransport) {
					if (-not (Restore-TransportCertificate $ServerName $TransportCertificates[$ServerName])) {
						$RestoreFailedServers.Add($ServerName)
					}
				}
			}
			catch {
				# Continue with the remaining servers and report the failure at the end.
				$FailedServers.Add($ServerName)
				Write-Log ('Deployment of certificate {0} to {1} failed: {2}' -f $Certificate.Thumbprint, $ServerName, $_.Exception.Message) -Level ERROR
			}
		}
	}

	#endregion

	#region Cleanup of old certificates (exit code 8)

	if ($LeaveOldExchangeCerts -eq '0') {
		Write-Debug ('Removing older Exchange certificates with subject {0}.' -f $Certificate.Subject)
		foreach ($ServerName in $SucceededServers) {
			try {
				$OldCertificates = @(
					Get-ExchangeCertificate -Server $ServerName -ErrorAction Stop |
						Where-Object {
							$_.Thumbprint -ne $Certificate.Thumbprint -and
							$_.Thumbprint -ne $TransportCertificates[$ServerName] -and
							$_.Subject -eq $Certificate.Subject
						}
				)
				foreach ($OldCertificate in $OldCertificates) {
					Remove-ExchangeCertificate -Server $ServerName -Thumbprint $OldCertificate.Thumbprint -Confirm:$false -ErrorAction Stop
					Write-Log ('Old certificate {0} removed from {1}.' -f $OldCertificate.Thumbprint, $ServerName)
				}
			}
			catch {
				$CleanupFailedServers.Add($ServerName)
				Write-Log ('Cleanup of old certificates on {0} failed: {1}' -f $ServerName, $_.Exception.Message) -Level ERROR
			}
		}
	}

	#endregion

	# Report partial failures in order of severity: deployment, transport certificate, cleanup.
	if ($FailedServers.Count -gt 0) {
		Stop-WithCode 9 ('Deployment failed on: {0}. Succeeded on: {1}.' -f ($FailedServers -join ', '), ($SucceededServers -join ', '))
	}
	if ($RestoreFailedServers.Count -gt 0) {
		Stop-WithCode 10 ('Restoring the transport certificate failed on: {0}.' -f ($RestoreFailedServers -join ', '))
	}
	if ($CleanupFailedServers.Count -gt 0) {
		Stop-WithCode 8 ('Cleanup of old certificates failed on: {0}.' -f ($CleanupFailedServers -join ', '))
	}

	Write-Log ('Certificate {0} active on: {1}.' -f $Certificate.Thumbprint, ($SucceededServers -join ', '))
}
catch {
	$ExitCode = 1
	if ($_.Exception.Data.Contains('ExitCode')) {
		$ExitCode = [int]$_.Exception.Data['ExitCode']
	}
	# Write-Log mirrors the error to the console in debug mode only.
	Write-Log ('Run failed with exit code {0}: {1}' -f $ExitCode, $_.Exception.Message) -Level ERROR
	Write-Debug ('Script stack trace: {0}' -f $_.ScriptStackTrace)
}
finally {
	# Cleanup must never override the exit code of the actual operation.
	if ($TempPfxFile -and (Test-Path -LiteralPath $TempPfxFile)) {
		Remove-Item -LiteralPath $TempPfxFile -Force -ErrorAction SilentlyContinue
	}
	if ($ExchangeModule) {
		Remove-Module -ModuleInfo $ExchangeModule -Force -ErrorAction SilentlyContinue
	}
	if ($Session) {
		Remove-PSSession -Session $Session -ErrorAction SilentlyContinue
	}
}

Write-Log ('Run finished with exit code {0}.' -f $ExitCode)
exit $ExitCode