<#
.SYNOPSIS
  Import-ExchangeHybrid.ps1 - All-in-one Let's Encrypt certificate lifecycle
  manager for Exchange (win-acme / simple-acme based).

.DESCRIPTION
  Single-script consolidation of the former four-script suite (Wacs-Initial,
  Wacs-Export, Wacs-Import, Wacs-HA-Renewal). Every former script is now a
  MODE of this one script, and a new read-only 'verify' prerequisite-check
  mode was added, backed by consolidated shared helpers (settings, logging,
  secrets, PFX discovery/import, Exchange, PEM/CER export) defined once at
  the top of the file.

  MODES
    init        Create the initial win-acme renewal (run once on the ACME host)
    export      Post-renewal artifact generation (win-acme post-install hook)
    import      Deploy latest certificate across Exchange (scheduled task)
    ha-renew    HA recovery: force an immediate renewal on a rebuilt node
    verify      Read-only prerequisite verification (run as service account)
    settings    Bootstrap / inspect wacs-settings.json interactively

  CONFIGURATION
    All modes read wacs-settings.json (next to this script; override with
    -SettingsPath). Resolution precedence everywhere:
      explicit parameter > settings file > built-in default.
    If the settings file is missing/empty AND the session is interactive you
    are prompted once for the core values (including which DNS validation
    plugin your environment uses) and the file is created. In non-interactive
    contexts (scheduled tasks, win-acme hooks) the script fails fast with
    remediation guidance instead of hanging on a prompt.

    Secrets (actual passwords) NEVER go in the settings file - only vault
    references (vault://...) do. Passwords live in export-secrets.json on the
    share root.

  DNS VALIDATION
    The DNS-01 provider is NOT presumed. The settings key DnsPlugin selects:
      cloudflare - simple-acme Cloudflare plugin (separate download, unpacked
                  next to wacs.exe); token via settings CloudflareApiToken.
      script     - simple-acme generic script plugin; point DnsCreateScript /
                  DnsDeleteScript at provider scripts (e.g. OVH, or any
                  provider without a native plugin). Provider credentials stay
                  in the scripts' own configuration, not in this settings file.
      custom     - raw wacs.exe validation arguments via WacsValidationArgs
                  (space-separated), for any other plugin (Azure DNS, Route53,
                  acme-dns, ...). Secrets inside must be vault:// references.
    Run 'settings' once to choose interactively; init/ha-renew never prompt.

  SECRETS FORMAT (canonical, on the share):
    [ { "Key": "default", "Secret": "..." }, { "Key": "example.com", "Secret": "..." } ]
    A legacy object-map shape ({ "default": { "pfxPassword": "..." } }) is still accepted.

  SERVICE ACCOUNT (tenant-provisioned, NOT automated by this script):
    - Local Administrator on all Exchange servers
    - Member of 'Exchange Trusted Subsystem' (and, where required by your
      topology, the local 'Exchange Servers' group on each node)
    - Exchange RBAC rights to manage certificates and connectors
    Run 'Import-ExchangeHybrid.ps1 verify' as the service account to validate all of this.

.EXECUTION
  .\Import-ExchangeHybrid.ps1 settings                                   # first run: bootstrap config
  .\Import-ExchangeHybrid.ps1 init                                       # settings-driven initial renewal
  .\Import-ExchangeHybrid.ps1 verify                                     # prereq checks (as service account)
  .\Import-ExchangeHybrid.ps1 import                                     # scheduled-task deployment (no params)
  .\Import-ExchangeHybrid.ps1 ha-renew                                   # HA recovery on a rebuilt node
  .\Import-ExchangeHybrid.ps1 export -NewCertThumbprint "<thumb>" ...     # win-acme hook form

  Example win-acme hook wiring (--scriptparameters):
    export -NewCertThumbprint '{CertThumbprint}' -OutputRoot '\\NETWORKDRIVE\Share' -RequiredDomainsCsv '*.example.com,example.com' -ExportPfxPassword '{CachePassword}'

.NOTES
  Run as Administrator or SYSTEM. Exit codes: 0 = success, 1 = failure.
#>
[CmdletBinding()]
param(
    # ---------------- Dispatcher ----------------
    [Parameter(Position=0)]
    [ValidateSet('Init','Export','Import','Ha-Renew','Verify','Settings','Help','')]
    [string] $Mode = '',

    # ---------------- Common ----------------
    [string] $SettingsPath,
    [switch]  $DebugOn,

    # ---------------- Init / Ha-Renew ----------------
    [string] $WacsPath,        # Default: settings WacsPath
    [string] $ShareRoot,       # Default: settings ShareRoot
    [string] $Domains,         # Default: settings RequiredDomainsCsv
    [string] $ApiToken,        # Default: settings CloudflareApiToken (vault:// ref, cloudflare plugin only)
    [string] $PfxPassword,     # Default: settings PfxPasswordVaultRef (vault:// ref)

    # ---------------- Export ----------------
    [string] $NewCertThumbprint,   # Expected for export mode
    [string] $FriendlyName,
    [string] $OutputRoot,          # Default: settings ShareRoot
    [string] $RequiredDomainsCsv,  # Default: settings RequiredDomainsCsv
    [string] $SecretsPath,         # Default: <ShareRoot>\<settings SecretsFileName>
    [string] $ExportPfxPassword,   # Overrides secrets resolution
    [switch]  $AllowStoreFallback,

    # ---------------- Import ----------------
    [string] $BaseName,             # Default: settings BaseName
    [string] $PfxOverridePath,
    [string] $Services,             # Default: settings Services
    [switch]  $NoHybridUpdates,     # Default: -not settings EnableHybridUpdates
    [string] $SendConnectorName,   # Default: settings SendConnectorName
    [string[]]$SendConnectorExact,
    [switch]  $AllSendConnectors,
    [string] $ReceiveConnectorPattern,  # Default: settings ReceiveConnectorPattern
    [switch]  $NoCleanup,            # Default: -not settings CleanupOldCerts
    [switch]  $RestartIIS,          # Default: settings RestartIIS
    [switch]  $Diagnose,
    [switch]  $StartTranscript,
    [string] $TranscriptPath,

    # ---------------- Verify ----------------
    [string[]]$Servers,
    [switch]  $SkipExchangeChecks
)

# =====================================================================
# 1. SETTINGS
# =====================================================================

# Good defaults: every knob the suite uses, in one place. Values here are
# placeholders that work for a single-domain lab; the first-run bootstrap
# replaces the core ones for real deployments.
$script:WacsSettingsDefaults = [ordered]@{
    ShareRoot               = '\\NETWORKDRIVE\Share'       # Central UNC share for artifacts/secrets
    BaseName                = 'example.com'               # Base name for cert files & secrets lookup
    RequiredDomainsCsv      = '*.example.com,example.com'  # SANs the renewal covers
    FriendlyName            = 'example.com'                # win-acme renewal friendly name
    WacsPath                = 'C:\Program Files\simple-acme\wacs.exe'
    SecretsFileName         = 'export-secrets.json'        # Relative to ShareRoot
    Services                = 'IIS,SMTP'                   # Exchange services to enable
    SendConnectorName       = '*Outbound to Office 365*'
    ReceiveConnectorPattern = ''                           # Empty = "*Default Frontend <hostname>*"
    DnsPlugin               = 'cloudflare'                 # cloudflare | script | custom
    CloudflareApiToken      = 'vault://json/cloudflare-token'   # vault:// ref (DnsPlugin=cloudflare)
    DnsCreateScript         = ''                           # TXT create script (DnsPlugin=script)
    DnsDeleteScript         = ''                           # TXT delete script, optional (DnsPlugin=script)
    DnsCreateScriptArgs     = '{Identifier} {RecordName} {Token}'   # Argument template for create script
    DnsDeleteScriptArgs     = '{Identifier} {RecordName} {Token}'   # Argument template for delete script
    WacsValidationArgs      = ''                           # Raw wacs validation args (DnsPlugin=custom)
    PfxPasswordVaultRef     = 'vault://json/pfx-password'   # vault:// ref used for --pfxpassword
    EnableHybridUpdates     = $true
    CleanupOldCerts         = $true
    RestartIIS              = $false
}
$script:WacsScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$script:WacsSettingsPath = $null
$script:WacsDebugOn = $false
$script:WacsDiagnose = $false

function Get-SettingsPath {
    param([string]$OverridePath)
    if ($OverridePath -and $OverridePath.Trim()) { return $OverridePath }
    if ($script:WacsSettingsPath) { return $script:WacsSettingsPath }
    return (Join-Path $script:WacsScriptDir 'wacs-settings.json')
}

# Encoding- and provider-safe JSON file reader (UTF-8 BOM/no BOM, UTF-16 LE/BE)
function Read-JsonFile {
    param([string]$Path)
    if (-not $Path) { return $null }
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    # Normalize to a pure filesystem path (strip provider prefix)
    $fsPath = (Get-Item -LiteralPath $Path -ErrorAction Stop).FullName
    $bytes = [System.IO.File]::ReadAllBytes($fsPath)
    if (-not $bytes -or $bytes.Length -eq 0) { return $null }

    $raw = $null
    if     ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) { $raw = [System.Text.Encoding]::UTF8.GetString($bytes, 3, $bytes.Length - 3) }
    elseif ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE)                           { $raw = [System.Text.Encoding]::Unicode.GetString($bytes, 2, $bytes.Length - 2) }
    elseif ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF)                           { $raw = [System.Text.Encoding]::BigEndianUnicode.GetString($bytes, 2, $bytes.Length - 2) }
    else                                                                                                   { $raw = [System.Text.Encoding]::UTF8.GetString($bytes) }

    if (-not $raw -or -not $raw.Trim()) { return $null }
    return $raw | ConvertFrom-Json -ErrorAction Stop
}

function Save-Settings {
    param([string]$Path, [System.Collections.IDictionary]$Settings)
    $Settings | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $Path -Encoding UTF8
    Write-Log "Saved settings to $Path"
}

function Test-InteractiveHost {
    try {
        $interactive = [Environment]::UserInteractive -and ($Host.Name -eq 'ConsoleHost')
        try { $interactive = $interactive -and -not [Console]::IsOutputRedirected } catch {}
        return $interactive
    } catch { return $false }
}

function Initialize-Settings {
    <#
      Loads wacs-settings.json. If missing/empty:
      - Interactive session: prompts for the core values (including the DNS
        validation plugin), writes the file (with all defaults included so
        every knob is visible/discoverable), returns settings.
      - Non-interactive: throws with remediation guidance (never hangs a task).
    #>
    param([string]$Path)

    $settingsPath = Get-SettingsPath -OverridePath $Path
    $settings = $null
    if (Test-Path -LiteralPath $settingsPath) {
        try { $settings = Read-JsonFile -Path $settingsPath }
        catch { throw "Settings file '$settingsPath' could not be parsed: $($_.Exception.Message)" }
    }

    if ($settings) {
        $props = @($settings.PSObject.Properties.Name)
        $hasCore = ($props -contains 'ShareRoot') -and ($props -contains 'BaseName')
        if (-not $hasCore) {
            throw "Settings file incomplete: '$settingsPath'. Expected at minimum: ShareRoot, BaseName, RequiredDomainsCsv. Run 'Import-ExchangeHybrid.ps1 settings' interactively to rebuild it."
        }
        # Merge with defaults so every knob exists even in older settings files
        $merged = [ordered]@{}
        foreach ($k in $script:WacsSettingsDefaults.Keys) {
            $merged[$k] = if ($props -contains $k) { $settings.$k } else { $script:WacsSettingsDefaults[$k] }
        }
        $script:WacsSettingsPath = $settingsPath
        Write-Log "Loaded settings from $settingsPath" 'DEBUG'
        return $merged
    }

    # ---------------- First-run bootstrap (interactive only) ----------------
    if (-not (Test-InteractiveHost)) {
        throw "Settings file not found or empty: '$settingsPath'. Run 'Import-ExchangeHybrid.ps1 settings' once interactively to bootstrap it, or create the file manually. Expected at minimum: ShareRoot, BaseName, RequiredDomainsCsv."
    }

    Write-Host "No settings found at $settingsPath - starting first-run bootstrap."
    Write-Host "You will be prompted for the core values; every other knob gets a sensible default."
    Write-Host ""

    $answers = @{}
    foreach ($key in @('ShareRoot','BaseName','RequiredDomainsCsv','FriendlyName','WacsPath')) {
        $def = [string]$script:WacsSettingsDefaults[$key]
        $v = Read-Host ("{0} [{1}]" -f $key, $def)
        if (-not $v -or -not $v.Trim()) { $v = $def }
        $answers[$key] = $v
    }

    Write-Host ""
    Write-Host "Which DNS-01 validation plugin does your environment use?"
    Write-Host "  cloudflare - Cloudflare API token (simple-acme Cloudflare plugin)"
    Write-Host "  script     - generic script plugin (OVH or any provider without a native plugin)"
    Write-Host "  custom     - raw wacs.exe validation arguments (Azure DNS, Route53, acme-dns, ...)"
    $plugin = Read-Host "DnsPlugin [cloudflare]"
    if (-not $plugin -or -not $plugin.Trim()) { $plugin = 'cloudflare' }
    $plugin = $plugin.Trim().ToLowerInvariant()
    if (@('cloudflare','script','custom') -notcontains $plugin) {
        throw "Unknown DnsPlugin '$plugin'. Supported: cloudflare, script, custom."
    }
    $answers['DnsPlugin'] = $plugin

    switch ($plugin) {
        'cloudflare' {
            $v = Read-Host ("CloudflareApiToken (vault:// ref) [{0}]" -f $script:WacsSettingsDefaults['CloudflareApiToken'])
            $answers['CloudflareApiToken'] = if ($v -and $v.Trim()) { $v.Trim() } else { [string]$script:WacsSettingsDefaults['CloudflareApiToken'] }
        }
        'script' {
            $v = Read-Host 'DnsCreateScript (path to your TXT-record create script)'
            $answers['DnsCreateScript'] = if ($v) { $v.Trim() } else { '' }
            if (-not $answers['DnsCreateScript']) { throw "DnsPlugin 'script' requires DnsCreateScript." }
            $v = Read-Host 'DnsDeleteScript (optional path to your TXT-record delete script)'
            $answers['DnsDeleteScript'] = if ($v) { $v.Trim() } else { '' }
        }
        'custom' {
            $v = Read-Host 'WacsValidationArgs (raw wacs.exe validation arguments, space-separated)'
            $answers['WacsValidationArgs'] = if ($v) { $v.Trim() } else { '' }
            if (-not $answers['WacsValidationArgs']) { throw "DnsPlugin 'custom' requires WacsValidationArgs." }
        }
    }

    # Build the FULL settings file: defaults + prompted answers
    $full = [ordered]@{}
    foreach ($k in $script:WacsSettingsDefaults.Keys) { $full[$k] = $script:WacsSettingsDefaults[$k] }
    foreach ($k in $answers.Keys) { $full[$k] = $answers[$k] }
    Save-Settings -Path $settingsPath -Settings $full
    $script:WacsSettingsPath = $settingsPath
    return $full
}

function Get-SettingValue {
    param([System.Collections.IDictionary]$Settings, [string]$Key, $Default = $null)
    if ($Settings -and $Settings.Contains($Key)) {
        $v = $Settings[$Key]
        if ($null -ne $v -and "$v".Trim() -ne '') { return $v }
    }
    if ($null -ne $Default) { return $Default }
    return $script:WacsSettingsDefaults[$Key]
}

# =====================================================================
# 2. LOGGING & SAFETY
# =====================================================================

function Write-Log {
    param([string]$Message, [ValidateSet('INFO','WARN','ERROR','DEBUG','DIAG')][string]$Level = 'INFO')
    $stamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    switch ($Level) {
        'INFO'  { Write-Host    "[$stamp][INFO ] $Message" }
        'WARN'  { Write-Warning "[$stamp][WARN ] $Message" }
        'ERROR' { Write-Error   "[$stamp][ERROR] $Message" }
        'DEBUG' { if ($script:WacsDebugOn)  { Write-Host "[$stamp][DEBUG] $Message" -ForegroundColor DarkGray } }
        'DIAG'  { if ($script:WacsDebugOn -or $script:WacsDiagnose) { Write-Host "[$stamp][DIAG ] $Message" -ForegroundColor Cyan } }
    }
}

function Require-AdminOrSystem {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    $isAdmin  = $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $isSystem = $id.Name -eq "NT AUTHORITY\SYSTEM"
    if (-not ($isAdmin -or $isSystem)) {
        throw "Run as Administrator or SYSTEM (recommended: service account with local admin + Exchange RBAC)."
    }
    Write-Log "Running as: $($id.Name)" 'DIAG'
}

function Ensure-Folder {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
        Write-Log "Created folder $Path"
    }
    (Resolve-Path -LiteralPath $Path).Path
}

# =====================================================================
# 3. DNS-01 VALIDATION ARGUMENT BUILDER (plugin-agnostic)
# =====================================================================

function Get-WacsValidationArgs {
    <#
      Builds the wacs.exe arguments that implement DNS-01 validation for the
      configured DnsPlugin. Never prompts; throws with remediation when the
      plugin's required settings are missing.
    #>
    param([System.Collections.IDictionary]$Settings)

    $plugin = [string](Get-SettingValue -Settings $Settings -Key 'DnsPlugin')
    $plugin = $plugin.Trim().ToLowerInvariant()
    $valArgs = @('--validationmode', 'dns-01')

    switch ($plugin) {
        'cloudflare' {
            $token = [string](Get-SettingValue -Settings $Settings -Key 'CloudflareApiToken')
            if (-not $token -or -not $token.Trim()) {
                throw "DnsPlugin 'cloudflare' requires settings CloudflareApiToken (vault:// reference). Run 'Import-ExchangeHybrid.ps1 settings' to configure it."
            }
            $valArgs += @('--validation', 'cloudflare', '--cloudflareapitoken', $token)
        }
        'script' {
            $create = [string](Get-SettingValue -Settings $Settings -Key 'DnsCreateScript')
            $delete = [string](Get-SettingValue -Settings $Settings -Key 'DnsDeleteScript')
            if (-not $create -or -not $create.Trim()) {
                throw "DnsPlugin 'script' requires settings DnsCreateScript (path to your TXT-record create script). Run 'Import-ExchangeHybrid.ps1 settings' to configure it."
            }
            $valArgs += @('--validation', 'script', '--dnscreatescript', $create)
            $createArgs = [string](Get-SettingValue -Settings $Settings -Key 'DnsCreateScriptArgs')
            if ($createArgs -and $createArgs.Trim()) { $valArgs += @('--dnscreatescriptarguments', $createArgs) }
            if ($delete -and $delete.Trim()) {
                $valArgs += @('--dnsdeletescript', $delete)
                $deleteArgs = [string](Get-SettingValue -Settings $Settings -Key 'DnsDeleteScriptArgs')
                if ($deleteArgs -and $deleteArgs.Trim()) { $valArgs += @('--dnsdeletescriptarguments', $deleteArgs) }
            }
        }
        'custom' {
            $raw = [string](Get-SettingValue -Settings $Settings -Key 'WacsValidationArgs')
            if (-not $raw -or -not $raw.Trim()) {
                throw "DnsPlugin 'custom' requires settings WacsValidationArgs (raw wacs.exe validation arguments, space-separated). Run 'Import-ExchangeHybrid.ps1 settings' to configure it."
            }
            $valArgs += (@($raw.Trim() -split '\s+') | Where-Object { $_ })
        }
        default {
            throw "Unknown DnsPlugin '$plugin'. Supported: cloudflare, script, custom. Run 'Import-ExchangeHybrid.ps1 settings' to fix wacs-settings.json."
        }
    }
    return ,$valArgs
}

# =====================================================================
# 4. SECRETS
# =====================================================================

# Encoding- and provider-safe loader
function Load-Secrets {
    param([string]$Path)
    if (-not $Path) { return $null }
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    try {
        return (Read-JsonFile -Path $Path)
    } catch {
        throw "Failed to parse secrets file at '$Path' $($_.Exception.Message)"
    }
}

# Normalize secrets to a list of @{ Key=..., Secret=... } (case-insensitive, trimmed)
# Accepts the canonical Key/Secret array and legacy object-map shapes.
function Get-SecretsEntries {
    param([object]$Secrets)
    $entries = New-Object System.Collections.Generic.List[object]
    if ($null -eq $Secrets) { return ,$entries }

    if ($Secrets -is [System.Array]) {
        foreach ($it in $Secrets) {
            if ($null -ne $it -and ($it.PSObject.Properties.Name -contains 'Key') -and ($it.PSObject.Properties.Name -contains 'Secret')) {
                $key = ([string]$it.Key).Trim()
                $sec = ([string]$it.Secret)
                if ($key -and $sec) { [void]$entries.Add([ordered]@{ Key=$key; Secret=$sec }) }
            }
        }
    } else {
        # Legacy back-compat: object with named properties -> entries
        foreach ($p in $Secrets.PSObject.Properties) {
            $name = ([string]$p.Name).Trim()
            $node = $p.Value
            $pw = $null
            if     ($node -is [string])                                                       { $pw = [string]$node }
            elseif ($null -ne $node -and ($node.PSObject.Properties.Name -contains 'pfxPassword')) { $pw = [string]$node.pfxPassword }
            if ($name -and $pw) { [void]$entries.Add([ordered]@{ Key=$name; Secret=$pw }) }
        }
    }
    return ,$entries
}

function Find-Secret {
    param([string]$Key, [object[]]$Entries)
    if (-not $Key) { return $null }
    $norm = $Key.Trim()
    $hit = $Entries | Where-Object { $_.Key.Trim() -ieq $norm } | Select-Object -First 1
    if ($hit) { return [string]$hit.Secret }
    return $null
}

# Unique password candidate list, default's secret first
function Get-SecretPasswordCandidates {
    param([object[]]$Entries)
    $list = New-Object System.Collections.Generic.List[string]
    if ($null -eq $Entries -or $Entries.Count -eq 0) { return ,$list }

    foreach ($e in $Entries) {
        $pw = [string]$e.Secret
        if ($pw -and -not $list.Contains($pw)) { [void]$list.Add($pw) }
    }
    $default = $Entries | Where-Object { $_.Key -ieq 'default' } | Select-Object -First 1
    if ($default) {
        $defPw = [string]$default.Secret
        if ($defPw -and $list.Contains($defPw)) {
            $list.Remove($defPw) | Out-Null
            $list.Insert(0, $defPw)
        }
    }
    return ,$list
}

# Resolve export password: ParamOverride first, then BaseName -> any SAN ->
# default -> the password that successfully imported the source PFX.
function Resolve-PfxPassword {
    param(
        [object[]]$Entries,
        [string]$BaseName,
        [string[]]$PresentDomains,
        [string]$ParamOverride,
        [string]$ImportPw
    )

    if ($ParamOverride) { return $ParamOverride }

    if ($Entries -and $Entries.Count -gt 0) {
        $pw = Find-Secret -Key $BaseName -Entries $Entries
        if ($pw) { return $pw }

        if ($PresentDomains) {
            foreach ($d in $PresentDomains) {
                $pw = Find-Secret -Key $d -Entries $Entries
                if ($pw) { return $pw }
            }
        }

        $pw = Find-Secret -Key 'default' -Entries $Entries
        if ($pw) { return $pw }
    }

    if ($ImportPw) { return $ImportPw }
    return $null
}

# =====================================================================
# 5. CERTIFICATE & PFX HELPERS
# =====================================================================

function Get-RequiredDomains {
    param([string]$Csv)
    ($Csv -split ',') | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ -ne '' } | Sort-Object -Unique
}

function Get-CertDomains {
    <#
      Returns lower-cased list of SAN DNS names (plus CN as fallback) from a cert.
      Note: Detect SAN by OID to avoid localized FriendlyName lookups.
    #>
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert)
    $dns = New-Object System.Collections.Generic.List[string]
    $cn = $Cert.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::DnsName, $false)
    if ($cn) { [void]$dns.Add($cn.ToLowerInvariant()) }
    foreach ($ext in $Cert.Extensions) {
        if ($ext.Oid.Value -eq '2.5.29.17') {
            $data = $ext.Format($true)
            $data -split "`n" | ForEach-Object {
                $line = $_.Trim()
                if ($line -match '^DNS Name=(.+)$') {
                    [void]$dns.Add($Matches[1].Trim().ToLowerInvariant())
                }
            }
        }
    }
    return ,($dns | Sort-Object -Unique)
}

function Test-RequiredDomainsPresent {
    param([string[]]$Required, [string[]]$Present)
    $missing = @()
    foreach ($r in $Required) { if ($Present -notcontains $r) { $missing += $r } }
    return ,$missing
}

function Choose-BaseName {
    param([string[]]$Required, [string[]]$Present)
    $candidate = $Required | Where-Object { $_ -notmatch '^\*\.' } | Where-Object { $Present -contains $_ } | Select-Object -First 1
    if (-not $candidate) { $candidate = $Present | Where-Object { $_ -notmatch '^\*\.' } | Select-Object -First 1 }
    if (-not $candidate) { $candidate = ($Present | Select-Object -First 1) }
    if ($candidate -like '*.*') { return $candidate -replace '^\*\.', '' }
    return $candidate
}

function Get-CN {
    param([string]$Subject)
    ($Subject -split ',') | Where-Object { $_ -like 'CN=*' } |
        ForEach-Object { $_.Split('=')[1].Trim() } | Select-Object -First 1
}

function Get-CertTlsName {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert)
    return ("<I>{0}<S>{1}" -f $Cert.Issuer, $Cert.Subject)
}

function Is-SelfSigned {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert)
    return ($Cert.Subject -eq $Cert.Issuer)
}

function Get-CertChain {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert)
    $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
    $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
    $chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::IgnoreWrongUsage
    [void]$chain.Build($Cert)
    return ,($chain.ChainElements | ForEach-Object { $_.Certificate })
}

function To-Pem {
    param([byte[]]$Raw, [string]$Header, [string]$Footer)
    $b64 = [System.Convert]::ToBase64String($Raw)
    $chunks = ($b64 -split "(.{1,64})" | Where-Object { $_ -ne '' })
    return @($Header) + $chunks + @($Footer) -join "`r`n"
}

function Export-LeafCer {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert, [string]$CerPath)
    Export-Certificate -Cert $Cert -FilePath $CerPath -Type CERT -Force | Out-Null
}

function Export-LeafPem {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert, [string]$PemPath)
    $raw = $Cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    $pem = To-Pem -Raw $raw -Header '-----BEGIN CERTIFICATE-----' -Footer '-----END CERTIFICATE-----'
    Set-Content -LiteralPath $PemPath -Value $pem -NoNewline -Encoding ascii
}

function Export-FullChainPem {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert, [string]$FullChainPemPath)
    $chain = Get-CertChain -Cert $Cert
    if ($chain.Count -gt 0 -and (Is-SelfSigned -Cert $chain[-1])) {
        $chain = @($chain[0..($chain.Count-2)])
    }
    $parts = @()
    foreach ($c in $chain) {
        $parts += To-Pem -Raw $c.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert) -Header '-----BEGIN CERTIFICATE-----' -Footer '-----END CERTIFICATE-----'
    }
    Set-Content -LiteralPath $FullChainPemPath -Value ($parts -join "`r`n") -NoNewline -Encoding ascii
}

function Export-PfxWithPassword {
    param(
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert,
        [string]$DestPfxPath,
        [string]$Password
    )
    if (-not $Password) { throw "Export PFX password not resolved. Check secrets file or pass -ExportPfxPassword." }

    $sec = ConvertTo-SecureString -String $Password -AsPlainText -Force

    # Open a temporary Current User store so the native cmdlet can see the key
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("My", "CurrentUser")
    $store.Open("ReadWrite")
    try {
        $store.Add($Cert)
        Export-PfxCertificate -Cert $Cert -FilePath $DestPfxPath -Password $sec -Force | Out-Null
    }
    finally {
        # Clean up immediately so no zombie keys are left behind
        $store.Remove($Cert)
        $store.Close()
    }
}

# Attempt to import PFX bytes with a set of candidate passwords (provider-safe).
# Returns the imported X509Certificate2 and sets $UsedPassword, or $null.
function Import-PfxBytes {
    param(
        [byte[]]$Bytes,
        [string[]]$CandidatePasswords,
        [ref]$UsedPassword
    )
    $flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::MachineKeySet `
        -bor [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet `
        -bor [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable

    if ($CandidatePasswords) {
        foreach ($pw in $CandidatePasswords) {
            try {
                $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                $cert.Import($Bytes, $pw, $flags)
                $UsedPassword.Value = $pw
                return $cert
            } catch {
                Write-Log "Password attempt failed (masked)." 'DEBUG'
            }
        }
    }

    # Last attempt: empty password
    try {
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
        $cert.Import($Bytes, "", $flags)
        $UsedPassword.Value = ""
        return $cert
    } catch {
        Write-Log "Empty password attempt failed." 'DEBUG'
    }
    return $null
}

# Wildcard-aware PFX candidate ordering for the export stage:
#   exact <base>.pfx and _.<base>.pfx (underscore preferred when wildcard SANs
#   are required), then *<base>*.pfx newest-first, then the newest *.pfx.
function Find-PfxCandidates {
    param(
        [Parameter(Mandatory=$true)][string]$CertsDir,
        [Parameter(Mandatory=$true)][string]$BaseName,
        [switch]$WildcardPresent
    )

    $candidates = New-Object System.Collections.Generic.List[System.IO.FileInfo]

    $exactPath      = Join-Path $CertsDir ("{0}.pfx" -f $BaseName)
    $underscorePath = Join-Path $CertsDir ("_.{0}.pfx" -f $BaseName)

    $orderedPreferred = if ($WildcardPresent) { @($underscorePath, $exactPath) } else { @($exactPath, $underscorePath) }
    foreach ($p in $orderedPreferred) {
        if (Test-Path -LiteralPath $p) {
            $item = Get-Item -LiteralPath $p -ErrorAction SilentlyContinue
            if ($item) { [void]$candidates.Add($item) }
        }
    }

    $patternMatches = Get-ChildItem -LiteralPath $CertsDir -Filter '*.pfx' -File -ErrorAction SilentlyContinue |
                      Where-Object { $_.Name -like ("*{0}*" -f $BaseName) } |
                      Sort-Object LastWriteTime -Descending
    foreach ($m in $patternMatches) {
        if (-not ($candidates | Where-Object { $_.FullName -ieq $m.FullName })) { [void]$candidates.Add($m) }
    }

    $newest = Get-ChildItem -LiteralPath $CertsDir -Filter '*.pfx' -File -ErrorAction SilentlyContinue |
              Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($newest -and -not ($candidates | Where-Object { $_.FullName -ieq $newest.FullName })) { [void]$candidates.Add($newest) }

    return ,$candidates
}

function Get-CertificateFromStores {
    param([string]$Thumbprint)
    $thumb = $Thumbprint -replace '\s','' -replace '[^0-9A-Fa-f]',''
    $stores = @('Cert:\LocalMachine\My', 'Cert:\LocalMachine\WebHosting')
    foreach ($store in $stores) {
        try {
            Write-Log "Searching store $store for thumbprint $thumb" 'DEBUG'
            $c = Get-ChildItem -Path $store -ErrorAction SilentlyContinue |
                 Where-Object { $_.Thumbprint -ieq $thumb } |
                 Select-Object -First 1
            if ($c) {
                Write-Log "Found certificate in $store"
                return $c
            }
        } catch {
            Write-Log "Error accessing $store $($_.Exception.Message)" 'WARN'
        }
    }
    return $null
}

# =====================================================================
# 6. EXCHANGE HELPERS
# =====================================================================

function Ensure-ExchangePSSession {
    if (Get-Command Import-ExchangeCertificate -ErrorAction SilentlyContinue) { return }
    $ps1 = $env:ExchangeInstallPath
    if ($ps1) { $ps1 = Join-Path $ps1 "bin\RemoteExchange.ps1" }
    if (-not $ps1 -or -not (Test-Path -LiteralPath $ps1)) {
        $ps1 = "C:\Program Files\Microsoft\Exchange Server\V15\bin\RemoteExchange.ps1"
    }
    if (Test-Path -LiteralPath $ps1) {
        . $ps1
        try { Connect-ExchangeServer -auto -ErrorAction Stop | Out-Null; Write-Log "Connected Exchange PS session." 'DIAG' } catch { Write-Log "Connect-ExchangeServer failed: $($_.Exception.Message)" 'WARN' }
    }
    if (-not (Get-Command Import-ExchangeCertificate -ErrorAction SilentlyContinue)) {
        throw "Exchange cmdlets unavailable. Run from EMS or ensure RemoteExchange.ps1 is present."
    }
}

function Classify-RemoteError {
    param([string]$Message)
    if ($Message -match '(?i)access is denied|0x5') { return 'AccessDenied' }
    if ($Message -match '(?i)rpc server is unavailable|0x6ba|winrm|endpoint not found') { return 'Connectivity' }
    if ($Message -match "(?i)couldn.?t be found|not recognized") { return 'NotFound' }
    return 'Other'
}

function Test-CertPresentOnServer {
    param([string]$Server, [string]$Thumb)
    try { $null = Get-ExchangeCertificate -Server $Server -Thumbprint $Thumb -ErrorAction Stop; return $true } catch { return $false }
}

function Test-RemoteExchangeAccess {
    param([string]$Server)
    try {
        $null = Get-ExchangeCertificate -Server $Server -ErrorAction Stop | Select-Object -First 1
        return [pscustomobject]@{ Server=$Server; Access='OK'; Note='Get-ExchangeCertificate succeeded' }
    } catch {
        $msg = $_.Exception.Message
        $kind = Classify-RemoteError -Message $msg
        return [pscustomobject]@{ Server=$Server; Access=$kind; Error=$msg }
    }
}

function Ensure-CertOnServerExchange {
    param(
        [string]$Server,
        [byte[]]$PfxBytes,
        [SecureString]$SecPassword,
        [switch]$EnableIIS
    )
    try {
        # If running locally, omit -Server parameter for speed and reliability
        $imported = if ($Server -ieq $env:COMPUTERNAME -or $Server -ieq 'localhost') {
            Import-ExchangeCertificate -FileData $PfxBytes -Password $SecPassword -PrivateKeyExportable:$true -ErrorAction Stop
        } else {
            Import-ExchangeCertificate -Server $Server -FileData $PfxBytes -Password $SecPassword -PrivateKeyExportable:$true -ErrorAction Stop
        }

        $thumbLocal = $null
        if ($imported -and $imported.Thumbprint) {
            $thumbLocal = $imported.Thumbprint
        } else {
            $thumbLocal = (Get-ExchangeCertificate -Server $Server | Sort-Object NotAfter -Descending | Select-Object -First 1).Thumbprint
        }
        if (-not $thumbLocal) { throw "Import on $Server succeeded but thumbprint couldn't be determined." }

        Enable-ExchangeCertificate -Server $Server -Thumbprint $thumbLocal -Services SMTP -Force | Out-Null
        if ($EnableIIS) { Enable-ExchangeCertificate -Server $Server -Thumbprint $thumbLocal -Services IIS -Force | Out-Null }

        Write-Log "Exchange(remote): '$Server' imported/enabled cert $thumbLocal" 'DEBUG'
        return $true
    } catch {
        $msg = $_.Exception.Message
        $kind = Classify-RemoteError -Message $msg
        Write-Log "Exchange(remote) on '$Server' failed [$kind]: $msg" 'WARN'
        return $false
    }
}

# =====================================================================
# 7. VERIFY HELPERS
# =====================================================================

$script:VerifyResults = New-Object System.Collections.Generic.List[object]

function Add-VerifyResult {
    param([string]$Check, [ValidateSet('OK','WARN','FAIL')][string]$Result = 'OK', [string]$Details = '')
    [void]$script:VerifyResults.Add([pscustomobject]@{ Check=$Check; Result=$Result; Details=$Details })
    $lvl = if ($Result -eq 'OK') { 'INFO' } elseif ($Result -eq 'WARN') { 'WARN' } else { 'ERROR' }
    Write-Log ("{0,-40} {1,-4} {2}" -f $Check, $Result, $Details) $lvl
}

# Token-group inspection: reports membership as materialized in the current
# logon token, which reflects nested and cross-domain group nesting.
function Test-TokenGroupMember {
    param([string]$GroupAccountName)
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $wanted = $GroupAccountName.Trim('\').ToLowerInvariant()
        foreach ($g in $id.Groups) {
            try {
                $name = $g.Translate([Security.Principal.NTAccount]).Value
                if ($name) {
                    $leaf = ($name -split '\\')[-1]
                    if ($leaf -ieq $GroupAccountName -or $name -ieq $GroupAccountName) { return $true }
                    if ($leaf.Trim('\').ToLowerInvariant() -eq $wanted) { return $true }
                }
            } catch {}
        }
    } catch {}
    return $false
}

# Returns $true / $false, or $null when membership cannot be determined
# (group or cmdlet missing on this OS).
function Test-LocalGroupContains {
    param([string]$GroupName)
    if (-not (Get-Command Get-LocalGroupMember -ErrorAction SilentlyContinue)) { return $null }
    $members = $null
    try { $members = @(Get-LocalGroupMember -Group $GroupName -ErrorAction Stop) } catch { return $null }

    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $sidSet = @{}
    foreach ($g in $id.Groups) { try { $sidSet["$($g.Value)"] = $true } catch {} }

    foreach ($m in $members) {
        if ($m.Name -ieq $id.Name) { return $true }
        try { if ($m.SID -and $sidSet.ContainsKey("$($m.SID)")) { return $true } } catch {}
    }
    return $false
}

# =====================================================================
# 8. STAGES
# =====================================================================

function Invoke-SettingsStage {
    param([string]$Path)
    $settings = Initialize-Settings -Path $Path
    Write-Host ""
    Write-Host "Current settings ($($script:WacsSettingsPath)):"
    foreach ($k in $settings.Keys) {
        Write-Host ("  {0,-24} = {1}" -f $k, $settings[$k])
    }
    Write-Host ""
    Write-Log "Settings OK. Next: run 'Import-ExchangeHybrid.ps1 verify' as the service account."
}

function Invoke-InitialStage {
    param([string]$SettingsPath, [string]$WacsPath, [string]$ShareRoot, [string]$Domains, [string]$ApiToken, [string]$PfxPassword)

    $settings = Initialize-Settings -Path $SettingsPath

    $wacsPath  = if ($WacsPath  -and $WacsPath.Trim())  { $WacsPath }  else { [string](Get-SettingValue -Settings $settings -Key 'WacsPath') }
    $shareRoot = if ($ShareRoot -and $ShareRoot.Trim()) { $ShareRoot } else { [string](Get-SettingValue -Settings $settings -Key 'ShareRoot') }
    $domains   = if ($Domains   -and $Domains.Trim())   { $Domains }   else { [string](Get-SettingValue -Settings $settings -Key 'RequiredDomainsCsv') }
    $friendly  = [string](Get-SettingValue -Settings $settings -Key 'FriendlyName')
    $pfxVault  = if ($PfxPassword -and $PfxPassword.Trim()) { $PfxPassword } else { [string](Get-SettingValue -Settings $settings -Key 'PfxPasswordVaultRef') }

    if (-not (Test-Path -LiteralPath $wacsPath)) { throw "wacs.exe not found at '$wacsPath' (settings WacsPath). Install simple-acme or fix the path." }
    if (-not $shareRoot -or -not $domains) { throw "ShareRoot and RequiredDomainsCsv must be set (settings or parameters)." }

    # DNS validation arguments (plugin-agnostic). An explicit -ApiToken only
    # applies to the cloudflare plugin.
    $plugin = [string](Get-SettingValue -Settings $settings -Key 'DnsPlugin')
    if ($ApiToken -and $ApiToken.Trim() -and $plugin.Trim().ToLowerInvariant() -ne 'cloudflare') {
        Write-Log "-ApiToken ignored: DnsPlugin is '$plugin', not 'cloudflare'." 'WARN'
    }
    if ($ApiToken -and $ApiToken.Trim() -and $plugin.Trim().ToLowerInvariant() -eq 'cloudflare') {
        $settings['CloudflareApiToken'] = $ApiToken.Trim()
    }
    $valArgs = Get-WacsValidationArgs -Settings $settings

    $pfxOutDir = Ensure-Folder -Path (Join-Path $shareRoot 'Certs')

    # --script must point at this file, Import-ExchangeHybrid.ps1, with mode 'export' first.
    $hookScript = Join-Path $script:WacsScriptDir 'Import-ExchangeHybrid.ps1'
    if (-not (Test-Path -LiteralPath $hookScript)) { $hookScript = $PSCommandPath }
    $hookParameters = " export -NewCertThumbprint '{CertThumbprint}' -OutputRoot '$shareRoot' -RequiredDomainsCsv '$domains' -ExportPfxPassword '{CachePassword}'"

    $wacsArgs = @(
        '--target',          'manual',
        '--host',            $domains
    ) + $valArgs + @(
        '--store',           'pfxfile',
        '--pfxfilepath',     $pfxOutDir,
        '--pfxpassword',     $pfxVault,

        '--installation',    'script',
        '--script',          $hookScript,
        '--scriptparameters', $hookParameters,

        '--friendlyname',    $friendly,
        '--accepttos',
        '--verbose'
    )

    Write-Log "Creating initial win-acme renewal for: $domains"
    Write-Log "wacs.exe: $wacsPath"
    Write-Log "PFX store: $pfxOutDir ; hook: $hookScript"
    & $wacsPath $wacsArgs
    if ($LASTEXITCODE -ne 0) { throw "wacs.exe failed with exit code $LASTEXITCODE. Check DNS plugin settings (DnsPlugin = '$plugin') and the validation arguments." }
    Write-Log "Initial renewal created. Future renewals run 'export' via the hook, and the scheduled 'import' task deploys."
}

function Invoke-HaRenewStage {
    param([string]$SettingsPath, [string]$WacsPath, [string]$ShareRoot, [string]$Domains, [string]$ApiToken, [string]$PfxPassword)

    $settings = Initialize-Settings -Path $SettingsPath

    $wacsPath  = if ($WacsPath  -and $WacsPath.Trim())  { $WacsPath }  else { [string](Get-SettingValue -Settings $settings -Key 'WacsPath') }
    $domains   = if ($Domains   -and $Domains.Trim())   { $Domains }   else { [string](Get-SettingValue -Settings $settings -Key 'RequiredDomainsCsv') }
    $friendly  = [string](Get-SettingValue -Settings $settings -Key 'FriendlyName')

    if (-not (Test-Path -LiteralPath $wacsPath)) { throw "wacs.exe not found at '$wacsPath' (settings WacsPath)." }

    $plugin = [string](Get-SettingValue -Settings $settings -Key 'DnsPlugin')
    if ($ApiToken -and $ApiToken.Trim() -and $plugin.Trim().ToLowerInvariant() -eq 'cloudflare') {
        $settings['CloudflareApiToken'] = $ApiToken.Trim()
    }
    $valArgs = Get-WacsValidationArgs -Settings $settings

    # 1) Create (or refresh) the renewal definition with no store/installation:
    #    this node was rebuilt; the share holds the artifacts.
    $createArgs = @(
        '--target',        'manual',
        '--host',          $domains
    ) + $valArgs + @(
        '--store',         'none',
        '--installation',  'none',
        '--friendlyname',  $friendly,
        '--accepttos',
        '--verbose'
    )
    Write-Log "Creating renewal definition on rebuilt node for: $domains"
    & $wacsPath $createArgs
    if ($LASTEXITCODE -ne 0) { throw "Renewal creation failed (exit $LASTEXITCODE). Check DNS plugin settings (DnsPlugin = '$plugin')." }

    # 2) Trigger the renewal immediately on the recovered node
    $renewArgs = @('--renew','--force','--verbose','--friendlyname', $friendly)
    Write-Log "Forcing immediate renewal on this node"
    & $wacsPath $renewArgs
    if ($LASTEXITCODE -ne 0) { throw "Forced renewal failed (exit $LASTEXITCODE)." }
    Write-Log "HA renewal complete. The scheduled 'import' task on this node will pick up the new certificate."
}

function Invoke-ExportStage {
    param([string]$SettingsPath, [string]$NewCertThumbprint, [string]$FriendlyName, [string]$OutputRoot, [string]$RequiredDomainsCsv, [string]$SecretsPath, [string]$ExportPfxPassword, [switch]$AllowStoreFallback)

    $settings = Initialize-Settings -Path $SettingsPath

    $shareRoot = if ($OutputRoot -and $OutputRoot.Trim()) { $OutputRoot } else { [string](Get-SettingValue -Settings $settings -Key 'ShareRoot') }
    $domainsCsv = if ($RequiredDomainsCsv -and $RequiredDomainsCsv.Trim()) { $RequiredDomainsCsv } else { [string](Get-SettingValue -Settings $settings -Key 'RequiredDomainsCsv') }
    if (-not $shareRoot -or -not $domainsCsv) { throw "OutputRoot/ShareRoot and RequiredDomainsCsv must be resolvable (parameters or settings)." }

    Write-Log "Thumbprint $NewCertThumbprint"
    if ($FriendlyName) { Write-Log "FriendlyName $FriendlyName" }
    Write-Log "OutputRoot $shareRoot"
    Write-Log "RequiredDomainsCsv $domainsCsv"

    $outRoot    = Ensure-Folder -Path $shareRoot
    $archiveDir = Ensure-Folder -Path (Join-Path $outRoot 'Archive')
    $certsDir   = Ensure-Folder -Path (Join-Path $outRoot 'Certs')

    if (-not $SecretsPath -or -not $SecretsPath.Trim()) {
        $SecretsPath = Join-Path $outRoot ([string](Get-SettingValue -Settings $settings -Key 'SecretsFileName'))
    }
    Write-Log "Secrets path: $SecretsPath"

    $secretsRaw = Load-Secrets -Path $SecretsPath
    $secretEntries = Get-SecretsEntries -Secrets $secretsRaw
    if ($script:WacsDebugOn) {
        $keys = if ($secretEntries) { ($secretEntries | ForEach-Object { $_.Key }) -join ', ' } else { '(none)' }
        Write-Log "secrets keys detected: $keys" 'DEBUG'
    }
    if (-not $secretEntries -or $secretEntries.Count -eq 0) {
        Write-Log "No usable secrets found. Import/export will require -ExportPfxPassword." 'WARN'
    }
    $secretCandidates = Get-SecretPasswordCandidates -Entries $secretEntries

    $requiredDomains = Get-RequiredDomains -Csv $domainsCsv
    Write-Log "Required domains: $($requiredDomains -join ', ')"

    # Tentative base from required domains (prefer non-wildcard; else first entry)
    $tentativeBase = ($requiredDomains | Where-Object { $_ -notmatch '^\*\.' } | Select-Object -First 1)
    if (-not $tentativeBase) { $tentativeBase = ($requiredDomains | Select-Object -First 1) }
    if ($tentativeBase -like '*.*') { $tentativeBase = ($tentativeBase -replace '^\*\.', '') }
    $hasWildcard = (($requiredDomains | Where-Object { $_ -match '^\*\.' }) -ne $null)

    # Acquire the certificate: PFX candidates in wildcard-aware order
    $candidates = Find-PfxCandidates -CertsDir $certsDir -BaseName $tentativeBase -WildcardPresent:$hasWildcard
    if ($script:WacsDebugOn) {
        Write-Log ("PFX candidate order: {0}" -f (($candidates | ForEach-Object { $_.Name }) -join ' | ')) 'DEBUG'
    }

    $cert = $null
    $usedImportPw = $null
    foreach ($file in $candidates) {
        Write-Log "Attempting to import candidate PFX: $($file.FullName)"
        $bytes = [System.IO.File]::ReadAllBytes($file.FullName)
        $pwRef = [ref] $null
        $cert = Import-PfxBytes -Bytes $bytes -CandidatePasswords $secretCandidates -UsedPassword $pwRef
        if ($cert) {
            $usedImportPw = $pwRef.Value
            Write-Log "Imported certificate from candidate PFX"
            break
        } else {
            Write-Log "Failed to import candidate: $($file.Name) with provided secrets" 'WARN'
        }
    }

    # Optional fallback to the Windows cert store by thumbprint
    if (-not $cert -and $AllowStoreFallback -and $NewCertThumbprint) {
        Write-Log "Falling back to certificate store lookup by thumbprint" 'WARN'
        $cert = Get-CertificateFromStores -Thumbprint $NewCertThumbprint
    }

    if (-not $cert) {
        throw "Certificate not found. Could not import from \Certs (and no store fallback allowed)."
    }

    $present = Get-CertDomains -Cert $cert
    Write-Log "Certificate SAN/subjects: $($present -join ', ')"
    $missing = Test-RequiredDomainsPresent -Required $requiredDomains -Present $present
    if ($missing.Count -gt 0) {
        Write-Log "Certificate is missing required SAN(s): $($missing -join ', ')" 'WARN'
    }

    $baseName = Choose-BaseName -Required $requiredDomains -Present $present
    if (-not $baseName) { $baseName = $NewCertThumbprint.ToLower() }
    Write-Log "Base name for files: $baseName"

    $timestamp   = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $archiveBase = Join-Path $archiveDir ("{0}_{1}" -f $baseName, $timestamp)

    # Resolve export password (ParamOverride -> BaseName -> SAN -> default -> import pw)
    if ($script:WacsDebugOn) {
        Write-Log ("Matching keys sought -> BaseName: {0}; SANs: {1}" -f $baseName, ($present -join ', ')) 'DEBUG'
        $paramOverrideFlag = if ([string]::IsNullOrEmpty($ExportPfxPassword)) { 'No' } else { 'Yes' }
        $importPwFlag      = if ([string]::IsNullOrEmpty($usedImportPw))      { 'No' } else { 'Yes' }
        Write-Log ("Password resolution inputs -> BaseName: {0}; ParamOverride: {1}; ImportPwPresent: {2}" -f $baseName, $paramOverrideFlag, $importPwFlag) 'DEBUG'
    }

    $resolvedExportPw = Resolve-PfxPassword -Entries $secretEntries -BaseName $baseName -PresentDomains $present -ParamOverride $ExportPfxPassword -ImportPw $usedImportPw
    if (-not $resolvedExportPw) {
        throw "Export PFX password not found. Provide -ExportPfxPassword or configure a secrets entry (default/BaseName/SAN) in $SecretsPath."
    }

    $pwSource = '(none)'
    if ($ExportPfxPassword) { $pwSource = 'parameter' }
    elseif ($usedImportPw -and $resolvedExportPw -eq $usedImportPw) { $pwSource = 'import password' }
    elseif ($secretEntries) { $pwSource = 'secrets file' }
    Write-Log "Resolved export PFX password source: $pwSource"

    # Paths for artifacts (Archive)
    $archivePfx     = "${archiveBase}.pfx"
    $archiveCer     = "${archiveBase}.cer"
    $archivePem     = "${archiveBase}.pem"
    $archiveFullPem = "${archiveBase}-fullchain.pem"

    Export-PfxWithPassword -Cert $cert -DestPfxPath $archivePfx -Password $resolvedExportPw
    Write-Log "Archived PFX: $archivePfx"

    Export-LeafCer      -Cert $cert -CerPath $archiveCer
    Export-LeafPem      -Cert $cert -PemPath $archivePem
    Export-FullChainPem -Cert $cert -FullChainPemPath $archiveFullPem
    Write-Log "Archived CER/PEM: $archiveCer ; $archivePem ; $archiveFullPem"

    # Copy "current" artifacts to \Certs (overwrite)
    $currentPfx     = Join-Path $certsDir ("{0}.pfx" -f $baseName)
    $currentCer     = Join-Path $certsDir ("{0}.cer" -f $baseName)
    $currentPem     = Join-Path $certsDir ("{0}.pem" -f $baseName)
    $currentFullPem = Join-Path $certsDir ("{0}-fullchain.pem" -f $baseName)

    Copy-Item -LiteralPath $archivePfx     -Destination $currentPfx     -Force
    Copy-Item -LiteralPath $archiveCer     -Destination $currentCer     -Force
    Copy-Item -LiteralPath $archivePem     -Destination $currentPem     -Force
    Copy-Item -LiteralPath $archiveFullPem -Destination $currentFullPem -Force

    Write-Log "Updated current \Certs:"
    Write-Log "  $currentPfx"
    Write-Log "  $currentCer"
    Write-Log "  $currentPem"
    Write-Log "  $currentFullPem"
    Write-Log "Export completed successfully."
}

function Invoke-ImportStage {
    param(
        [string]$SettingsPath, [string]$BaseName, [string]$PfxOverridePath, [string]$Services,
        [switch]$NoHybridUpdates, [string]$SendConnectorName, [string[]]$SendConnectorExact, [switch]$AllSendConnectors,
        [string]$ReceiveConnectorPattern, [switch]$NoCleanup, [switch]$RestartIIS,
        [switch]$StartTranscript, [string]$TranscriptPath
    )

    $settings = Initialize-Settings -Path $SettingsPath
    $shareRoot = [string](Get-SettingValue -Settings $settings -Key 'ShareRoot')
    $baseName  = if ($BaseName -and $BaseName.Trim()) { $BaseName } else { [string](Get-SettingValue -Settings $settings -Key 'BaseName') }
    $services  = if ($Services -and $Services.Trim()) { $Services } else { [string](Get-SettingValue -Settings $settings -Key 'Services') }

    # Transcript (default: <ShareRoot>\Logs\Import-ExchangeHybrid_<host>_<ts>.log)
    if ($StartTranscript) {
        try {
            if (-not $TranscriptPath -or -not $TranscriptPath.Trim()) {
                $logsDir = Join-Path $shareRoot "Logs"
                if (-not (Test-Path -LiteralPath $logsDir)) { New-Item -ItemType Directory -Path $logsDir -Force | Out-Null }
                $ts = (Get-Date).ToString('yyyyMMdd-HHmmss')
                $TranscriptPath = Join-Path $logsDir ("Import-ExchangeHybrid_{0}_{1}.log" -f $env:COMPUTERNAME, $ts)
            }
            Start-Transcript -Path $TranscriptPath -Append | Out-Null
            Write-Log "Transcript started: $TranscriptPath" 'INFO'
        } catch {
            Write-Log "Failed to start transcript: $($_.Exception.Message)" 'WARN'
        }
    }

    try {
        Ensure-ExchangePSSession

        $certsDir = Join-Path $shareRoot 'Certs'

        # Secrets path: settings name, then legacy candidates
        $secretsFile = Join-Path $shareRoot ([string](Get-SettingValue -Settings $settings -Key 'SecretsFileName'))
        if (-not (Test-Path -LiteralPath $secretsFile)) {
            foreach ($cand in @('import.secrets.json','secrets.json')) {
                $p = Join-Path $shareRoot $cand
                if (Test-Path -LiteralPath $p) { $secretsFile = $p; break }
            }
        }
        Write-Log "Secrets path: $secretsFile"

        # Multi-pattern candidate search (simple-acme naming variants)
        if ($PfxOverridePath) {
            if (-not (Test-Path -LiteralPath $PfxOverridePath)) { throw "PFX override file missing: $PfxOverridePath" }
            $candidateFiles = @(Get-Item -LiteralPath $PfxOverridePath -ErrorAction Stop)
            Write-Log "Override path specified: using $PfxOverridePath"
        } else {
            if (-not (Test-Path -LiteralPath $certsDir)) { throw "Certs directory not found: $certsDir" }
            Write-Log "Searching for latest PFX in: $certsDir"
            $patterns = @("$baseName*.pfx", "_.$baseName*.pfx", "*$baseName*.pfx", "*.pfx")
            $candidateFiles = @()
            foreach ($pat in $patterns) {
                $found = Get-ChildItem -Path $certsDir -Filter $pat -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending
                if ($found) { $candidateFiles += $found }
            }
            $candidateFiles = @($candidateFiles | Select-Object -Unique FullName)
        }
        if (-not $candidateFiles -or $candidateFiles.Count -eq 0) {
            throw "No candidate PFX files found under $certsDir matching '$baseName'"
        }

        # Resolve password (BaseName -> default; explicit param handled by Resolve-PfxPassword)
        $secretEntries = Get-SecretsEntries -Secrets (Load-Secrets -Path $secretsFile)
        $pfxPw = Resolve-PfxPassword -Entries $secretEntries -BaseName $baseName
        if (-not $pfxPw) { throw "No PFX password found. Ensure $secretsFile contains Key='$baseName' or Key='default'." }

        # Iterative decryption attempt (resolved password first, then all secret candidates)
        $candidatePws = @($pfxPw)
        foreach ($c in (Get-SecretPasswordCandidates -Entries $secretEntries)) {
            if ($candidatePws -notcontains $c) { $candidatePws += $c }
        }

        $x509 = $null
        $pfxPath = $null
        $bytes = $null
        foreach ($file in $candidateFiles) {
            $filePath = if ($file.FullName) { $file.FullName } else { $file }
            try {
                $testBytes = [System.IO.File]::ReadAllBytes($filePath)
                $pwRef = [ref] $null
                $testCert = Import-PfxBytes -Bytes $testBytes -CandidatePasswords $candidatePws -UsedPassword $pwRef
                if ($testCert) {
                    $bytes = $testBytes
                    $x509 = $testCert
                    $pfxPath = $filePath
                    break
                }
            } catch {
                Write-Log "Failed parsing candidate $filePath with resolved secret. Trying next candidate..." 'DEBUG'
            }
        }
        if (-not $x509) {
            throw "Found PFX candidates under $certsDir, but none could be decrypted using the resolved secret."
        }

        if (-not $ReceiveConnectorPattern -or -not $ReceiveConnectorPattern.Trim()) {
            $ReceiveConnectorPattern = "*Default Frontend $(hostname)*"
        }

        $thumb = $x509.Thumbprint.ToUpperInvariant()
        $cn    = Get-CN -Subject $x509.Subject
        $tlsName = Get-CertTlsName -Cert $x509

        Write-Log "Selected PFX: $pfxPath"
        Write-Log "Thumbprint:   $thumb"
        if ($cn) { Write-Log "Subject CN:   $cn" }
        Write-Log "New TLS name: $tlsName"

        # Settings-driven behaviour switches
        $hybridEnabled  = if ($NoHybridUpdates)  { $false } else { [bool](Get-SettingValue -Settings $settings -Key 'EnableHybridUpdates' $true) }
        $cleanupEnabled = if ($NoCleanup)        { $false } else { [bool](Get-SettingValue -Settings $settings -Key 'CleanupOldCerts'  $true) }
        $restartIIS    = $RestartIIS -or [bool](Get-SettingValue -Settings $settings -Key 'RestartIIS' $false)
        $sendConnName   = if ($SendConnectorName -and $SendConnectorName.Trim()) { $SendConnectorName } else { [string](Get-SettingValue -Settings $settings -Key 'SendConnectorName') }

        # Optional diagnostics pre-flight
        if ($script:WacsDiagnose) {
            Write-Log "Running diagnostics (pre-flight)..." 'DIAG'
            try {
                $srvList = @()
                $sendConnDiag = $null
                try {
                    if ($AllSendConnectors) {
                        $sendConnDiag = Get-SendConnector -ErrorAction Stop
                    } elseif ($SendConnectorExact -and $SendConnectorExact.Count -gt 0) {
                        $sendConnDiag = foreach ($name in $SendConnectorExact) { Get-SendConnector -Identity $name -ErrorAction Stop }
                    } else {
                        $sendConnDiag = Get-SendConnector $sendConnName -ErrorAction Stop
                    }
                } catch { Write-Log "Diagnostic: Get-SendConnector failed: $($_.Exception.Message)" 'WARN' }

                if ($sendConnDiag) {
                    foreach ($sc in $sendConnDiag) { if ($sc.SourceTransportServers) { $srvList += @($sc.SourceTransportServers) } }
                    $srvList = $srvList | Select-Object -Unique
                    if ($srvList.Count -gt 0) {
                        Write-Log ("Diagnostic: Found {0} unique source servers: {1}" -f $srvList.Count, ($srvList -join ', ')) 'DIAG'
                        foreach ($s in $srvList) {
                            $res = Test-RemoteExchangeAccess -Server $s
                            $msg = if ($res.Access -eq 'OK') { 'OK' } else { "$($res.Access): $($res.Error)" }
                            Write-Log ("Diagnostic: Access test for '{0}': {1}" -f $res.Server, $msg) 'DIAG'
                        }
                    }
                }

                if ($hybridEnabled) {
                    try {
                        $hy = Get-HybridConfiguration -ErrorAction Stop
                        $cur = if ($hy -and $hy.TlsCertificateName) { $hy.TlsCertificateName } else { '<null>' }
                        Write-Log "Diagnostic: HybridConfiguration current TLS name: $cur" 'DIAG'
                    } catch {
                        Write-Log "Diagnostic: Get-HybridConfiguration failed: $($_.Exception.Message)" 'WARN'
                    }
                }
            } catch {
                Write-Log "Diagnostics encountered an error: $($_.Exception.Message)" 'WARN'
            }
        }

        # Local Import
        $existing = @(Get-ExchangeCertificate) | Where-Object Thumbprint -eq $thumb
        if (-not $existing) {
            Write-Log "Importing PFX into LocalMachine\My (local)"
            Import-ExchangeCertificate -FileData $bytes -Password (ConvertTo-SecureString -String $pfxPw -AsPlainText -Force) -PrivateKeyExportable:$true | Out-Null
        }
        Write-Log "Enabling services (local): $services"
        Enable-ExchangeCertificate -Thumbprint $thumb -Services $services -Force | Out-Null

        # Hybrid & Connectors
        if ($hybridEnabled) {
            try {
                $currentHybrid = $null
                try { $currentHybrid = Get-HybridConfiguration -ErrorAction Stop } catch {}
                $needsHybrid = $true
                if ($currentHybrid -and $currentHybrid.TlsCertificateName) {
                    if ($currentHybrid.TlsCertificateName -ieq $tlsName) { $needsHybrid = $false; Write-Log "HybridConfiguration already set. Skipping." }
                }
                if ($needsHybrid) {
                    Write-Log "Setting HybridConfiguration -TlsCertificateName to: $tlsName"
                    Set-HybridConfiguration -TlsCertificateName $tlsName -ErrorAction Stop
                    Start-Sleep -Seconds 1
                    try {
                        $post = Get-HybridConfiguration -ErrorAction Stop
                        $postVal = if ($post.TlsCertificateName) { $post.TlsCertificateName } else { '<null>' }
                        if ($postVal -ieq $tlsName) { Write-Log "HybridConfiguration verification successful." 'DEBUG' }
                    } catch {}
                }
            } catch {
                Write-Log "Set-HybridConfiguration failed: $($_.Exception.Message)" 'WARN'
            }

            # Send Connectors
            $sendConnectorsToUpdate = @()
            try {
                if ($AllSendConnectors) {
                    $sendConnectorsToUpdate = Get-SendConnector -ErrorAction Stop
                } elseif ($SendConnectorExact -and $SendConnectorExact.Count -gt 0) {
                    foreach ($name in $SendConnectorExact) {
                        $sc = Get-SendConnector -Identity $name -ErrorAction Stop
                        if ($sc) { $sendConnectorsToUpdate += $sc }
                    }
                } else {
                    $sendConnectorsToUpdate = Get-SendConnector $sendConnName -ErrorAction Stop
                }
            } catch {
                Write-Log "Failed to resolve send connectors: $($_.Exception.Message)" 'WARN'
            }

            if ($sendConnectorsToUpdate -and $sendConnectorsToUpdate.Count -gt 0) {
                foreach ($sc in $sendConnectorsToUpdate) {
                    $currentTls = $null
                    try { $currentTls = $sc.TlsCertificateName } catch {}

                    $srcServers = @()
                    try { $srcServers = @($sc.SourceTransportServers) } catch {}
                    if (-not $srcServers -or $srcServers.Count -eq 0) { $srcServers = @("$(hostname)") }

                    Write-Log ("Connector '{0}' sources: {1}" -f $sc.Name, ($srcServers -join ', '))

                    $missing = @()
                    foreach ($srv in $srcServers) {
                        if (-not (Test-CertPresentOnServer -Server $srv -Thumb $thumb)) {
                            Write-Log "Server '$srv' missing cert; importing via Exchange -Server..."
                            $ok = Ensure-CertOnServerExchange -Server $srv -PfxBytes $bytes -SecPassword (ConvertTo-SecureString -String $pfxPw -AsPlainText -Force)
                            if (-not $ok) { $missing += $srv }
                        }
                    }

                    if ($currentTls -and ($currentTls -ieq $tlsName)) {
                        Write-Log ("Send Connector '{0}': TLS already set. Skipping." -f $sc.Name)
                    } else {
                        $oldShown = if ($null -ne $currentTls -and $currentTls -ne "") { $currentTls } else { "<null>" }
                        Write-Log ("Updating Send Connector '{0}' -TlsCertificateName (old='{1}' -> new='{2}')" -f $sc.Name, $oldShown, $tlsName)
                        try { $sc | Set-SendConnector -TlsCertificateName $tlsName -ErrorAction Stop } catch { Write-Log ("Set-SendConnector '{0}' failed: {1}" -f $sc.Name, $_.Exception.Message) 'WARN' }
                    }
                }
            }

            # Receive Connectors
            Write-Log "Checking Receive Connector '$ReceiveConnectorPattern' -TlsCertificateName"
            try {
                $rcs = @(Get-ReceiveConnector $ReceiveConnectorPattern -ErrorAction Stop)
                foreach ($rc in $rcs) {
                    $rcCurrent = $null
                    try { $rcCurrent = $rc.TlsCertificateName } catch {}
                    if ($rcCurrent -and ($rcCurrent -ieq $tlsName)) {
                        Write-Log ("Receive Connector '{0}': TLS already set. Skipping." -f $rc.Name)
                    } else {
                        $oldRCShown = if ($null -ne $rcCurrent -and $rcCurrent -ne "") { $rcCurrent } else { "<null>" }
                        Write-Log ("Updating Receive Connector '{0}' -TlsCertificateName (old='{1}' -> new='{2}')" -f $rc.Name, $oldRCShown, $tlsName)
                        try { $rc | Set-ReceiveConnector -TlsCertificateName $tlsName -ErrorAction Stop } catch { Write-Log ("Set-ReceiveConnector '{0}' failed: {1}" -f $rc.Name, $_.Exception.Message) 'WARN' }
                    }
                }
            } catch { Write-Log "ReceiveConnector query failed: $($_.Exception.Message)" 'WARN' }
        }

        # Cleanup Old Certs
        if ($cleanupEnabled) {
            Write-Log "Removing older Exchange certificates matching subject (excluding $thumb)"
            try {
                $exNew = $null
                try { $exNew = Get-ExchangeCertificate -Thumbprint $thumb -ErrorAction Stop } catch {}
                $toRemove = @()

                if ($exNew) {
                    $domains = @()
                    if ($exNew.CertificateDomains) {
                        $domains = $exNew.CertificateDomains |
                            ForEach-Object { ($_ -replace '^\*\.', '') } |
                            Where-Object { $_ -and ($_ -match '^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$') } |
                            Select-Object -Unique
                    }
                    if ($domains -and $domains.Count -gt 0) {
                        $cand = $null
                        try { $cand = Get-ExchangeCertificate -DomainName $domains -ErrorAction Stop } catch {}
                        if ($cand) { $toRemove += ($cand | Where-Object { $_.Thumbprint -ne $thumb }) }
                    }
                    if (-not $toRemove -or $toRemove.Count -eq 0) {
                        $subj = $exNew.Subject
                        if ($subj) {
                            $toRemove += (Get-ExchangeCertificate | Where-Object { $_.Thumbprint -ne $thumb -and $_.Subject -eq $subj })
                        }
                    }
                }

                $toRemove = @($toRemove | Select-Object -Unique)
                if ($toRemove -and $toRemove.Count -gt 0) {
                    Write-Log ("Cleanup: removing {0} older certificate(s)" -f $toRemove.Count)
                    $toRemove | ForEach-Object {
                        try { $_ | Remove-ExchangeCertificate -Confirm:$false; Write-Log ("Removed older cert {0}" -f $_.Thumbprint) }
                        catch { Write-Log ("Failed to remove cert {0}: {1}" -f $_.Thumbprint, $_.Exception.Message) 'WARN' }
                    }
                } else {
                    Write-Log "Cleanup: no older matching certificates found."
                }
            } catch { Write-Log "Cleanup failed: $($_.Exception.Message)" 'WARN' }
        }

        if ($restartIIS) {
            Write-Log "Restarting IIS"
            iisreset /noforce | Out-Null
        }

        Write-Log "Import/Configure completed successfully."

    } catch {
        Write-Log "ERROR: $($_.Exception.Message)" 'ERROR'
        if ($script:WacsDebugOn -and $_.ScriptStackTrace) {
            Write-Log "Stack: $($_.ScriptStackTrace)" 'DEBUG'
        }
        throw
    } finally {
        if ($StartTranscript) {
            try { Stop-Transcript | Out-Null } catch {}
        }
    }
}

function Invoke-VerifyStage {
    param([string]$SettingsPath, [string[]]$Servers, [switch]$SkipExchangeChecks)

    $settings = Initialize-Settings -Path $SettingsPath
    $shareRoot = [string](Get-SettingValue -Settings $settings -Key 'ShareRoot')

    Write-Log "Verification starting (read-only checks)."

    # ---------------- Settings ----------------
    Add-VerifyResult -Check 'Settings file' -Result 'OK' -Details $script:WacsSettingsPath

    # ---------------- Share ----------------
    if (Test-Path -LiteralPath $shareRoot) {
        Add-VerifyResult -Check 'Share reachable' -Result 'OK' -Details $shareRoot
        $probePath = Join-Path $shareRoot ('.wacs-verify-probe_{0}' -f (Get-Date -Format 'yyyyMMddHHmmss'))
        try {
            Set-Content -LiteralPath $probePath -Value 'probe' -Encoding ASCII -ErrorAction Stop
            Remove-Item -LiteralPath $probePath -Force -ErrorAction Stop
            Add-VerifyResult -Check 'Share writability' -Result 'OK' -Details 'write/delete probe succeeded'
        } catch {
            Add-VerifyResult -Check 'Share writability' -Result 'FAIL' -Details "cannot write to $shareRoot - grant the service account Modify rights on the share"
        }
    } else {
        Add-VerifyResult -Check 'Share reachable' -Result 'FAIL' -Details "$shareRoot not reachable - check share permissions and network"
    }

    # ---------------- Secrets ----------------
    $secretsFile = Join-Path $shareRoot ([string](Get-SettingValue -Settings $settings -Key 'SecretsFileName'))
    if (Test-Path -LiteralPath $secretsFile) {
        try {
            $entries = Get-SecretsEntries -Secrets (Load-Secrets -Path $secretsFile)
            if ($entries -and $entries.Count -gt 0) {
                Add-VerifyResult -Check 'Secrets file' -Result 'OK' -Details ("$secretsFile ($($entries.Count) entries)")
            } else {
                Add-VerifyResult -Check 'Secrets file' -Result 'WARN' -Details "$secretsFile has no usable entries - import will need an explicit password"
            }
        } catch {
            Add-VerifyResult -Check 'Secrets file' -Result 'FAIL' -Details "$secretsFile cannot be parsed: $($_.Exception.Message)"
        }
    } else {
        Add-VerifyResult -Check 'Secrets file' -Result 'FAIL' -Details "$secretsFile not found - create it (Key/Secret JSON, never in settings)"
    }

    # ---------------- wacs.exe + DNS plugin ----------------
    $wacsPath = [string](Get-SettingValue -Settings $settings -Key 'WacsPath')
    $plugin   = ([string](Get-SettingValue -Settings $settings -Key 'DnsPlugin')).Trim().ToLowerInvariant()
    if (Test-Path -LiteralPath $wacsPath) {
        Add-VerifyResult -Check 'wacs.exe' -Result 'OK' -Details $wacsPath
        $wacsDir = Split-Path -Parent $wacsPath
        switch ($plugin) {
            'cloudflare' {
                $dll = Get-ChildItem -LiteralPath $wacsDir -Filter '*Cloudflare*.dll' -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($dll) {
                    Add-VerifyResult -Check 'DNS plugin (cloudflare)' -Result 'OK' -Details $dll.Name
                } else {
                    Add-VerifyResult -Check 'DNS plugin (cloudflare)' -Result 'FAIL' -Details 'Cloudflare validation plugin DLL not found next to wacs.exe - download it from the simple-acme releases page and unpack it there'
                }
            }
            'script' {
                $create = [string](Get-SettingValue -Settings $settings -Key 'DnsCreateScript')
                if ($create -and (Test-Path -LiteralPath $create)) {
                    Add-VerifyResult -Check 'DNS plugin (script)' -Result 'OK' -Details $create
                    $del = [string](Get-SettingValue -Settings $settings -Key 'DnsDeleteScript')
                    if ($del -and -not (Test-Path -LiteralPath $del)) {
                        Add-VerifyResult -Check 'DNS delete script' -Result 'WARN' -Details "DnsDeleteScript not found: $del"
                    }
                } else {
                    Add-VerifyResult -Check 'DNS plugin (script)' -Result 'FAIL' -Details "DnsCreateScript not found: '$create' - fix settings DnsCreateScript"
                }
            }
            'custom' {
                $raw = [string](Get-SettingValue -Settings $settings -Key 'WacsValidationArgs')
                if ($raw -and $raw.Trim()) {
                    Add-VerifyResult -Check 'DNS plugin (custom)' -Result 'OK' -Details 'raw validation arguments configured'
                } else {
                    Add-VerifyResult -Check 'DNS plugin (custom)' -Result 'FAIL' -Details 'WacsValidationArgs is empty - set raw wacs.exe validation arguments in settings'
                }
            }
        }
    } else {
        Add-VerifyResult -Check 'wacs.exe' -Result 'WARN' -Details "$wacsPath not found - only required on the ACME host"
    }

    # ---------------- Exchange ----------------
    if (-not $SkipExchangeChecks) {
        $haveCmdlets = $true
        foreach ($c in @('Import-ExchangeCertificate','Enable-ExchangeCertificate','Get-ExchangeCertificate','Get-SendConnector','Get-HybridConfiguration')) {
            if (-not (Get-Command $c -ErrorAction SilentlyContinue)) {
                $haveCmdlets = $false
                Add-VerifyResult -Check 'Exchange cmdlets' -Result 'FAIL' -Details "$c unavailable - run from Exchange Management Shell or ensure RemoteExchange.ps1 is present"
            }
        }
        if ($haveCmdlets) { Add-VerifyResult -Check 'Exchange cmdlets' -Result 'OK' -Details 'certificate/connector cmdlets available' }

        if (Test-TokenGroupMember -GroupAccountName 'Exchange Trusted Subsystem') {
            Add-VerifyResult -Check 'Exchange Trusted Subsystem' -Result 'OK' -Details 'membership present in logon token (nested/cross-domain aware)'
        } else {
            Add-VerifyResult -Check 'Exchange Trusted Subsystem' -Result 'FAIL' -Details 'account is not a member (via its token groups) - add the service account to the Exchange Trusted Subsystem group, then start a fresh logon session'
        }

        $localGrp = Test-LocalGroupContains -GroupName 'Exchange Servers'
        if ($localGrp -eq $null) {
            Add-VerifyResult -Check "Local group 'Exchange Servers'" -Result 'WARN' -Details 'cannot be determined on this host (group or cmdlet missing) - topology-dependent'
        } elseif ($localGrp) {
            Add-VerifyResult -Check "Local group 'Exchange Servers'" -Result 'OK' -Details 'account (or a token group) is a member'
        } else {
            Add-VerifyResult -Check "Local group 'Exchange Servers'" -Result 'WARN' -Details 'not a member - required in some multi-domain topologies'
        }

        # Remote Exchange access: explicit -Servers, else derived from send connectors
        $serverList = @()
        if ($Servers -and $Servers.Count -gt 0) {
            $serverList = $Servers
        } elseif ($haveCmdlets) {
            try {
                $sendConnName = [string](Get-SettingValue -Settings $settings -Key 'SendConnectorName')
                $conns = Get-SendConnector $sendConnName -ErrorAction Stop
                foreach ($sc in $conns) { if ($sc.SourceTransportServers) { $serverList += @($sc.SourceTransportServers) } }
                $serverList = @($serverList | Select-Object -Unique)
            } catch {
                Write-Log "Could not derive server list from send connectors: $($_.Exception.Message)" 'WARN'
            }
        }

        if ($serverList.Count -eq 0) {
            Add-VerifyResult -Check 'Remote Exchange access' -Result 'WARN' -Details 'no servers to test (pass -Servers or match a send connector in settings)'
        } else {
            foreach ($srv in $serverList) {
                $res = Test-RemoteExchangeAccess -Server $srv
                if ($res.Access -eq 'OK') {
                    Add-VerifyResult -Check "Remote access: $srv" -Result 'OK' -Details 'Get-ExchangeCertificate succeeded'
                } else {
                    $remedy = switch ($res.Access) {
                        'AccessDenied' { 'verify local Administrator membership and Exchange RBAC on that server' }
                        'Connectivity'  { 'verify WinRM/RPC connectivity and that the server is online' }
                        default        { 'verify the server name and Exchange configuration' }
                    }
                    Add-VerifyResult -Check "Remote access: $srv" -Result 'FAIL' -Details "$($res.Access): $($res.Error) - $remedy"
                }
            }
        }
    }

    # ---------------- Summary ----------------
    Write-Host ""
    $script:VerifyResults | Format-Table -AutoSize
    $failures = @($script:VerifyResults | Where-Object { $_.Result -eq 'FAIL' })

    if ($failures.Count -gt 0) {
        Write-Log "$($failures.Count) check(s) FAILED. Remediation:" 'ERROR'
        foreach ($f in $failures) {
            Write-Log ("  - {0}: {1}" -f $f.Check, $f.Details) 'ERROR'
        }
        Write-Log "Fix the issues above and re-run 'Import-ExchangeHybrid.ps1 verify'." 'ERROR'
        return $false
    }

    Write-Log "All verification checks passed. You are ready to run 'init' (ACME host) and schedule the 'import' task."
    return $true
}

# =====================================================================
# 9. HELP & DISPATCHER
# =====================================================================

function Show-Help {
    Write-Host @"
Import-ExchangeHybrid.ps1 - Let's Encrypt certificate lifecycle manager for Exchange

Usage:
  .\Import-ExchangeHybrid.ps1 <mode> [options]

Modes:
  init        Create the initial win-acme renewal (ACME host, run once)
  export      Post-renewal artifact generation (win-acme hook)
  import      Deploy latest cert across Exchange (scheduled task)
  ha-renew    HA recovery: force immediate renewal on a rebuilt node
  verify      Read-only prerequisite verification (as service account)
  settings    Bootstrap / inspect wacs-settings.json interactively
  help        Show this help

Examples:
  .\Import-ExchangeHybrid.ps1 settings
  .\Import-ExchangeHybrid.ps1 init
  .\Import-ExchangeHybrid.ps1 verify
  .\Import-ExchangeHybrid.ps1 import
  .\Import-ExchangeHybrid.ps1 ha-renew
  .\Import-ExchangeHybrid.ps1 export -NewCertThumbprint "<thumb>" -ExportPfxPassword "<pw>"

Settings: wacs-settings.json next to this script (param > settings > default).
          DnsPlugin: cloudflare | script | custom (no provider is presumed).
Secrets:  export-secrets.json on the share (never in settings).
"@
}

# ---------------- Main ----------------
if ($DebugOn) {
    $script:WacsDebugOn = $true
    $DebugPreference   = 'Continue'
    $VerbosePreference = 'Continue'
}
if ($Diagnose) { $script:WacsDiagnose = $true }

try {
    if (-not $Mode -or $Mode -ieq 'Help') { Show-Help; exit 0 }

    Require-AdminOrSystem

    switch ($Mode.ToLower()) {

        'settings' {
            Invoke-SettingsStage -Path $SettingsPath
            exit 0
        }

        'init' {
            Invoke-InitialStage -SettingsPath $SettingsPath -WacsPath $WacsPath -ShareRoot $ShareRoot -Domains $Domains -ApiToken $ApiToken -PfxPassword $PfxPassword
            exit 0
        }

        'export' {
            Invoke-ExportStage -SettingsPath $SettingsPath -NewCertThumbprint $NewCertThumbprint -FriendlyName $FriendlyName -OutputRoot $OutputRoot -RequiredDomainsCsv $RequiredDomainsCsv -SecretsPath $SecretsPath -ExportPfxPassword $ExportPfxPassword -AllowStoreFallback:$AllowStoreFallback
            exit 0
        }

        'import' {
            Invoke-ImportStage -SettingsPath $SettingsPath -BaseName $BaseName -PfxOverridePath $PfxOverridePath -Services $Services `
                -NoHybridUpdates:$NoHybridUpdates -SendConnectorName $SendConnectorName -SendConnectorExact $SendConnectorExact -AllSendConnectors:$AllSendConnectors `
                -ReceiveConnectorPattern $ReceiveConnectorPattern -NoCleanup:$NoCleanup -RestartIIS:$RestartIIS `
                -StartTranscript:$StartTranscript -TranscriptPath $TranscriptPath
            exit 0
        }

        'ha-renew' {
            Invoke-HaRenewStage -SettingsPath $SettingsPath -WacsPath $WacsPath -ShareRoot $ShareRoot -Domains $Domains -ApiToken $ApiToken -PfxPassword $PfxPassword
            exit 0
        }

        'verify' {
            $ok = Invoke-VerifyStage -SettingsPath $SettingsPath -Servers $Servers -SkipExchangeChecks:$SkipExchangeChecks
            if ($ok) { exit 0 } else { exit 1 }
        }
    }
}
catch {
    Write-Log "ERROR: $($_.Exception.Message)" 'ERROR'
    if ($script:WacsDebugOn -and $_.ScriptStackTrace) {
        Write-Log "Stack: $($_.ScriptStackTrace)" 'DEBUG'
    }
    exit 1
}
