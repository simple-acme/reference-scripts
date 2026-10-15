# Import-ExchangeHybrid.ps1

Let's Encrypt certificate lifecycle manager for Exchange hybrid deployments — a single
PowerShell script built on [simple-acme](https://simple-acme.com) (win-acme) with
DNS-01 validation.

This is a consolidation of the former four-script suite (`Wacs-Initial`, `Wacs-Export`,
`Wacs-Import`, `Wacs-HA-Renewal`) into **one script with a mode dispatcher**. Every
former script is now a mode, a new read-only `verify` mode was added, and the shared
helpers are defined once at the top of the file.

## Modes

```powershell
.\Import-ExchangeHybrid.ps1 <mode> [options]
```

| Mode       | Purpose                                                            | Run as / context                          |
|------------|--------------------------------------------------------------------|--------------------------------------------|
| `settings` | Bootstrap or inspect `wacs-settings.json` interactively           | Admin, interactive                         |
| `init`     | Create the initial win-acme renewal and wire the export hook       | Admin on the ACME host, run once           |
| `export`   | Post-renewal artifact generation (PFX/PEM/CER to the share)        | Called by win-acme as a post-install hook |
| `import`   | Deploy the latest certificate across Exchange (IIS/SMTP/IMAP/POP, send/receive connectors, hybrid) | Scheduled task as service account |
| `ha-renew` | HA recovery: force an immediate renewal on a rebuilt node          | Admin on the rebuilt node                  |
| `verify`   | Read-only prerequisite verification                               | Service account, anytime                   |
| `help`     | Show usage help                                                    | —                                          |

Exit codes: `0` = success, `1` = failure.

## Configuration — `wacs-settings.json`

All modes read `wacs-settings.json` located next to the script (override with
`-SettingsPath`). Resolution precedence everywhere:

```
explicit parameter  >  settings file  >  built-in default
```

The file ships with good defaults for every knob the script uses. If the file is
missing or empty **and** the session is interactive, the script prompts once for the
core values — including which DNS validation provider you use — and writes the full
file (all keys included, so every knob stays discoverable). In non-interactive
contexts (scheduled tasks, win-acme hooks) it fails fast with remediation guidance
instead of hanging on a prompt.

| Key                      | Default                                   | Notes                                           |
|--------------------------|-------------------------------------------|-------------------------------------------------|
| `ShareRoot`              | `\\NETWORKDRIVE\Share`                    | Central UNC share for artifacts/secrets          |
| `BaseName`               | `example.com`                             | Base name for cert files & secrets lookup       |
| `RequiredDomainsCsv`     | `*.example.com,example.com`               | SANs the renewal covers                         |
| `FriendlyName`           | `example.com`                             | win-acme renewal friendly name                  |
| `WacsPath`               | `C:\Program Files\simple-acme\wacs.exe`   |                                                 |
| `SecretsFileName`        | `export-secrets.json`                     | Relative to `ShareRoot`                        |
| `Services`              | `IIS,SMTP`                                | Exchange services to enable                    |
| `SendConnectorName`      | `*Outbound to Office 365*`                | Wildcard pattern                                |
| `ReceiveConnectorPattern`| `` (empty)                                | Empty = `*Default Frontend <hostname>*`         |
| `DnsPlugin`              | `cloudflare`                              | `cloudflare` \| `script` \| `custom` — see below |
| `CloudflareApiToken`     | `vault://json/cloudflare-token`          | vault ref; used when `DnsPlugin=cloudflare`    |
| `DnsCreateScript`        | `` (empty)                               | TXT create script path; `DnsPlugin=script`    |
| `DnsDeleteScript`        | `` (empty)                               | optional TXT delete script; `DnsPlugin=script` |
| `DnsCreateScriptArgs`    | `{Identifier} {RecordName} {Token}`      | Argument template for the create script         |
| `DnsDeleteScriptArgs`    | `{Identifier} {RecordName} {Token}`      | Argument template for the delete script         |
| `WacsValidationArgs`    | `` (empty)                               | raw wacs validation args; `DnsPlugin=custom`   |
| `PfxPasswordVaultRef`   | `vault://json/pfx-password`              | vault ref used for `--pfxpassword`             |
| `EnableHybridUpdates`    | `true`                                    | Update hybrid config during import              |
| `CleanupOldCerts`        | `true`                                    | Remove superseded certs during import           |
| `RestartIIS`             | `false`                                   | Optional IIS restart after import               |

## DNS validation — no provider presumed

`init` and `ha-renew` build their DNS-01 validation arguments from the `DnsPlugin`
setting. The choice is made **once**, in the interactive `settings` bootstrap; the
renewal stages themselves never prompt.

- **`cloudflare`** — the simple-acme Cloudflare plugin (a separate download; unpack
  the plugin DLLs next to `wacs.exe`). Token is referenced by vault URI via
  `CloudflareApiToken`. `verify` checks the plugin DLL is actually installed.
- **`script`** — the simple-acme generic script plugin, for providers without a
  native plugin (OVH, and many others). Point `DnsCreateScript` (and optionally
  `DnsDeleteScript`) at provider scripts; argument templates are configurable.
  Provider credentials stay in the script's own configuration — never in this
  settings file.
- **`custom`** — a raw `WacsValidationArgs` string (space-separated) appended
  verbatim to the wacs.exe command line, covering any other plugin
  (Azure DNS, Route53, acme-dns, …). Use `vault://` references for any secrets.

## Secrets — never in settings

Actual secret values **never** go in `wacs-settings.json`; only vault references
(`vault://...`) do. Passwords live in `export-secrets.json` on the share root.

Canonical shape:

```json
[
  { "Key": "default",      "Secret": "..." },
  { "Key": "example.com",  "Secret": "..." }
]
```

A legacy object-map shape (`{ "default": { "pfxPassword": "..." } }`) is still
accepted for backwards compatibility. Export password resolution order:
explicit override → `BaseName` key → any SAN key → `default` key → the password
that imported the source PFX.

## Workflow

```
┌─────────────┐   ┌──────┐   ┌──────────────────────┐   ┌─────────────────────┐
│ settings    │→ │ init │→ │ win-acme renewals    │→ │ import              │
│ (bootstrap) │   │      │   │ + export hook        │   │ (scheduled task)     │
└─────────────┘   └──────┘   └──────────────────────┘   └─────────────────────┘
                       │                                       ↑
                       └── verify (service account, anytime) ──┘
                       └── ha-renew (rebuilt HA node, as needed) ─┘
```

1. **Bootstrap** — run `.\Import-ExchangeHybrid.ps1 settings` once on the ACME host;
   answer the core prompts (ShareRoot, BaseName, SANs, FriendlyName, WacsPath) and
   pick your DNS validation plugin.
2. **Verify** — run `.\Import-ExchangeHybrid.ps1 verify` **as the service account** on
   each Exchange server. Checks (read-only): settings/secrets parseability, share
   writability probe, wacs.exe + DNS plugin presence (cloudflare DLL or script paths),
   Exchange cmdlets, Exchange Trusted Subsystem membership (token-group aware, handles
   nested/cross-domain groups), local `Exchange Servers` group, and remote Exchange
   access. Exits `1` with remediation text on any failure.
3. **Initial renewal** — run `.\Import-ExchangeHybrid.ps1 init`. This creates the
   win-acme renewal with your configured DNS-01 plugin and registers this script
   itself as the post-install hook.
4. **Automated lifecycle** — every subsequent win-acme renewal fires the `export` hook
   (fresh PFX/PEM/CER to the share); the scheduled `import` task deploys the new cert
   across Exchange.
5. **HA recovery** — on a rebuilt node, run `.\Import-ExchangeHybrid.ps1 ha-renew` to
   force an immediate renewal and rejoin the rotation.

### win-acme hook wiring (registered by `init`)

```
--script            <path-to>\Import-ExchangeHybrid.ps1
--scriptparameters  export -NewCertThumbprint '{CertThumbprint}' -OutputRoot '\\NETWORKDRIVE\Share' -RequiredDomainsCsv '*.example.com,example.com' -ExportPfxPassword '{CachePassword}'
```

### Scheduled import task (example)

```powershell
schtasks /Create /TN "Import-ExchangeHybrid" /SC DAILY /ST 03:30 `
  /TR "powershell.exe -NoProfile -ExecutionPolicy Bypass -File \"C:\Scripts\Import-ExchangeHybrid.ps1\" import" `
  /RU CONTOSO\svc-wacs /RP /RL HIGHEST
```

The import task runs with **no parameters** — everything comes from
`wacs-settings.json`.

## Service account (tenant-provisioned, not automated by this script)

- Local Administrator on all Exchange servers
- Member of `Exchange Trusted Subsystem` (and, where required by your topology, the
  local `Exchange Servers` group on each node)
- Exchange RBAC rights to manage certificates and connectors

The script **verifies** these (via the `verify` mode) but never provisions them.

## Consolidation notes

- One script, not a module: six `Invoke-*Stage` functions plus consolidated shared
  helpers (settings engine, logging, secrets normalization, PFX discovery/import,
  Exchange session/error classification, PEM/CER export, DNS-plugin argument builder)
  defined once at the top.
- Supersedes the legacy positional hook invocation; the mode keyword (`export`) is now
  always the first argument.
- Legacy secrets shapes and underscore-prefixed PFX names (`_.example.com.pfx`) remain
  supported for backwards compatibility.
