# SecurityAssessment

A read-only PowerShell tool that assesses the security posture of a Microsoft
estate — **Windows Server, Active Directory, Exchange (on-prem), SQL Server and
Microsoft 365 / Entra ID** — and produces a prioritised gap report with
remediation guidance, plus an **infrastructure inventory** (server hardware/OS
specs, Exchange topology, SQL instances) so the report shows exactly what was
assessed.

Findings are mapped to **CIS Benchmarks**, **Microsoft Security Baselines**,
**NIST 800-53** and **ASD Essential 8**.

> Nothing is changed on the targets. Every collector is read-only. Always review
> findings in context before remediating.

## Why PowerShell

Every target is Microsoft, and PowerShell is the native administrative
interface for all of them (the `ActiveDirectory`, `ExchangeManagement`,
`Microsoft.Graph` and CIM modules). It runs agentless with the credentials an
admin already has and emits structured objects that map cleanly to a report.

## Quick start

```powershell
# No live environment needed — runs against bundled synthetic data
.\Invoke-SecurityAssessment.ps1 -Demo

# Assess specific targets, multiple output formats
.\Invoke-SecurityAssessment.ps1 -Target AD,WindowsServer -Format HTML,JSON

# Assess everything (default), name the environment in the report
.\Invoke-SecurityAssessment.ps1 -EnvironmentName "corp.contoso.com"
```

Reports are written to `./reports` (HTML by default; JSON and CSV optional).

## How it works

```
 Collectors            Engine                 Reporting
 ───────────           ──────                 ─────────
 Get-ADContext      ─┐                      ┌─►  HTML dashboard (incl. infra inventory)
 Get-Windows...     ─┤                      │
 Get-Exchange...    ─┼─►  $Context  ─►  checks/*.checks.ps1  ─┼─►  JSON
 Get-M365Context    ─┤    (hashtable)   (data-driven rules)   ├─►  CSV
 Get-SqlContext     ─┤                                        └─►  console summary
 Get-ServerInventory─┘
```

1. **Collectors** (`src/Collectors.ps1`) gather read-only state from each
   target into a `$Context` hashtable. If a module/credential is missing the
   collector returns `$null` and those checks are reported as **NotAssessed**
   rather than failing the run.
2. **Checks** (`checks/*.checks.ps1`) are data, not code paths. Each declares
   an ID, severity, framework references, rationale, remediation and a `-Test`
   scriptblock. The **engine** (`src/Engine.ps1`) runs every check against the
   context and scores the result.
3. **Reporting** (`src/Report.ps1`) renders a self-contained HTML report plus
   optional JSON/CSV.

## Adding a check

Drop it into the relevant `checks/*.checks.ps1` file:

```powershell
New-AssessmentCheck -Id 'AD-009' -Title 'Guest account is disabled' `
    -Category 'Active Directory' -Requires AD -Severity Low `
    -Frameworks @{ CIS='1.x'; NIST='AC-2' } `
    -Rationale 'The built-in Guest account is a well-known anonymous foothold.' `
    -Remediation 'Disable the Guest account via Default Domain Policy.' `
    -Test {
        param($ad)
        @{ Passed = (-not $ad.GuestEnabled); Evidence = "Guest enabled: $($ad.GuestEnabled)." }
    }
```

Then make sure the collector populates the field(s) your `-Test` reads.

## Current check coverage (v1)

| Module | Checks | Examples |
|--------|--------|----------|
| Active Directory | 8 | KRBTGT age, privileged group sprawl, unconstrained delegation, MachineAccountQuota, password policy, reversible encryption, LAPS, stale accounts |
| Windows Server | 6 | SMBv1, RDP NLA, host firewall, legacy TLS, patch age, local admins |
| Exchange (on-prem) | 3 | build/patch level, basic auth, ECP exposure |
| M365 / Entra ID | 4 | legacy auth, admin MFA enforcement, Global Admin count, Conditional Access baseline |
| SQL Server | 5 | supported/patched build, auth mode, sa account, xp_cmdshell, backup recency |

The HTML report also opens with an **Infrastructure & Specifications** section:
per-server OS/CPU/RAM/disk/uptime, Exchange servers (version, roles, edition,
mailbox databases) and SQL instances (version, edition, auth mode, databases).

## Requirements

- PowerShell 5.1+ or PowerShell 7+
- For live collection: the relevant RSAT/AD module, Exchange Management Shell,
  `Microsoft.Graph` (run `Connect-MgGraph` first for M365) and the `SqlServer`
  module for SQL checks (`-SqlInstance` selects the instance). `-Demo` needs
  none of these.

## Roadmap

- Build/CVE comparison tables for Exchange and Windows (live version lookup)
- BloodHound-style AD attack-path summary
- Per-finding "remediation script" snippets
- Linux/SSH collectors and CIS Linux checks
- Scheduled runs with trend/delta reporting
