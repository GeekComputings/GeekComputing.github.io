<#
.SYNOPSIS
    Read-only security posture assessment for Windows Server, Active Directory,
    Exchange (on-prem) and Microsoft 365 / Entra ID.

.DESCRIPTION
    Collects configuration state from the selected targets, evaluates it against
    a library of data-driven checks (mapped to CIS, Microsoft Security Baselines,
    NIST 800-53 and ASD Essential 8) and produces a prioritised gap report with
    remediation guidance. Nothing is changed on the targets.

.PARAMETER Target
    One or more of: AD, WindowsServer, Exchange, M365. Defaults to all.

.PARAMETER Demo
    Run against bundled synthetic data - no live environment required. Useful for
    demos, screenshots and validating the engine.

.PARAMETER OutputPath
    Directory for the generated report(s). Defaults to ./reports.

.PARAMETER Format
    One or more of: HTML, JSON, CSV. Defaults to HTML.

.EXAMPLE
    .\Invoke-SecurityAssessment.ps1 -Demo

.EXAMPLE
    .\Invoke-SecurityAssessment.ps1 -Target AD,WindowsServer -Format HTML,JSON
#>
[CmdletBinding()]
param(
    [ValidateSet('AD','WindowsServer','Exchange','M365')]
    [string[]]$Target = @('AD','WindowsServer','Exchange','M365'),

    [switch]$Demo,

    [string]$OutputPath = (Join-Path $PSScriptRoot 'reports'),

    [ValidateSet('HTML','JSON','CSV')]
    [string[]]$Format = @('HTML'),

    [string]$EnvironmentName = 'Assessed Environment'
)

$ErrorActionPreference = 'Stop'

# --- Load modules -----------------------------------------------------------
. (Join-Path $PSScriptRoot 'src/Engine.ps1')
. (Join-Path $PSScriptRoot 'src/Collectors.ps1')
. (Join-Path $PSScriptRoot 'src/Report.ps1')

# --- Load checks ------------------------------------------------------------
$checks = @()
foreach ($file in Get-ChildItem -Path (Join-Path $PSScriptRoot 'checks') -Filter '*.checks.ps1') {
    $checks += & $file.FullName
}
Write-Host "Loaded $($checks.Count) checks." -ForegroundColor Cyan

# --- Collect ----------------------------------------------------------------
$context = @{}
if ($Demo) {
    Write-Host 'Running in DEMO mode (synthetic data).' -ForegroundColor Yellow
    $context = Get-DemoContext
}
else {
    if ($Target -contains 'AD')            { $context['AD']            = Get-ADContext }
    if ($Target -contains 'WindowsServer') { $context['WindowsServer'] = Get-WindowsServerContext }
    if ($Target -contains 'Exchange')      { $context['Exchange']      = Get-ExchangeContext }
    if ($Target -contains 'M365')          { $context['M365']          = Get-M365Context }
}

# Only evaluate checks whose target was requested.
$activeChecks = $checks | Where-Object { $_.Requires -in $Target -or $Demo }

# --- Evaluate ---------------------------------------------------------------
$findings = Invoke-AssessmentChecks -Checks $activeChecks -Context $context
$summary  = Get-AssessmentSummary -Findings $findings

# --- Console summary --------------------------------------------------------
Write-Host ''
Write-Host "Posture score: $($summary.Score)/100 (Grade $($summary.Grade))" -ForegroundColor Cyan
Write-Host ("Critical {0}  High {1}  Medium {2}  Low {3}  Passed {4}  NotAssessed {5}" -f `
    $summary.Critical, $summary.High, $summary.Medium, $summary.Low, $summary.Passed, $summary.NotAssessed)

# --- Export -----------------------------------------------------------------
if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'

if ($Format -contains 'HTML') {
    $p = Join-Path $OutputPath "assessment-$stamp.html"
    New-HtmlReport -Findings $findings -Summary $summary -Path $p -Environment $EnvironmentName | Out-Null
    Write-Host "HTML report: $p" -ForegroundColor Green
}
if ($Format -contains 'JSON') {
    $p = Join-Path $OutputPath "assessment-$stamp.json"
    [pscustomobject]@{ Summary = $summary; Findings = $findings } | ConvertTo-Json -Depth 6 | Out-File $p -Encoding utf8
    Write-Host "JSON report: $p" -ForegroundColor Green
}
if ($Format -contains 'CSV') {
    $p = Join-Path $OutputPath "assessment-$stamp.csv"
    $findings | Select-Object Id,Category,Severity,Status,Title,Evidence,Remediation |
        Export-Csv -Path $p -NoTypeInformation -Encoding utf8
    Write-Host "CSV report: $p" -ForegroundColor Green
}

# Return findings for pipeline use.
$findings
