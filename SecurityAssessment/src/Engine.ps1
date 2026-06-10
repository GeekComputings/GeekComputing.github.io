<#
    Engine.ps1
    Core findings engine: defines findings, runs data-driven checks against a
    collected context, and scores the overall posture.

    Design: collectors produce a $Context hashtable keyed by domain
    ('AD','WindowsServer','Exchange','M365'). Each check declares the context
    key it needs via -Requires and supplies a -Test scriptblock that receives
    that data and returns either a [bool] or a hashtable:
        @{ Passed = $true/$false; Evidence = '...'; AffectedItems = @(...) }
#>

$script:SeverityWeight = [ordered]@{
    Critical = 40
    High     = 20
    Medium   = 8
    Low      = 3
    Info     = 0
}

$script:SeverityOrder = @{ Critical = 0; High = 1; Medium = 2; Low = 3; Info = 4 }

function New-AssessmentCheck {
    <# Factory used inside checks/*.checks.ps1 to keep definitions terse. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][ValidateSet('AD','WindowsServer','Exchange','M365')][string]$Requires,
        [Parameter(Mandatory)][ValidateSet('Critical','High','Medium','Low','Info')][string]$Severity,
        [Parameter(Mandatory)][string]$Rationale,
        [Parameter(Mandatory)][string]$Remediation,
        [hashtable]$Frameworks = @{},
        [Parameter(Mandatory)][scriptblock]$Test
    )
    [pscustomobject]@{
        Id          = $Id
        Title       = $Title
        Category    = $Category
        Requires    = $Requires
        Severity    = $Severity
        Rationale   = $Rationale
        Remediation = $Remediation
        Frameworks  = $Frameworks
        Test        = $Test
    }
}

function New-Finding {
    param(
        [Parameter(Mandatory)]$Check,
        [Parameter(Mandatory)][ValidateSet('Pass','Fail','NotAssessed','Error')][string]$Status,
        [string]$Evidence,
        [string[]]$AffectedItems = @()
    )
    [pscustomobject]@{
        Id            = $Check.Id
        Title         = $Check.Title
        Category      = $Check.Category
        Severity      = $Check.Severity
        Status        = $Status
        Evidence      = $Evidence
        AffectedItems = $AffectedItems
        Rationale     = $Check.Rationale
        Remediation   = $Check.Remediation
        Frameworks    = $Check.Frameworks
    }
}

function Invoke-AssessmentChecks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Checks,
        [Parameter(Mandatory)][hashtable]$Context
    )

    $findings = foreach ($check in $Checks) {
        $data = $Context[$check.Requires]
        if ($null -eq $data) {
            New-Finding -Check $check -Status NotAssessed `
                -Evidence "Target '$($check.Requires)' was not collected (module/credentials unavailable)."
            continue
        }

        try {
            $result = & $check.Test $data

            if ($result -is [bool]) {
                $passed = $result
                $evidence = $null
                $affected = @()
            }
            else {
                $passed   = [bool]$result.Passed
                $evidence = $result.Evidence
                $affected = @($result.AffectedItems)
            }

            New-Finding -Check $check -Status ($(if ($passed) { 'Pass' } else { 'Fail' })) `
                -Evidence $evidence -AffectedItems $affected
        }
        catch {
            New-Finding -Check $check -Status Error -Evidence $_.Exception.Message
        }
    }

    $findings
}

function Get-AssessmentSummary {
    param([Parameter(Mandatory)][object[]]$Findings)

    $assessed = $Findings | Where-Object Status -in 'Pass','Fail'
    $failed   = $assessed | Where-Object Status -eq 'Fail'

    # Posture score: start at 100, subtract weighted penalty for failures,
    # normalised against the maximum penalty that was actually assessable.
    $maxPenalty = 0
    foreach ($f in $assessed) { $maxPenalty += $script:SeverityWeight[$f.Severity] }
    $lostPenalty = 0
    foreach ($f in $failed)   { $lostPenalty += $script:SeverityWeight[$f.Severity] }

    $score = if ($maxPenalty -gt 0) {
        [math]::Round((1 - ($lostPenalty / $maxPenalty)) * 100)
    } else { 100 }

    $grade = switch ($score) {
        { $_ -ge 90 } { 'A'; break }
        { $_ -ge 80 } { 'B'; break }
        { $_ -ge 70 } { 'C'; break }
        { $_ -ge 60 } { 'D'; break }
        default       { 'F' }
    }

    [pscustomobject]@{
        Score        = $score
        Grade        = $grade
        Total        = $Findings.Count
        Passed       = ($assessed | Where-Object Status -eq 'Pass').Count
        Failed       = $failed.Count
        NotAssessed  = ($Findings | Where-Object Status -eq 'NotAssessed').Count
        Errors       = ($Findings | Where-Object Status -eq 'Error').Count
        Critical     = ($failed | Where-Object Severity -eq 'Critical').Count
        High         = ($failed | Where-Object Severity -eq 'High').Count
        Medium       = ($failed | Where-Object Severity -eq 'Medium').Count
        Low          = ($failed | Where-Object Severity -eq 'Low').Count
        GeneratedAt  = (Get-Date)
    }
}

function Sort-FindingsByRisk {
    param([Parameter(Mandatory)][object[]]$Findings)
    # Fails first, then by severity, then by id.
    $Findings | Sort-Object `
        @{ Expression = { if ($_.Status -eq 'Fail') { 0 } else { 1 } } },
        @{ Expression = { $script:SeverityOrder[$_.Severity] } },
        Id
}
