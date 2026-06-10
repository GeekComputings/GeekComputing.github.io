<#
    Exchange (on-prem) checks. -Test scriptblock receives the Exchange context as $ex.
#>

@(
    New-AssessmentCheck -Id 'EXC-001' -Title 'Exchange servers on a supported, patched build' `
        -Category 'Exchange' -Requires Exchange -Severity Critical `
        -Frameworks @{ MS='Exchange Security Updates'; NIST='SI-2'; E8='Patch Applications' } `
        -Rationale 'Exchange is a top target (ProxyLogon/ProxyShell). Out-of-support or unpatched builds are routinely exploited for pre-auth RCE.' `
        -Remediation 'Run the Exchange Health Checker, apply the latest CU + Security Update, and decommission unsupported versions. Subscribe to MSRC advisories.' `
        -Test {
            param($ex)
            # Flag known older builds; in practice compare against the current CU table.
            $stale = @($ex.Servers | Where-Object { $_.AdminDisplayVersion -match 'Build 23(0|1|2|3)' })
            @{ Passed = ($stale.Count -eq 0)
               Evidence = if ($stale) { "Outdated build(s): $($stale.Name -join ', ')." } else { 'All servers on a recent build.' }
               AffectedItems = @($stale.Name) }
        }

    New-AssessmentCheck -Id 'EXC-002' -Title 'Basic authentication is disabled' `
        -Category 'Exchange' -Requires Exchange -Severity High `
        -Frameworks @{ MS='Modern Auth'; NIST='IA-2'; E8='Multi-factor Authentication' } `
        -Rationale 'Basic auth sends reusable credentials and bypasses MFA, making it the primary vector for password spraying against mailboxes.' `
        -Remediation 'Disable Basic auth via authentication policies and enforce Modern Authentication / OAuth. Block legacy protocols (POP/IMAP/EWS basic).' `
        -Test { param($ex) @{ Passed = (-not $ex.BasicAuthEnabled); Evidence = "Basic auth enabled: $($ex.BasicAuthEnabled)." } }

    New-AssessmentCheck -Id 'EXC-003' -Title 'ECP/OWA admin surface not published externally' `
        -Category 'Exchange' -Requires Exchange -Severity High `
        -Frameworks @{ MS='Exchange Hardening'; NIST='SC-7' } `
        -Rationale 'Internet-exposed ECP is the entry point for several Exchange exploit chains. The admin control panel should not be reachable from the internet.' `
        -Remediation 'Restrict ECP to internal/VPN only at the load balancer or via IP restrictions; publish OWA through a reverse proxy with pre-auth.' `
        -Test { param($ex) @{ Passed = (-not $ex.EcpExternallyPublished); Evidence = "ECP externally published: $($ex.EcpExternallyPublished)." } }
)
