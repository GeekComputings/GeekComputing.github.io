<#
    Microsoft 365 / Entra ID checks. -Test scriptblock receives the M365 context as $m.
#>

@(
    New-AssessmentCheck -Id 'M365-001' -Title 'Legacy authentication is blocked' `
        -Category 'M365 / Entra ID' -Requires M365 -Severity Critical `
        -Frameworks @{ MS='Identity Secure Score'; NIST='IA-2'; E8='Multi-factor Authentication' } `
        -Rationale 'Legacy auth protocols cannot enforce MFA and account for the bulk of successful password-spray compromises in Entra ID.' `
        -Remediation 'Create a Conditional Access policy blocking legacy authentication clients for all users, or enable Security Defaults.' `
        -Test {
            param($m)
            $ok = $m.LegacyAuthBlocked -or $m.SecurityDefaults
            @{ Passed = $ok; Evidence = "LegacyAuthBlocked=$($m.LegacyAuthBlocked), SecurityDefaults=$($m.SecurityDefaults)." }
        }

    New-AssessmentCheck -Id 'M365-002' -Title 'MFA enforced for privileged roles' `
        -Category 'M365 / Entra ID' -Requires M365 -Severity Critical `
        -Frameworks @{ MS='Identity Secure Score'; NIST='IA-2(1)'; E8='Multi-factor Authentication' } `
        -Rationale 'Admin accounts without enforced MFA are the highest-value target in the tenant. Report-only CA policies do not protect anything.' `
        -Remediation 'Enforce MFA for all admin roles via a Conditional Access policy in "enabled" state (not report-only). Prefer phishing-resistant methods.' `
        -Test {
            param($m)
            $enforced = @($m.ConditionalAccess | Where-Object { $_.State -eq 'enabled' -and $_.DisplayName -match 'MFA' })
            @{ Passed = ($enforced.Count -gt 0)
               Evidence = if ($enforced) { 'An enforced MFA CA policy is present.' } else { 'No enforced MFA policy (report-only or missing).' } }
        }

    New-AssessmentCheck -Id 'M365-003' -Title 'Global Administrator count is minimal' `
        -Category 'M365 / Entra ID' -Requires M365 -Severity High `
        -Frameworks @{ MS='Identity Secure Score'; NIST='AC-6'; E8='Restrict Admin Privileges' } `
        -Rationale 'Microsoft recommends fewer than 5 Global Admins. Excess GAs widen the blast radius and complicate monitoring.' `
        -Remediation 'Reduce Global Admins to <5 break-glass/named accounts. Use least-privilege roles and Privileged Identity Management (PIM) for just-in-time elevation.' `
        -Test {
            param($m)
            @{ Passed = ($m.GlobalAdminCount -lt 5); Evidence = "Global Administrators: $($m.GlobalAdminCount)." }
        }

    New-AssessmentCheck -Id 'M365-004' -Title 'A baseline of Conditional Access is configured' `
        -Category 'M365 / Entra ID' -Requires M365 -Severity Medium `
        -Frameworks @{ MS='Zero Trust'; NIST='AC-3'; E8='Multi-factor Authentication' } `
        -Rationale 'Without Conditional Access (or Security Defaults), access is governed only by passwords - no device, location, or risk controls.' `
        -Remediation 'Implement baseline CA policies: require MFA, block legacy auth, require compliant/hybrid-joined devices for sensitive apps.' `
        -Test {
            param($m)
            $hasEnabled = @($m.ConditionalAccess | Where-Object State -eq 'enabled').Count -gt 0
            @{ Passed = ($hasEnabled -or $m.SecurityDefaults); Evidence = "Enabled CA policies present: $hasEnabled; Security Defaults: $($m.SecurityDefaults)." }
        }
)
