<#
    Active Directory checks. Each returns a check object via New-AssessmentCheck.
    The -Test scriptblock receives the AD context hashtable as $ad.
#>

@(
    New-AssessmentCheck -Id 'AD-001' -Title 'KRBTGT password rotated within 180 days' `
        -Category 'Active Directory' -Requires AD -Severity High `
        -Frameworks @{ MS='Securing Privileged Access'; NIST='IA-5'; E8='Restrict Admin Privileges' } `
        -Rationale 'A stale KRBTGT password makes Golden Ticket attacks viable and long-lived. It should be rotated (twice) on a schedule and after any DA compromise.' `
        -Remediation 'Rotate the KRBTGT account password twice, allowing replication between resets. Use the Microsoft New-KrbtgtKeys.ps1 script. Schedule rotation every 180 days.' `
        -Test {
            param($ad)
            $age = (New-TimeSpan -Start $ad.KrbtgtPasswordLastSet -End (Get-Date)).Days
            @{ Passed = ($age -le 180); Evidence = "KRBTGT password last set $age days ago." }
        }

    New-AssessmentCheck -Id 'AD-002' -Title 'Privileged group membership is minimal' `
        -Category 'Active Directory' -Requires AD -Severity High `
        -Frameworks @{ CIS='5.x'; MS='Tiered Admin Model'; E8='Restrict Admin Privileges' } `
        -Rationale 'Excess members in Domain/Enterprise Admins expand the blast radius of a single credential compromise. Service and helpdesk accounts rarely need this tier.' `
        -Remediation 'Remove standing membership from Domain/Enterprise Admins. Adopt a tiered admin model, use PAM/JIT elevation, and dedicated admin accounts (no service accounts).' `
        -Test {
            param($ad)
            $da = @($ad.PrivilegedGroups['Domain Admins'])
            $ea = @($ad.PrivilegedGroups['Enterprise Admins'])
            $over = ($da.Count -gt 5) -or ($ea.Count -gt 3)
            @{ Passed = (-not $over)
               Evidence = "Domain Admins: $($da.Count), Enterprise Admins: $($ea.Count)."
               AffectedItems = $da }
        }

    New-AssessmentCheck -Id 'AD-003' -Title 'No accounts with unconstrained delegation' `
        -Category 'Active Directory' -Requires AD -Severity Critical `
        -Frameworks @{ MS='Securing Privileged Access'; NIST='AC-6' } `
        -Rationale 'Unconstrained delegation lets a compromised host impersonate any user that authenticates to it, including Domain Admins - a direct path to domain takeover.' `
        -Remediation 'Replace unconstrained delegation with constrained or resource-based constrained delegation. Mark sensitive accounts "Account is sensitive and cannot be delegated".' `
        -Test {
            param($ad)
            $hosts = @($ad.UnconstrainedDelegation)
            @{ Passed = ($hosts.Count -eq 0)
               Evidence = "$($hosts.Count) host(s) configured for unconstrained delegation."
               AffectedItems = $hosts }
        }

    New-AssessmentCheck -Id 'AD-004' -Title 'MachineAccountQuota is set to 0' `
        -Category 'Active Directory' -Requires AD -Severity Medium `
        -Frameworks @{ MS='Hardening AD'; NIST='AC-3' } `
        -Rationale 'The default quota of 10 lets any authenticated user create computer accounts, enabling attacks such as RBCD and noPac/sAMAccountName spoofing.' `
        -Remediation 'Set ms-DS-MachineAccountQuota to 0 and delegate computer-account creation to a dedicated group.' `
        -Test {
            param($ad)
            @{ Passed = ($ad.MachineAccountQuota -eq 0)
               Evidence = "ms-DS-MachineAccountQuota = $($ad.MachineAccountQuota)." }
        }

    New-AssessmentCheck -Id 'AD-005' -Title 'Domain password policy meets baseline' `
        -Category 'Active Directory' -Requires AD -Severity Medium `
        -Frameworks @{ CIS='1.1.x'; NIST='IA-5'; E8='Multi-factor / Passphrases' } `
        -Rationale 'Short or non-complex passwords are trivially brute-forced or sprayed. A minimum length of 14 with lockout reduces guessing.' `
        -Remediation 'Set minimum password length to 14+, enable complexity, and configure an account lockout threshold (e.g. 10 attempts). Prefer passphrases and MFA.' `
        -Test {
            param($ad)
            $ok = ($ad.MinPasswordLength -ge 14) -and $ad.PasswordComplexity -and ($ad.LockoutThreshold -gt 0)
            @{ Passed = $ok
               Evidence = "MinLength=$($ad.MinPasswordLength), Complexity=$($ad.PasswordComplexity), Lockout=$($ad.LockoutThreshold)." }
        }

    New-AssessmentCheck -Id 'AD-006' -Title 'No reversible password encryption' `
        -Category 'Active Directory' -Requires AD -Severity High `
        -Frameworks @{ CIS='1.1.x'; NIST='IA-5' } `
        -Rationale 'Reversible encryption stores passwords in a recoverable form, equivalent to cleartext for an attacker with directory access.' `
        -Remediation 'Disable "Store password using reversible encryption" on all accounts and the domain policy, then force a password reset for affected users.' `
        -Test {
            param($ad)
            $u = @($ad.ReversibleEncryption)
            @{ Passed = ($u.Count -eq 0); Evidence = "$($u.Count) account(s) with reversible encryption."; AffectedItems = $u }
        }

    New-AssessmentCheck -Id 'AD-007' -Title 'LAPS deployed for local admin passwords' `
        -Category 'Active Directory' -Requires AD -Severity Medium `
        -Frameworks @{ MS='LAPS'; E8='Restrict Admin Privileges'; NIST='AC-6' } `
        -Rationale 'Without LAPS, local Administrator passwords are often shared/identical across machines, enabling lateral movement via pass-the-hash.' `
        -Remediation 'Deploy Windows LAPS (built into modern Windows) to randomise and rotate local admin passwords, stored encrypted in AD.' `
        -Test {
            param($ad)
            @{ Passed = [bool]$ad.LapsDeployed; Evidence = "LAPS schema/deployment present: $($ad.LapsDeployed)." }
        }

    New-AssessmentCheck -Id 'AD-008' -Title 'Stale enabled accounts are disabled' `
        -Category 'Active Directory' -Requires AD -Severity Low `
        -Frameworks @{ CIS='5.x'; NIST='AC-2' } `
        -Rationale 'Enabled accounts unused for 90+ days are prime targets for password spraying and go unnoticed if compromised.' `
        -Remediation 'Disable accounts inactive for 90+ days after verification, then remove after a retention window. Automate with a scheduled review.' `
        -Test {
            param($ad)
            $s = @($ad.StaleAccounts)
            @{ Passed = ($s.Count -eq 0); Evidence = "$($s.Count) enabled account(s) inactive >90 days."; AffectedItems = $s }
        }
)
