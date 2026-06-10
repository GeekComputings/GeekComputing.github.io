<#
    Windows Server checks. -Test scriptblock receives the WindowsServer context as $w.
#>

@(
    New-AssessmentCheck -Id 'WIN-001' -Title 'SMBv1 is disabled' `
        -Category 'Windows Server' -Requires WindowsServer -Severity High `
        -Frameworks @{ CIS='2.3.x'; MS='Security Baseline'; NIST='SC-7' } `
        -Rationale 'SMBv1 is obsolete and exploitable (EternalBlue/WannaCry). It has no place on a modern network.' `
        -Remediation 'Remove the SMB1 feature: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol. Confirm no legacy clients depend on it first.' `
        -Test { param($w) @{ Passed = (-not $w.SMB1Enabled); Evidence = "SMB1 enabled: $($w.SMB1Enabled)." } }

    New-AssessmentCheck -Id 'WIN-002' -Title 'RDP requires Network Level Authentication' `
        -Category 'Windows Server' -Requires WindowsServer -Severity Medium `
        -Frameworks @{ CIS='18.x'; MS='Security Baseline'; NIST='IA-2' } `
        -Rationale 'NLA forces authentication before a session is established, mitigating pre-auth RDP exploits and resource exhaustion.' `
        -Remediation 'Enable "Require user authentication for remote connections by using NLA" via GPO or set UserAuthentication=1 on the RDP-Tcp listener.' `
        -Test { param($w) @{ Passed = [bool]$w.RdpNlaEnabled; Evidence = "RDP NLA enabled: $($w.RdpNlaEnabled)." } }

    New-AssessmentCheck -Id 'WIN-003' -Title 'Windows Firewall enabled on all profiles' `
        -Category 'Windows Server' -Requires WindowsServer -Severity Medium `
        -Frameworks @{ CIS='9.x'; NIST='SC-7' } `
        -Rationale 'A host firewall limits lateral movement and exposure of management ports even inside the perimeter.' `
        -Remediation 'Enable the firewall for Domain, Private and Public profiles via GPO; allow only required inbound services.' `
        -Test { param($w) @{ Passed = [bool]$w.FirewallAllEnabled; Evidence = "All firewall profiles enabled: $($w.FirewallAllEnabled)." } }

    New-AssessmentCheck -Id 'WIN-004' -Title 'Legacy TLS/SSL protocols disabled' `
        -Category 'Windows Server' -Requires WindowsServer -Severity High `
        -Frameworks @{ CIS='18.x'; NIST='SC-8'; E8='Patch Applications' } `
        -Rationale 'SSL 2/3 and TLS 1.0/1.1 are deprecated and vulnerable (POODLE, BEAST). They weaken every TLS service on the host.' `
        -Remediation 'Disable SSL 2.0/3.0 and TLS 1.0/1.1 server-side in the SCHANNEL registry (Enabled=0, DisabledByDefault=1). Enforce TLS 1.2+.' `
        -Test {
            param($w)
            $p = @($w.WeakTlsProtocols)
            @{ Passed = ($p.Count -eq 0); Evidence = "Weak protocols enabled: $($p -join ', ')."; AffectedItems = $p }
        }

    New-AssessmentCheck -Id 'WIN-005' -Title 'Host patched within 30 days' `
        -Category 'Windows Server' -Requires WindowsServer -Severity High `
        -Frameworks @{ CIS='18.x'; NIST='SI-2'; E8='Patch Operating Systems' } `
        -Rationale 'Unpatched servers are the most common initial-access vector. Essential 8 expects OS patching within 30 days (48h for critical).' `
        -Remediation 'Apply the latest cumulative update. Establish a monthly patch cycle with an expedited path for critical/exploited CVEs.' `
        -Test {
            param($w)
            $days = if ($w.LastHotfixDate) { (New-TimeSpan -Start $w.LastHotfixDate -End (Get-Date)).Days } else { 9999 }
            @{ Passed = ($days -le 30); Evidence = "Last hotfix installed $days days ago." }
        }

    New-AssessmentCheck -Id 'WIN-006' -Title 'Local Administrators group is constrained' `
        -Category 'Windows Server' -Requires WindowsServer -Severity Medium `
        -Frameworks @{ CIS='2.x'; NIST='AC-6'; E8='Restrict Admin Privileges' } `
        -Rationale 'Broad local admin membership enables lateral movement and undermines tiering. Only required, audited principals should be local admins.' `
        -Remediation 'Remove ad-hoc users from local Administrators; manage membership centrally via GPO/Restricted Groups and use LAPS for the built-in account.' `
        -Test {
            param($w)
            $a = @($w.LocalAdmins)
            @{ Passed = ($a.Count -le 3); Evidence = "$($a.Count) local administrator principals."; AffectedItems = $a }
        }
)
