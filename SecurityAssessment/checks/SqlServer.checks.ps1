<#
    SQL Server checks. -Test scriptblock receives the SQL context as $sql.
#>

@(
    New-AssessmentCheck -Id 'SQL-001' -Title 'SQL Server version is supported and patched' `
        -Category 'SQL Server' -Requires SQL -Severity Critical `
        -Frameworks @{ CIS='1.x (SQL)'; NIST='SI-2'; E8='Patch Applications' } `
        -Rationale 'Out-of-support SQL Server builds receive no security fixes; database engines are high-value targets holding the organisation''s most sensitive data.' `
        -Remediation 'Upgrade to a supported SQL Server version (2019+) and apply the latest CU. Track end-of-support dates and plan migrations 12 months ahead.' `
        -Test {
            param($sql)
            # Major build 16=2022, 15=2019 are in support; 14=2017 and older are not (as of 2026).
            $major = [int]($sql.Version -split '\.')[0]
            @{ Passed = ($major -ge 15)
               Evidence = "Instance $($sql.Instance) is build $($sql.Version) ($($sql.Edition))." }
        }

    New-AssessmentCheck -Id 'SQL-002' -Title 'Windows Authentication mode only' `
        -Category 'SQL Server' -Requires SQL -Severity High `
        -Frameworks @{ CIS='3.1 (SQL)'; NIST='IA-2' } `
        -Rationale 'Mixed mode enables SQL logins with passwords stored in the instance - no MFA, no AD lockout policy, and a separate credential set to spray.' `
        -Remediation 'Switch to Windows Authentication mode where applications allow it; migrate SQL logins to AD-integrated logins or contained users with strong policies.' `
        -Test {
            param($sql)
            @{ Passed = [bool]$sql.WindowsAuthOnly
               Evidence = "Windows-auth-only: $($sql.WindowsAuthOnly)." }
        }

    New-AssessmentCheck -Id 'SQL-003' -Title 'sa account is disabled and renamed' `
        -Category 'SQL Server' -Requires SQL -Severity High `
        -Frameworks @{ CIS='2.13/2.14 (SQL)'; NIST='AC-2' } `
        -Rationale 'The sa account is the best-known SQL principal and the first target of brute-force attacks; enabled with its default name it is a standing risk.' `
        -Remediation 'Disable the sa login (ALTER LOGIN sa DISABLE) and rename it. Use named admin logins with least privilege instead.' `
        -Test {
            param($sql)
            @{ Passed = ($sql.SaDisabled -and $sql.SaRenamed)
               Evidence = "sa disabled: $($sql.SaDisabled), renamed: $($sql.SaRenamed)." }
        }

    New-AssessmentCheck -Id 'SQL-004' -Title 'xp_cmdshell is disabled' `
        -Category 'SQL Server' -Requires SQL -Severity High `
        -Frameworks @{ CIS='2.2 (SQL)'; NIST='CM-7' } `
        -Rationale 'xp_cmdshell lets anyone with sysadmin run OS commands as the SQL service account - a standard privilege-escalation and lateral-movement path.' `
        -Remediation "Disable it: EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE. Audit for jobs/applications that depend on it and replace them." `
        -Test {
            param($sql)
            @{ Passed = (-not $sql.XpCmdshellEnabled)
               Evidence = "xp_cmdshell enabled: $($sql.XpCmdshellEnabled)." }
        }

    New-AssessmentCheck -Id 'SQL-005' -Title 'All user databases backed up within 7 days' `
        -Category 'SQL Server' -Requires SQL -Severity High `
        -Frameworks @{ NIST='CP-9'; E8='Regular Backups' } `
        -Rationale 'Backups are the last line of defence against ransomware and data loss. A database without a recent full backup is unrecoverable.' `
        -Remediation 'Schedule full backups (daily or per RPO) for every user database, verify restores regularly, and keep offline/immutable copies.' `
        -Test {
            param($sql)
            @{ Passed = ($sql.OldestBackupAgeDays -le 7)
               Evidence = "Oldest full backup across $($sql.DatabaseCount) user database(s): $($sql.OldestBackupAgeDays) day(s) ago." }
        }
)
