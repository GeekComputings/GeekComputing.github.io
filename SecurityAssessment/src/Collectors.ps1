<#
    Collectors.ps1
    Read-only collectors. Each Get-*Context function gathers configuration
    state from a target and returns a flat hashtable consumed by checks.

    Collectors are best-effort: if the required module/cmdlets or connectivity
    are missing, the function returns $null and the engine marks those checks
    'NotAssessed' rather than failing the run. Nothing here writes/changes
    state on the target.
#>

function Test-CommandAvailable {
    param([string]$Name)
    [bool](Get-Command -Name $Name -ErrorAction SilentlyContinue)
}

function Get-ADContext {
    [CmdletBinding()] param()
    if (-not (Test-CommandAvailable 'Get-ADDomain')) {
        Write-Warning 'ActiveDirectory module not available - skipping AD collection.'
        return $null
    }
    try {
        $domain = Get-ADDomain -ErrorAction Stop
        $krbtgt = Get-ADUser 'krbtgt' -Properties PasswordLastSet -ErrorAction Stop
        $defPol = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop

        $inactiveThreshold = (Get-Date).AddDays(-90)
        $staleUsers = Get-ADUser -Filter { Enabled -eq $true } -Properties LastLogonTimestamp |
            Where-Object { $_.LastLogonTimestamp -and ([datetime]::FromFileTime($_.LastLogonTimestamp) -lt $inactiveThreshold) } |
            Select-Object -ExpandProperty SamAccountName

        $unconstrained = Get-ADComputer -Filter { TrustedForDelegation -eq $true } -Properties TrustedForDelegation |
            Select-Object -ExpandProperty Name

        $privGroups = @{}
        foreach ($g in 'Domain Admins','Enterprise Admins','Schema Admins','Administrators') {
            $members = Get-ADGroupMember -Identity $g -Recursive -ErrorAction SilentlyContinue |
                Select-Object -ExpandProperty SamAccountName
            $privGroups[$g] = @($members)
        }

        $reversible = Get-ADUser -Filter { AllowReversiblePasswordEncryption -eq $true } |
            Select-Object -ExpandProperty SamAccountName
        $neverExpire = Get-ADUser -Filter { PasswordNeverExpires -eq $true -and Enabled -eq $true } |
            Select-Object -ExpandProperty SamAccountName

        $lapsDeployed = [bool](Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext `
            -Filter { name -like 'ms-Mcs-AdmPwd' -or name -like 'msLAPS-Password' } -ErrorAction SilentlyContinue)

        @{
            DomainName              = $domain.DNSRoot
            DomainFunctionalLevel   = $domain.DomainMode.ToString()
            MachineAccountQuota     = (Get-ADObject (Get-ADDomain).DistinguishedName -Properties 'ms-DS-MachineAccountQuota').'ms-DS-MachineAccountQuota'
            KrbtgtPasswordLastSet   = $krbtgt.PasswordLastSet
            MinPasswordLength       = $defPol.MinPasswordLength
            PasswordComplexity      = $defPol.ComplexityEnabled
            LockoutThreshold        = $defPol.LockoutThreshold
            PrivilegedGroups        = $privGroups
            UnconstrainedDelegation = @($unconstrained)
            StaleAccounts           = @($staleUsers)
            ReversibleEncryption    = @($reversible)
            PasswordNeverExpires    = @($neverExpire)
            LapsDeployed            = $lapsDeployed
        }
    }
    catch {
        Write-Warning "AD collection failed: $($_.Exception.Message)"
        return $null
    }
}

function Get-WindowsServerContext {
    [CmdletBinding()] param([string]$ComputerName = $env:COMPUTERNAME)
    if (-not (Test-CommandAvailable 'Get-CimInstance')) { return $null }
    try {
        $smb1 = (Get-SmbServerConfiguration -ErrorAction SilentlyContinue).EnableSMB1Protocol
        $rdpNla = (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
            -Name UserAuthentication -ErrorAction SilentlyContinue).UserAuthentication
        $fw = Get-NetFirewallProfile -ErrorAction SilentlyContinue
        $localAdmins = (Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue).Name

        # Insecure TLS/SSL protocols still enabled (server side).
        $weakProtocols = @()
        foreach ($p in 'SSL 2.0','SSL 3.0','TLS 1.0','TLS 1.1') {
            $key = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$p\Server"
            $enabled = (Get-ItemProperty $key -Name Enabled -ErrorAction SilentlyContinue).Enabled
            $disabledByDefault = (Get-ItemProperty $key -Name DisabledByDefault -ErrorAction SilentlyContinue).DisabledByDefault
            if ($enabled -ne 0 -or $disabledByDefault -ne 1) { $weakProtocols += $p }
        }

        $lastHotfix = (Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending |
            Select-Object -First 1).InstalledOn

        @{
            ComputerName       = $ComputerName
            SMB1Enabled        = [bool]$smb1
            RdpNlaEnabled      = ($rdpNla -eq 1)
            FirewallAllEnabled = (@($fw | Where-Object Enabled -eq $true).Count -eq 3)
            LocalAdmins        = @($localAdmins)
            WeakTlsProtocols   = @($weakProtocols)
            LastHotfixDate     = $lastHotfix
        }
    }
    catch {
        Write-Warning "Windows Server collection failed: $($_.Exception.Message)"
        return $null
    }
}

function Get-ServerInventory {
    <# Hardware/OS specifications for one or more servers (read-only CIM).
       Returned objects feed the report's Infrastructure section. #>
    [CmdletBinding()] param([string[]]$ComputerName = @($env:COMPUTERNAME))
    if (-not (Test-CommandAvailable 'Get-CimInstance')) { return $null }

    $inventory = foreach ($computer in $ComputerName) {
        try {
            $cimArgs = @{}
            if ($computer -ne $env:COMPUTERNAME) { $cimArgs.ComputerName = $computer }

            $os   = Get-CimInstance Win32_OperatingSystem @cimArgs -ErrorAction Stop
            $cs   = Get-CimInstance Win32_ComputerSystem @cimArgs -ErrorAction Stop
            $cpu  = Get-CimInstance Win32_Processor @cimArgs -ErrorAction Stop | Select-Object -First 1
            $disk = Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' @cimArgs -ErrorAction Stop

            [pscustomobject]@{
                Name      = $cs.Name
                OS        = $os.Caption
                Build     = $os.BuildNumber
                CPU       = $cpu.Name
                Cores     = ($cs.NumberOfLogicalProcessors)
                MemoryGB  = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
                Disks     = ($disk | ForEach-Object {
                                "{0} {1}/{2} GB free" -f $_.DeviceID,
                                    [math]::Round($_.FreeSpace/1GB), [math]::Round($_.Size/1GB)
                             }) -join '; '
                UptimeDays = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalDays, 1)
            }
        }
        catch {
            Write-Warning "Inventory collection failed for ${computer}: $($_.Exception.Message)"
        }
    }
    @($inventory)
}

function Get-SqlContext {
    <# SQL Server posture + specs via Invoke-Sqlcmd (SqlServer module).
       All queries are read-only catalog/SERVERPROPERTY lookups. #>
    [CmdletBinding()] param([string]$ServerInstance = 'localhost')
    if (-not (Test-CommandAvailable 'Invoke-Sqlcmd')) {
        Write-Warning 'SqlServer module (Invoke-Sqlcmd) not available - skipping SQL collection.'
        return $null
    }
    try {
        $props = Invoke-Sqlcmd -ServerInstance $ServerInstance -Query @"
SELECT SERVERPROPERTY('ProductVersion')  AS Version,
       SERVERPROPERTY('ProductLevel')    AS Level,
       SERVERPROPERTY('Edition')         AS Edition,
       SERVERPROPERTY('IsIntegratedSecurityOnly') AS WindowsAuthOnly
"@ -ErrorAction Stop

        $sa = Invoke-Sqlcmd -ServerInstance $ServerInstance -Query `
            "SELECT name, is_disabled FROM sys.server_principals WHERE sid = 0x01" -ErrorAction Stop

        $xp = Invoke-Sqlcmd -ServerInstance $ServerInstance -Query `
            "SELECT CAST(value_in_use AS int) AS v FROM sys.configurations WHERE name = 'xp_cmdshell'" -ErrorAction Stop

        $dbCount = (Invoke-Sqlcmd -ServerInstance $ServerInstance -Query `
            "SELECT COUNT(*) AS n FROM sys.databases WHERE database_id > 4" -ErrorAction Stop).n

        $oldestBackup = Invoke-Sqlcmd -ServerInstance $ServerInstance -Query @"
SELECT MAX(d.days_since) AS days FROM (
  SELECT DATEDIFF(day, MAX(b.backup_finish_date), GETDATE()) AS days_since
  FROM sys.databases s
  LEFT JOIN msdb.dbo.backupset b ON b.database_name = s.name AND b.type = 'D'
  WHERE s.database_id > 4 AND s.state = 0
  GROUP BY s.name
) d
"@ -ErrorAction Stop

        @{
            Instance            = $ServerInstance
            Version             = [string]$props.Version
            Edition             = [string]$props.Edition
            WindowsAuthOnly     = [bool]$props.WindowsAuthOnly
            SaDisabled          = [bool]$sa.is_disabled
            SaRenamed           = ($sa.name -ne 'sa')
            XpCmdshellEnabled   = ($xp.v -eq 1)
            DatabaseCount       = [int]$dbCount
            OldestBackupAgeDays = if ($null -ne $oldestBackup.days) { [int]$oldestBackup.days } else { 9999 }
        }
    }
    catch {
        Write-Warning "SQL collection failed: $($_.Exception.Message)"
        return $null
    }
}

function Get-ExchangeContext {
    [CmdletBinding()] param()
    if (-not (Test-CommandAvailable 'Get-ExchangeServer')) { return $null }
    try {
        $servers = Get-ExchangeServer -ErrorAction Stop
        $dbCount = @(Get-MailboxDatabase -ErrorAction SilentlyContinue).Count
        @{
            Servers            = @($servers | Select-Object Name, AdminDisplayVersion,
                                     @{ N='Roles';   E={ $_.ServerRole } },
                                     @{ N='Edition'; E={ $_.Edition } })
            MailboxDatabases   = $dbCount
            BasicAuthEnabled   = [bool]((Get-AuthenticationPolicy -ErrorAction SilentlyContinue) -eq $null)
            EcpExternallyPublished = [bool]((Get-EcpVirtualDirectory -ErrorAction SilentlyContinue).ExternalUrl)
        }
    }
    catch {
        Write-Warning "Exchange collection failed: $($_.Exception.Message)"
        return $null
    }
}

function Get-M365Context {
    [CmdletBinding()] param()
    if (-not (Test-CommandAvailable 'Get-MgContext')) { return $null }
    if (-not (Get-MgContext -ErrorAction SilentlyContinue)) {
        Write-Warning 'Not connected to Microsoft Graph (Connect-MgGraph) - skipping M365 collection.'
        return $null
    }
    try {
        $globalAdminRole = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'" -ErrorAction SilentlyContinue
        $globalAdmins = if ($globalAdminRole) {
            Get-MgDirectoryRoleMember -DirectoryRoleId $globalAdminRole.Id | Select-Object -ExpandProperty Id
        } else { @() }

        $caPolicies = Get-MgIdentityConditionalAccessPolicy -ErrorAction SilentlyContinue

        @{
            GlobalAdminCount     = @($globalAdmins).Count
            ConditionalAccess    = @($caPolicies | Select-Object DisplayName, State)
            LegacyAuthBlocked    = [bool]($caPolicies | Where-Object {
                                     $_.State -eq 'enabled' -and
                                     $_.Conditions.ClientAppTypes -contains 'exchangeActiveSync' })
            SecurityDefaults     = (Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy -ErrorAction SilentlyContinue).IsEnabled
        }
    }
    catch {
        Write-Warning "M365 collection failed: $($_.Exception.Message)"
        return $null
    }
}

function Get-DemoContext {
    <# Synthetic, deliberately-imperfect data so the tool produces a
       representative report with no live environment. Used by -Demo. #>
    @{
        AD = @{
            DomainName              = 'corp.contoso.com'
            DomainFunctionalLevel   = 'Windows2012R2Domain'
            MachineAccountQuota     = 10
            KrbtgtPasswordLastSet   = (Get-Date).AddDays(-1400)
            MinPasswordLength       = 7
            PasswordComplexity      = $true
            LockoutThreshold        = 0
            PrivilegedGroups        = @{
                'Domain Admins'    = @('Administrator','svc_sql','svc_backup','jdoe_adm','legacy_app','helpdesk1')
                'Enterprise Admins'= @('Administrator','ealindh')
                'Schema Admins'    = @('Administrator')
                'Administrators'   = @('Administrator','svc_sql','svc_backup','jdoe_adm','legacy_app','helpdesk1','localsupport')
            }
            UnconstrainedDelegation = @('SRV-APP01','SRV-LEGACY02')
            StaleAccounts           = @('tmp_contractor','old_svc','jsmith_old','vendor_x','batch_2019')
            ReversibleEncryption    = @('legacy_radius_svc')
            PasswordNeverExpires    = @('svc_sql','svc_backup','svc_iis','svc_monitor')
            LapsDeployed            = $false
        }
        WindowsServer = @{
            ComputerName       = 'SRV-FILE01'
            SMB1Enabled        = $true
            RdpNlaEnabled      = $false
            FirewallAllEnabled = $true
            LocalAdmins        = @('Administrator','CORP\Domain Admins','CORP\helpdesk','localadmin2')
            WeakTlsProtocols   = @('TLS 1.0','TLS 1.1','SSL 3.0')
            LastHotfixDate     = (Get-Date).AddDays(-210)
        }
        Exchange = @{
            Servers                = @([pscustomobject]@{ Name='EXCH01'; AdminDisplayVersion='Version 15.1 (Build 2375.7)'; Roles='Mailbox'; Edition='Standard' })
            MailboxDatabases       = 4
            BasicAuthEnabled       = $true
            EcpExternallyPublished = $true
        }
        M365 = @{
            GlobalAdminCount  = 7
            ConditionalAccess = @([pscustomobject]@{ DisplayName='Require MFA - Admins'; State='enabledForReportingButNotEnforced' })
            LegacyAuthBlocked = $false
            SecurityDefaults  = $false
        }
        SQL = @{
            Instance            = 'SQL01\PROD'
            Version             = '13.0.5026.0'   # SQL Server 2016 SP2 - out of support
            Edition             = 'Standard Edition (64-bit)'
            WindowsAuthOnly     = $false
            SaDisabled          = $false
            SaRenamed           = $false
            XpCmdshellEnabled   = $true
            DatabaseCount       = 12
            OldestBackupAgeDays = 19
        }
        Inventory = @{
            Servers = @(
                [pscustomobject]@{ Name='SRV-DC01';   OS='Windows Server 2016 Standard';    Build='14393'; CPU='Intel Xeon E5-2640 v4'; Cores=8;  MemoryGB=16;  Disks='C: 38/120 GB free';                UptimeDays=212.4 }
                [pscustomobject]@{ Name='SRV-FILE01'; OS='Windows Server 2012 R2 Standard'; Build='9600';  CPU='Intel Xeon E5-2620 v3'; Cores=12; MemoryGB=32;  Disks='C: 12/120 GB free; D: 410/2048 GB free'; UptimeDays=388.7 }
                [pscustomobject]@{ Name='SRV-APP01';  OS='Windows Server 2019 Standard';    Build='17763'; CPU='Intel Xeon Silver 4214'; Cores=16; MemoryGB=64; Disks='C: 95/240 GB free';                UptimeDays=45.2 }
                [pscustomobject]@{ Name='EXCH01';     OS='Windows Server 2016 Standard';    Build='14393'; CPU='Intel Xeon Gold 5118';   Cores=24; MemoryGB=96; Disks='C: 60/240 GB free; E: 800/4096 GB free'; UptimeDays=97.1 }
                [pscustomobject]@{ Name='SQL01';      OS='Windows Server 2016 Standard';    Build='14393'; CPU='Intel Xeon Gold 6130';   Cores=32; MemoryGB=128; Disks='C: 80/240 GB free; F: 350/2048 GB free'; UptimeDays=130.5 }
            )
        }
    }
}
