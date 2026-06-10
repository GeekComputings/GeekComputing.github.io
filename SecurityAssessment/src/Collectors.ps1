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

function Get-ExchangeContext {
    [CmdletBinding()] param()
    if (-not (Test-CommandAvailable 'Get-ExchangeServer')) { return $null }
    try {
        $servers = Get-ExchangeServer -ErrorAction Stop
        @{
            Servers            = @($servers | Select-Object Name, AdminDisplayVersion)
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
            Servers                = @([pscustomobject]@{ Name='EXCH01'; AdminDisplayVersion='Version 15.1 (Build 2375.7)' })
            BasicAuthEnabled       = $true
            EcpExternallyPublished = $true
        }
        M365 = @{
            GlobalAdminCount  = 7
            ConditionalAccess = @([pscustomobject]@{ DisplayName='Require MFA - Admins'; State='enabledForReportingButNotEnforced' })
            LegacyAuthBlocked = $false
            SecurityDefaults  = $false
        }
    }
}
