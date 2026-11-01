
#Requires -Version 5.1

<#
.SYNOPSIS
    Active Directory enumeration module for authorized assessments.

.DESCRIPTION
    Read-only Active Directory queries using the RSAT ActiveDirectory
    module. Identifies common configuration and identity risks, including
    stale accounts, privileged-account indicators, password policies,
    SPN exposure, domain trusts, and Group Policy inventory.

    This module performs enumeration only. It does not request service
    tickets, crack credentials, modify directory objects, or change
    domain configuration.

.NOTES
    Requires:
      - Windows PowerShell 5.1+
      - ActiveDirectory PowerShell module (RSAT)
      - GroupPolicy module for GPO inventory
      - Appropriate permissions to query the target domain

    Run only against domains you are authorized to assess.
#>

function Test-ADModuleAvailable {
    [CmdletBinding()]
    param()

    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Warning "ActiveDirectory module not available. Install RSAT: Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0"
        return $false
    }

    try {
        if (-not (Get-Module -Name ActiveDirectory)) {
            Import-Module ActiveDirectory -ErrorAction Stop
        }

        return $true
    }
    catch {
        Write-Warning "Failed to load ActiveDirectory module: $($_.Exception.Message)"
        return $false
    }
}

function Get-ADUserAudit {
    <#
    .SYNOPSIS
        Audits domain users for stale accounts, password settings,
        privileged-account indicators, and SPN presence.
    #>
    [CmdletBinding()]
    param(
        [ValidateRange(1, 36500)]
        [int]$StaleDays = 90
    )

    if (-not (Test-ADModuleAvailable)) { return }

    $cutoff = (Get-Date).AddDays(-$StaleDays)

    try {
        Get-ADUser -Filter * -Properties LastLogonDate, PasswordNeverExpires,
            PasswordLastSet, Enabled, AdminCount, ServicePrincipalName `
            -ErrorAction Stop |
            Select-Object Name, SamAccountName, Enabled, LastLogonDate,
                @{N='NeverLoggedIn';E={$null -eq $_.LastLogonDate}},
                @{N='StaleAccount';E={
                    $null -eq $_.LastLogonDate -or $_.LastLogonDate -lt $cutoff
                }},
                PasswordNeverExpires,
                PasswordLastSet,
                @{N='AdminCountIndicator';E={$_.AdminCount -eq 1}},
                @{N='DisabledPrivileged';E={
                    (-not $_.Enabled) -and ($_.AdminCount -eq 1)
                }},
                @{N='HasSPN';E={$_.ServicePrincipalName.Count -gt 0}},
                @{N='SPNs';E={
                    ($_.ServicePrincipalName) -join '; '
                }}
    }
    catch {
        Write-Warning "ADUserAudit failed: $($_.Exception.Message)"
    }
}

function Get-ADGroupAudit {
    <#
    .SYNOPSIS
        Enumerates membership of selected high-value domain groups.
    #>
    [CmdletBinding()]
    param(
        [string[]]$Groups = @(
            'Domain Admins',
            'Enterprise Admins',
            'Schema Admins',
            'Administrators',
            'Account Operators',
            'Backup Operators'
        )
    )

    if (-not (Test-ADModuleAvailable)) { return }

    foreach ($g in $Groups) {
        try {
            Get-ADGroupMember -Identity $g -Recursive -ErrorAction Stop |
                ForEach-Object {
                    [PSCustomObject]@{
                        Group       = $g
                        Name        = $_.Name
                        SamAccount  = $_.SamAccountName
                        ObjectClass = $_.ObjectClass
                    }
                }
        }
        catch {
            Write-Warning "Group '$g' lookup failed: $($_.Exception.Message)"
        }
    }
}

function Get-ADPasswordPolicy {
    <#
    .SYNOPSIS
        Retrieves the default domain password policy and fine-grained
        password policies.
    #>
    [CmdletBinding()]
    param()

    if (-not (Test-ADModuleAvailable)) { return }

    $default = $null
    $fgpp = @()

    try {
        $default = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop
    }
    catch {
        Write-Warning "Default password policy lookup failed: $($_.Exception.Message)"
    }

    try {
        $fgpp = @(Get-ADFineGrainedPasswordPolicy -Filter * -ErrorAction Stop)
    }
    catch {
        Write-Warning "Fine-grained password policy lookup failed: $($_.Exception.Message)"
    }

    [PSCustomObject]@{
        DefaultPolicy       = $default
        FineGrainedPolicies = $fgpp
    }
}

function Get-ADAccountsWithSPN {
    <#
    .SYNOPSIS
        Enumerates user accounts with Service Principal Names.

    .DESCRIPTION
        Enumeration only. This function does not request service tickets,
        extract ticket material, or attempt password cracking.
    #>
    [CmdletBinding()]
    param()

    if (-not (Test-ADModuleAvailable)) { return }

    try {
        Get-ADUser -Filter { ServicePrincipalName -like '*' } `
            -Properties ServicePrincipalName, PasswordLastSet, AdminCount `
            -ErrorAction Stop |
            Select-Object Name, SamAccountName, PasswordLastSet,
                @{N='IsPrivileged';E={$_.AdminCount -eq 1}},
                @{N='SPNs';E={
                    ($_.ServicePrincipalName) -join '; '
                }}
    }
    catch {
        Write-Warning "ADAccountsWithSPN check failed: $($_.Exception.Message)"
    }
}

function Get-ADTrustMap {
    <#
    .SYNOPSIS
        Enumerates domain trust relationships.
    #>
    [CmdletBinding()]
    param()

    if (-not (Test-ADModuleAvailable)) { return }

    try {
        Get-ADTrust -Filter * -ErrorAction Stop |
            Select-Object Name, Source, Target, Direction,
                TrustType, TrustAttributes
    }
    catch {
        Write-Warning "ADTrustMap failed: $($_.Exception.Message)"
    }
}

function Get-GPOInventory {
    <#
    .SYNOPSIS
        Retrieves Group Policy Object inventory and metadata.

    .DESCRIPTION
        Lists GPOs with identifiers, status, creation timestamps,
        and modification timestamps. Does not enumerate linked OUs
        or inspect individual policy settings.
    #>
    [CmdletBinding()]
    param()

    if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
        Write-Warning "GroupPolicy module not available. Install the Group Policy Management RSAT feature."
        return
    }

    try {
        if (-not (Get-Module -Name GroupPolicy)) {
            Import-Module GroupPolicy -ErrorAction Stop
        }

        Get-GPO -All -ErrorAction Stop |
            Select-Object DisplayName, Id, GpoStatus,
                CreationTime, ModificationTime
    }
    catch {
        Write-Warning "GPOInventory failed: $($_.Exception.Message)"
    }
}

function Invoke-ADAssessment {
    <#
    .SYNOPSIS
        Runs all AD checks and returns one structured report object.
    #>
    [CmdletBinding()]
    param(
        [string]$OutputPath,

        [ValidateRange(1, 36500)]
        [int]$StaleDays = 90
    )

    if (-not (Test-ADModuleAvailable)) { return }

    Write-Host "=== AD Assessment ===" -ForegroundColor Cyan

    $report = [PSCustomObject]@{
        GeneratedAt      = Get-Date -Format 'o'
        Users            = @(Get-ADUserAudit -StaleDays $StaleDays)
        PrivilegedGroups = @(Get-ADGroupAudit)
        PasswordPolicy   = Get-ADPasswordPolicy
        AccountsWithSPN   = @(Get-ADAccountsWithSPN)
        Trusts           = @(Get-ADTrustMap)
        GPOs             = @(Get-GPOInventory)
    }

    if ($OutputPath) {
        try {
            $report |
                ConvertTo-Json -Depth 8 |
                Out-File -FilePath $OutputPath -Encoding UTF8 -ErrorAction Stop

            Write-Host "Report written to $OutputPath" -ForegroundColor Green
        }
        catch {
            Write-Warning "Failed to write assessment report: $($_.Exception.Message)"
        }
    }

    return $report
}

Export-ModuleMember -Function Test-ADModuleAvailable, Get-ADUserAudit,
    Get-ADGroupAudit, Get-ADPasswordPolicy, Get-ADAccountsWithSPN,
    Get-ADTrustMap, Get-GPOInventory, Invoke-ADAssessment
