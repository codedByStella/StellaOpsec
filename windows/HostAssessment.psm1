
#Requires -Version 5.1
<#
.SYNOPSIS
    Host and network assessment toolkit for authorized security engagements.

.DESCRIPTION
    Read-only enumeration and configuration-review functions intended for
    scoped, authorized assessments.

    Functions return structured PowerShell objects suitable for CSV, JSON,
    and downstream reporting.

    The module does not perform exploitation, persistence, evasion,
    credential extraction, or payload delivery.

.NOTES
    Run only against systems you are explicitly authorized to assess.
    Some checks require administrative privileges.
#>

# ---------------------------------------------------------------------------
# Helper: isolate individual checks so one failure does not stop an assessment
# ---------------------------------------------------------------------------
function Invoke-SafeCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [scriptblock]$Script
    )

    try {
        $ErrorActionPreference = 'Stop'
        & $Script
    }
    catch {
        $message = $_.Exception.Message
        Write-Warning "[$Name] failed: $message"

        [PSCustomObject]@{
            Check = $Name
            Status = 'Failed'
            Error = $message
        }
    }
}


function Test-ContainsCheckFailure {
    [CmdletBinding()]
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) { return $false }
    if ($Value -is [string] -or $Value.GetType().IsValueType) { return $false }

    if ($Value -is [System.Collections.IDictionary]) {
        if ($Value.Contains('Status') -and $Value['Status'] -eq 'Failed') {
            return $true
        }
        foreach ($item in $Value.Values) {
            if (Test-ContainsCheckFailure -Value $item) { return $true }
        }
        return $false
    }

    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        foreach ($item in $Value) {
            if (Test-ContainsCheckFailure -Value $item) { return $true }
        }
        return $false
    }

    if ($Value.PSObject.Properties['Status'] -and $Value.Status -eq 'Failed') {
        return $true
    }

    foreach ($property in $Value.PSObject.Properties) {
        if (Test-ContainsCheckFailure -Value $property.Value) { return $true }
    }

    return $false
}

# ---------------------------------------------------------------------------
# Host information
# ---------------------------------------------------------------------------
function Get-HostSummary {
    <#
    .SYNOPSIS
        Collects operating system, domain, and hardware manufacturer/model data.
    #>
    [CmdletBinding()]
    param()

    Invoke-SafeCheck -Name 'HostSummary' -Script {
        $computerInfo = Get-ComputerInfo -ErrorAction Stop

        [PSCustomObject]@{
            ComputerName = $computerInfo.CsName
            Domain       = $computerInfo.CsDomain
            PartOfDomain = $computerInfo.CsPartOfDomain
            OSName       = $computerInfo.WindowsProductName
            OSVersion    = $computerInfo.WindowsVersion
            OSBuild      = $computerInfo.OsBuildNumber
            Manufacturer = $computerInfo.CsManufacturer
            Model        = $computerInfo.CsModel
            InstallDate  = $computerInfo.OsInstallDate
            LastBootTime = $computerInfo.OsLastBootUpTime
            TimeZone     = (Get-TimeZone -ErrorAction Stop).Id
        }
    }
}

# ---------------------------------------------------------------------------
# Local users and groups
# ---------------------------------------------------------------------------
function Get-LocalAccountAudit {
    <#
    .SYNOPSIS
        Enumerates local user accounts and local Administrators membership.
    #>
    [CmdletBinding()]
    param()

    $users = @(Invoke-SafeCheck -Name 'LocalUsers' -Script {
        Get-LocalUser -ErrorAction Stop |
            Select-Object Name, Enabled, LastLogon, PasswordRequired,
                PasswordExpires, PasswordLastSet,
                @{Name = 'AccountType'; Expression = { 'Local' }}
    })

    $admins = @(Invoke-SafeCheck -Name 'AdminGroupMembers' -Script {
        Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop |
            Select-Object Name, PrincipalSource, ObjectClass
    })

    [PSCustomObject]@{
        LocalUsers        = $users
        AdministratorsGrp = $admins
    }
}

# ---------------------------------------------------------------------------
# Network posture
# ---------------------------------------------------------------------------
function Get-NetworkPosture {
    <#
    .SYNOPSIS
        Collects IPv4 configuration, TCP listeners, and firewall profile state.
    #>
    [CmdletBinding()]
    param()

    $ips = @(Invoke-SafeCheck -Name 'IPAddresses' -Script {
        Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
            Where-Object {
                $_.IPAddress -notlike '127.*'
            } |
            Select-Object InterfaceAlias, IPAddress, PrefixLength, AddressState
    })

    $listeners = @(Invoke-SafeCheck -Name 'ListeningPorts' -Script {
        Get-NetTCPConnection -State Listen -ErrorAction Stop |
            ForEach-Object {
                $process = Get-Process -Id $_.OwningProcess `
                    -ErrorAction SilentlyContinue

                [PSCustomObject]@{
                    LocalAddress = $_.LocalAddress
                    LocalPort    = $_.LocalPort
                    PID          = $_.OwningProcess
                    ProcessName  = if ($process) { $process.ProcessName } else { $null }
                    ProcessPath  = if ($process) { $process.Path } else { $null }
                }
            } |
            Sort-Object LocalPort
    })

    $firewallProfiles = @(Invoke-SafeCheck -Name 'FirewallProfiles' -Script {
        Get-NetFirewallProfile -ErrorAction Stop |
            Select-Object Name, Enabled, DefaultInboundAction,
                DefaultOutboundAction
    })

    [PSCustomObject]@{
        IPAddresses      = $ips
        ListeningPorts   = $listeners
        FirewallProfiles = $firewallProfiles
    }
}

# ---------------------------------------------------------------------------
# Process snapshot
# ---------------------------------------------------------------------------
function Get-ProcessSnapshot {
    <#
    .SYNOPSIS
        Returns processes ranked by cumulative CPU time.

    .DESCRIPTION
        CPU is the cumulative processor time reported by Get-Process.
        It is not a sampled CPU utilization percentage.
    #>
    [CmdletBinding()]
    param(
        [ValidateRange(1, 500)]
        [int]$Top = 15
    )

    Invoke-SafeCheck -Name 'ProcessSnapshot' -Script {
        Get-Process -ErrorAction Stop |
            Sort-Object CPU -Descending |
            Select-Object -First $Top `
                Name, Id, CPU, WorkingSet, Path,
                @{Name = 'Company'; Expression = { $_.Company }}
    }
}

# ---------------------------------------------------------------------------
# Patch inventory
# ---------------------------------------------------------------------------
function Get-PatchInventory {
    <#
    .SYNOPSIS
        Enumerates installed hotfixes and their installation dates.

    .DESCRIPTION
        This function inventories installed hotfixes. It does not determine
        vulnerability status or independently map updates to CVEs.
    #>
    [CmdletBinding()]
    param()

    Invoke-SafeCheck -Name 'PatchInventory' -Script {
        Get-HotFix -ErrorAction Stop |
            Sort-Object InstalledOn |
            Select-Object HotFixID, Description, InstalledBy, InstalledOn
    }
}

# ---------------------------------------------------------------------------
# Installed software
# ---------------------------------------------------------------------------
function Get-InstalledSoftware {
    <#
    .SYNOPSIS
        Enumerates installed applications through registry uninstall entries.

    .DESCRIPTION
        Uses registry uninstall keys rather than Win32_Product, avoiding
        the MSI consistency checks that querying Win32_Product can trigger.
    #>
    [CmdletBinding()]
    param()

    Invoke-SafeCheck -Name 'InstalledSoftware' -Script {
        $paths = @(
            'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
            'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
            'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
        )

        Get-ItemProperty -Path $paths -ErrorAction Stop |
            Where-Object { $_.DisplayName } |
            Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
            Sort-Object DisplayName -Unique
    }
}

# ---------------------------------------------------------------------------
# Scheduled tasks
# ---------------------------------------------------------------------------
function Get-ScheduledTaskAudit {
    <#
    .SYNOPSIS
        Enumerates enabled and ready scheduled tasks and their configuration.

    .DESCRIPTION
        Collects task identity, state, principal, action, and last-run metadata.
        This is an inventory, not a determination that a task is malicious.
    #>
    [CmdletBinding()]
    param()

    Invoke-SafeCheck -Name 'ScheduledTasks' -Script {
        Get-ScheduledTask -ErrorAction Stop |
            Where-Object {
                $_.State -ne 'Disabled'
            } |
            ForEach-Object {
                $task = $_

                $info = Get-ScheduledTaskInfo `
                    -TaskName $task.TaskName `
                    -TaskPath $task.TaskPath `
                    -ErrorAction SilentlyContinue

                $actions = @(
                    $task.Actions |
                        ForEach-Object {
                            "$($_.Execute) $($_.Arguments)".Trim()
                        }
                )

                [PSCustomObject]@{
                    TaskName    = $task.TaskName
                    TaskPath    = $task.TaskPath
                    State       = $task.State
                    RunAsUser   = $task.Principal.UserId
                    RunLevel    = $task.Principal.RunLevel
                    Actions     = $actions -join '; '
                    LastRunTime = if ($info) { $info.LastRunTime } else { $null }
                    LastResult  = if ($info) { $info.LastTaskResult } else { $null }
                }
            }
    }
}

# ---------------------------------------------------------------------------
# Service configuration review
# ---------------------------------------------------------------------------
function Get-ServiceConfigAudit {
    <#
    .SYNOPSIS
        Inventories service configuration and identifies candidate unquoted paths.

    .DESCRIPTION
        Flags unquoted service executable paths containing whitespace.
        A finding is an indicator for manual review, not proof of exploitability.

        This function does not inspect service or executable ACLs and does not
        attempt exploitation.
    #>
    [CmdletBinding()]
    param()

    Invoke-SafeCheck -Name 'ServiceConfigAudit' -Script {
        Get-CimInstance -ClassName Win32_Service -ErrorAction Stop |
            ForEach-Object {
                $path = $_.PathName
                $candidate = $false

                if (
                    -not [string]::IsNullOrWhiteSpace($path) -and
                    $path -notmatch '^\s*"' -and
                    $path -match '\s'
                ) {
                    $candidate = $true
                }

                [PSCustomObject]@{
                    Name             = $_.Name
                    DisplayName      = $_.DisplayName
                    StartMode        = $_.StartMode
                    State            = $_.State
                    StartName        = $_.StartName
                    PathName         = $path
                    UnquotedPathRisk = $candidate
                }
            }
    }
}

# ---------------------------------------------------------------------------
# SMB share inventory
# ---------------------------------------------------------------------------
function Get-SmbShareAudit {
    <#
    .SYNOPSIS
        Enumerates SMB share metadata on the local or specified remote systems.

    .DESCRIPTION
        Remote systems are queried using temporary CIM sessions.
        This function collects share names, paths, and descriptions.
        It does not enumerate share-level or NTFS permissions.

    .PARAMETER ComputerName
        Target computer names. Defaults to localhost.
    #>
    [CmdletBinding()]
    param(
        [string[]]$ComputerName = @('localhost')
    )

    foreach ($computer in $ComputerName) {
        if ([string]::IsNullOrWhiteSpace($computer)) {
            continue
        }

        Invoke-SafeCheck -Name "SmbShares-$computer" -Script {
            $session = $null

            try {
                if (
                    $computer -eq 'localhost' -or
                    $computer -eq '.' -or
                    $computer -eq $env:COMPUTERNAME
                ) {
                    $shares = Get-SmbShare -ErrorAction Stop
                }
                else {
                    $session = New-CimSession `
                        -ComputerName $computer `
                        -ErrorAction Stop

                    $shares = Get-SmbShare `
                        -CimSession $session `
                        -ErrorAction Stop
                }

                $shares |
                    ForEach-Object {
                        [PSCustomObject]@{
                            ComputerName = $computer
                            ShareName    = $_.Name
                            Path         = $_.Path
                            Description  = $_.Description
                        }
                    }
            }
            finally {
                if ($null -ne $session) {
                    Remove-CimSession -CimSession $session `
                        -ErrorAction SilentlyContinue
                }
            }
        }
    }
}

# ---------------------------------------------------------------------------
# Full assessment
# ---------------------------------------------------------------------------
function Invoke-HostAssessment {
    <#
    .SYNOPSIS
        Runs the host assessment checks and returns a structured report.

    .PARAMETER OutputPath
        Optional path for a JSON report.

    .EXAMPLE
        Invoke-HostAssessment

    .EXAMPLE
        Invoke-HostAssessment -OutputPath 'C:\Reports\host1.json'
    #>
    [CmdletBinding()]
    param(
        [string]$OutputPath
    )

    $report = [PSCustomObject]@{
        GeneratedAt       = (Get-Date).ToUniversalTime().ToString('o')
        HostSummary       = Get-HostSummary
        LocalAccounts     = Get-LocalAccountAudit
        NetworkPosture    = Get-NetworkPosture
        TopProcesses      = Get-ProcessSnapshot
        PatchInventory    = Get-PatchInventory
        InstalledSoftware = Get-InstalledSoftware
        ScheduledTasks    = Get-ScheduledTaskAudit
        ServiceConfig     = Get-ServiceConfigAudit
        SmbShares         = @(Get-SmbShareAudit)
        ExportError       = $null
    }

    $report | Add-Member -NotePropertyName CollectionStatus -NotePropertyValue (
        if (Test-ContainsCheckFailure -Value $report) { 'Partial' } else { 'Complete' }
    )

    if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
        try {
            $fullPath = [System.IO.Path]::GetFullPath($OutputPath)
            $directory = [System.IO.Path]::GetDirectoryName($fullPath)

            if (
                -not [string]::IsNullOrWhiteSpace($directory) -and
                -not (Test-Path -LiteralPath $directory -PathType Container)
            ) {
                New-Item -Path $directory -ItemType Directory -Force `
                    -ErrorAction Stop | Out-Null
            }

            $json = ConvertTo-Json -InputObject $report -Depth 8 -ErrorAction Stop

            [System.IO.File]::WriteAllText(
                $fullPath,
                $json,
                (New-Object System.Text.UTF8Encoding($false))
            )

            Write-Verbose "Report written to $fullPath"
        }
        catch {
            $report.ExportError = $_.Exception.Message
            Write-Warning "Report export failed: $($_.Exception.Message)"
        }
    }

    return $report
}

Export-ModuleMember -Function @(
    'Get-HostSummary'
    'Get-LocalAccountAudit'
    'Get-NetworkPosture'
    'Get-ProcessSnapshot'
    'Get-PatchInventory'
    'Get-InstalledSoftware'
    'Get-ScheduledTaskAudit'
    'Get-ServiceConfigAudit'
    'Get-SmbShareAudit'
    'Invoke-HostAssessment'
)
