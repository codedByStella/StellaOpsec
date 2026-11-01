
#Requires -Version 5.1

<#
.SYNOPSIS
    Event log and detection-relevant data collection for authorized assessments.

.DESCRIPTION
    Performs read-only collection from Windows event logs and selected
    filesystem locations.

    Covers:
      - Successful and failed Windows logon events.
      - Failed logon aggregation by account.
      - PowerShell script block logging configuration and recent events.
      - PowerShell module logging configuration.
      - Recently created or modified files in selected locations.

    This module observes existing activity. It does not generate events,
    execute collected scripts, modify logging settings, or alter files.

.NOTES
    Compatible with Windows PowerShell 5.1.
    Security event collection may require elevated permissions.
#>


function Get-EventDataValue {
    <#
    .SYNOPSIS
        Extracts a named event-data field from a Windows event.
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [xml]$EventXml,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $field = @(
        $EventXml.Event.EventData.Data |
            Where-Object { $_.Name -eq $Name } |
            Select-Object -First 1
    )

    if ($field.Count -gt 0) {
        return [string]$field[0].'#text'
    }

    return $null
}


function Get-LogonEventSummary {
    <#
    .SYNOPSIS
        Summarizes recent successful and failed Windows logon events.

    .DESCRIPTION
        Collects Security event IDs:
          4624 - Successful logon
          4625 - Failed logon

        Extracts account, source address, logon type, and related metadata.
        This is a summary of recorded events, not proof of malicious activity.
    #>

    [CmdletBinding()]
    param(
        [ValidateRange(1, 8760)]
        [int]$Hours = 24,

        [ValidateRange(1, 100000)]
        [int]$MaxEvents = 5000
    )

    $start = (Get-Date).AddHours(-$Hours)

    try {
        $events = @(
            Get-WinEvent -FilterHashtable @{
                LogName = 'Security'
                Id = 4624, 4625
                StartTime = $start
            } -MaxEvents $MaxEvents -ErrorAction Stop
        )

        if ($events.Count -ge $MaxEvents) {
            Write-Warning "The event collection reached MaxEvents ($MaxEvents). Results may be truncated; increase MaxEvents or narrow the time window."
        }

        $findings = @(
            foreach ($event in $events) {
                try {
                    [xml]$xml = $event.ToXml()

                    $targetUser = Get-EventDataValue -EventXml $xml -Name 'TargetUserName'
                    $targetDomain = Get-EventDataValue -EventXml $xml -Name 'TargetDomainName'
                    $sourceIp = Get-EventDataValue -EventXml $xml -Name 'IpAddress'
                    $sourcePort = Get-EventDataValue -EventXml $xml -Name 'IpPort'
                    $logonType = Get-EventDataValue -EventXml $xml -Name 'LogonType'
                    $workstation = Get-EventDataValue -EventXml $xml -Name 'WorkstationName'
                    $processName = Get-EventDataValue -EventXml $xml -Name 'ProcessName'

                    [PSCustomObject]@{
                        TimeCreated = $event.TimeCreated
                        EventId = $event.Id
                        Result = if ($event.Id -eq 4624) {
                            'Success'
                        }
                        else {
                            'Failure'
                        }
                        TargetUser = $targetUser
                        TargetDomain = $targetDomain
                        SourceIP = $sourceIp
                        SourcePort = $sourcePort
                        Workstation = $workstation
                        LogonType = $logonType
                        ProcessName = $processName
                    }
                }
                catch {
                    Write-Warning "Could not parse event record $($event.RecordId): $($_.Exception.Message)"
                }
            }
        )

        return @($findings)
    }
    catch {
        if ($_.FullyQualifiedErrorId -like '*NoMatchingEventsFound*') {
            return @()
        }

        throw "Logon event collection failed. Security log access may require elevation: $($_.Exception.Message)"
    }
}


function Get-FailedLogonPattern {
    <#
    .SYNOPSIS
        Aggregates failed logons by account and summarizes source addresses.

    .DESCRIPTION
        Highlights accounts with repeated recorded failures.

        Counts alone do not establish brute-force activity. Interpret results
        alongside source addresses, time distribution, account context,
        authentication patterns, and other security telemetry.
    #>

    [CmdletBinding()]
    param(
        [ValidateRange(1, 8760)]
        [int]$Hours = 24,

        [ValidateRange(1, 100000)]
        [int]$MinAttempts = 5,

        [ValidateRange(1, 100000)]
        [int]$MaxEvents = 5000
    )

    $events = @(
        Get-LogonEventSummary -Hours $Hours -MaxEvents $MaxEvents
    )

    $failures = @(
        $events | Where-Object { $_.Result -eq 'Failure' }
    )

    $findings = @(
        $failures |
            Group-Object { '{0}\\{1}' -f $_.TargetDomain, $_.TargetUser } |
            Where-Object { $_.Count -ge $MinAttempts } |
            ForEach-Object {
                $group = $_.Group

                $sourceIps = @(
                    $group |
                        Where-Object {
                            -not [string]::IsNullOrWhiteSpace($_.SourceIP) -and
                            $_.SourceIP -notin @('-', '::1', '127.0.0.1')
                        } |
                        Select-Object -ExpandProperty SourceIP -Unique
                )

                [PSCustomObject]@{
                    Account = ($group[0].TargetUser)
                    Domain = ($group[0].TargetDomain)
                    AccountKey = $_.Name
                    Count = $_.Count
                    CollectionLimit = $MaxEvents
                    MayBeTruncated = ($events.Count -ge $MaxEvents)
                    UniqueSourceIPCount = $sourceIps.Count
                    SourceIPs = @($sourceIps)
                    FirstAttempt = (
                        $group |
                            Sort-Object TimeCreated |
                            Select-Object -First 1 -ExpandProperty TimeCreated
                    )
                    LastAttempt = (
                        $group |
                            Sort-Object TimeCreated -Descending |
                            Select-Object -First 1 -ExpandProperty TimeCreated
                    )
                }
            }
    )

    return @($findings)
}


function Get-PowerShellLogSummary {
    <#
    .SYNOPSIS
        Checks PowerShell logging configuration and collects recent script block events.

    .DESCRIPTION
        Reads the registry policy settings for:
          - Script block logging.
          - Module logging.

        Collects event ID 4104 from the PowerShell Operational event log.

        Script block logging configuration and the presence of recent
        events are reported separately. An enabled policy does not guarantee
        that events are available or that logging has been functioning.
    #>

    [CmdletBinding()]
    param(
        [ValidateRange(1, 8760)]
        [int]$Hours = 24,

        [ValidateRange(1, 100000)]
        [int]$MaxEvents = 500
    )

    $scriptBlockKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    $moduleLoggingKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'

    $scriptBlockEnabled = $null
    $moduleLoggingEnabled = $null
    $registryErrors = @()

    try {
        $settings = Get-ItemProperty `
            -Path $scriptBlockKey `
            -Name EnableScriptBlockLogging `
            -ErrorAction Stop

        $scriptBlockEnabled = ($settings.EnableScriptBlockLogging -eq 1)
    }
    catch {
        $registryErrors += "Script block logging policy: $($_.Exception.Message)"
    }

    try {
        $settings = Get-ItemProperty `
            -Path $moduleLoggingKey `
            -Name EnableModuleLogging `
            -ErrorAction Stop

        $moduleLoggingEnabled = ($settings.EnableModuleLogging -eq 1)
    }
    catch {
        $registryErrors += "Module logging policy: $($_.Exception.Message)"
    }

    $recentEvents = @()
    $eventLogError = $null
    $start = (Get-Date).AddHours(-$Hours)

    try {
        $events = @(
            Get-WinEvent -FilterHashtable @{
                LogName = 'Microsoft-Windows-PowerShell/Operational'
                Id = 4104
                StartTime = $start
            } -MaxEvents $MaxEvents -ErrorAction Stop
        )

        $recentEvents = @(
            $events | ForEach-Object {
                [PSCustomObject]@{
                    TimeCreated = $_.TimeCreated
                    EventId = $_.Id
                    ScriptBlockPreview = (
                        ($_.Message -split "`r?`n" |
                            Select-Object -First 3) -join ' '
                    )
                }
            }
        )
    }
    catch {
        if ($_.FullyQualifiedErrorId -notlike '*NoMatchingEventsFound*') {
            $eventLogError = $_.Exception.Message
        }
    }

    return [PSCustomObject]@{
        ScriptBlockLoggingEnabled = $scriptBlockEnabled
        ModuleLoggingEnabled = $moduleLoggingEnabled
        RecentEvents = @($recentEvents)
        EventLogQueryError = $eventLogError
        ConfigurationQueryErrors = @($registryErrors)
    }
}


function Get-RecentFileActivity {
    <#
    .SYNOPSIS
        Lists recently created or modified files in selected locations.

    .DESCRIPTION
        Collects file metadata only. Does not read or execute file contents.

        Recursive enumeration can be incomplete where the current identity
        lacks access to directories or files.
    #>

    [CmdletBinding()]
    param(
        [ValidateRange(1, 8760)]
        [int]$Hours = 24,

        [ValidateRange(1, 100000)]
        [int]$MaxFiles = 5000,

        [string[]]$Paths = @(
            "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
            "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
            "$env:TEMP",
            "$env:PUBLIC",
            "$env:WINDIR\Tasks"
        )
    )

    $cutoff = (Get-Date).AddHours(-$Hours)
    $findings = @()

    foreach ($path in $Paths) {
        if ([string]::IsNullOrWhiteSpace($path)) {
            continue
        }

        if (-not (Test-Path -LiteralPath $path -PathType Container)) {
            continue
        }

        try {
            $files = @(
                Get-ChildItem `
                    -LiteralPath $path `
                    -Recurse `
                    -File `
                    -ErrorAction SilentlyContinue |
                    Where-Object {
                        $_.LastWriteTime -gt $cutoff -or
                        $_.CreationTime -gt $cutoff
                    }
            )

            foreach ($file in $files) {
                $findings += [PSCustomObject]@{
                    FullName = $file.FullName
                    CreationTime = $file.CreationTime
                    LastWriteTime = $file.LastWriteTime
                    Length = $file.Length
                    ScannedPath = $path
                }

                if ($findings.Count -ge $MaxFiles) {
                    Write-Warning "File activity result limit of $MaxFiles reached. Additional files were not included."
                    return @($findings)
                }
            }
        }
        catch {
            Write-Warning "Recent file activity scan of '$path' failed: $($_.Exception.Message)"
        }
    }

    return @($findings)
}


function Invoke-EventLogAssessment {
    <#
    .SYNOPSIS
        Runs event log and recent file activity checks.

    .PARAMETER OutputPath
        Optional path to write the JSON report.

    .PARAMETER Hours
        Lookback period for event and file activity checks.

    .PARAMETER MaxEvents
        Maximum Security log events to retrieve for logon analysis.

    .PARAMETER MaxFiles
        Maximum recent file records to include.

    .OUTPUTS
        Report object containing:
          GeneratedAt
          LogonEvents
          FailedLogonPatterns
          PowerShellLogging
          RecentFileActivity
          AssessmentErrors
    #>

    [CmdletBinding()]
    param(
        [string]$OutputPath,

        [ValidateRange(1, 8760)]
        [int]$Hours = 24,

        [ValidateRange(1, 100000)]
        [int]$MaxEvents = 5000,

        [ValidateRange(1, 100000)]
        [int]$MaxFiles = 5000
    )

    $report = [PSCustomObject]@{
        GeneratedAt = (Get-Date).ToUniversalTime().ToString('o')
        LookbackHours = $Hours
        LogonEvents = @()
        FailedLogonPatterns = @()
        PowerShellLogging = $null
        RecentFileActivity = @()
        AssessmentErrors = @()
    }

    $errors = @()

    $checks = @(
        @{
            Name = 'Logon event collection'
            Property = 'LogonEvents'
            Action = {
                Get-LogonEventSummary -Hours $Hours -MaxEvents $MaxEvents
            }
        },
        @{
            Name = 'Failed logon aggregation'
            Property = 'FailedLogonPatterns'
            Action = {
                Get-FailedLogonPattern -Hours $Hours -MaxEvents $MaxEvents
            }
        },
        @{
            Name = 'PowerShell logging review'
            Property = 'PowerShellLogging'
            Action = {
                Get-PowerShellLogSummary -Hours $Hours
            }
        },
        @{
            Name = 'Recent file activity'
            Property = 'RecentFileActivity'
            Action = {
                Get-RecentFileActivity -Hours $Hours -MaxFiles $MaxFiles
            }
        }
    )

    foreach ($check in $checks) {
        try {
            Write-Verbose "Running check: $($check.Name)"

            $result = @(& $check.Action)

            if ($check.Property -eq 'PowerShellLogging') {
                $report.PowerShellLogging = $result | Select-Object -First 1
            }
            else {
                $report.($check.Property) = @($result)
            }
        }
        catch {
            $message = "$($check.Name): $($_.Exception.Message)"
            $errors += $message
            Write-Warning $message
        }
    }

    $report.AssessmentErrors = @($errors)

    if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
        try {
            $fullPath = [System.IO.Path]::GetFullPath($OutputPath)
            $directory = [System.IO.Path]::GetDirectoryName($fullPath)

            if (
                -not [string]::IsNullOrWhiteSpace($directory) -and
                -not (Test-Path -LiteralPath $directory -PathType Container)
            ) {
                New-Item -ItemType Directory -Path $directory -Force -ErrorAction Stop |
                    Out-Null
            }

            $json = ConvertTo-Json -InputObject $report -Depth 8

            Set-Content `
                -LiteralPath $fullPath `
                -Value $json `
                -Encoding UTF8 `
                -ErrorAction Stop

            Write-Verbose "Report written to: $fullPath"
        }
        catch {
            throw "Assessment completed, but the report could not be written to '$OutputPath': $($_.Exception.Message)"
        }
    }

    return $report
}


Export-ModuleMember -Function @(
    'Get-LogonEventSummary',
    'Get-FailedLogonPattern',
    'Get-PowerShellLogSummary',
    'Get-RecentFileActivity',
    'Invoke-EventLogAssessment'
)
