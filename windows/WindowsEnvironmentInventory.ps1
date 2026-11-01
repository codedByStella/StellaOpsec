
#Requires -Version 5.1
<#
.SYNOPSIS
    Read-only Windows environment inventory and configuration report.

.DESCRIPTION
    Collects general Windows, computer, hardware, display, network adapter,
    and storage configuration information.

    Supports console output and optional JSON reporting.

    The script does not modify registry values, system configuration,
    network adapters, hardware settings, or system files.

    Unique hardware identifiers and raw MAC addresses are intentionally
    excluded from the report.

.PARAMETER ExportReport
    Exports the collected inventory to JSON.

.PARAMETER ReportPath
    Optional destination for the JSON report.
    Defaults to a timestamped file in the user's TEMP directory.

.PARAMETER Detailed
    Includes additional non-unique hardware and configuration metadata.

.EXAMPLE
    .\WindowsEnvironmentInventory.ps1

.EXAMPLE
    .\WindowsEnvironmentInventory.ps1 -ExportReport

.EXAMPLE
    .\WindowsEnvironmentInventory.ps1 -ExportReport -Detailed `
        -ReportPath "C:\Reports\HostInventory.json"

.NOTES
    PowerShell 5.1 compatible.
    Administrator privileges are not required.
    Some information may be unavailable depending on permissions,
    Windows version, hardware, or installed management providers.
#>

[CmdletBinding()]
param(
    [switch]$ExportReport,

    [string]$ReportPath,

    [switch]$Detailed
)

$ErrorActionPreference = 'Continue'

$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

function Write-InventoryLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet('White', 'Gray', 'Green', 'Yellow', 'Red', 'Cyan')]
        [string]$Color = 'White'
    )

    Write-Host $Message -ForegroundColor $Color
}

# ---------------------------------------------------------------------------
# Collection helper
# ---------------------------------------------------------------------------

function Invoke-InventoryCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [scriptblock]$Action
    )

    try {
        $data = @(& $Action)
        if ($data.Count -eq 0) {
            [PSCustomObject]@{
                Check = $Name
                Success = $true
                Status = 'CompletedNoData'
                Data = @()
                Error = $null
            }
        }
        else {
            [PSCustomObject]@{
                Check = $Name
                Success = $true
                Status = 'Completed'
                Data = $data
                Error = $null
            }
        }
    }
    catch {
        [PSCustomObject]@{
            Check   = $Name
            Success = $false
            Status  = 'Failed'
            Data    = @()
            Error   = $_.Exception.Message
        }
    }
}

# ---------------------------------------------------------------------------
# Computer and Windows information
# ---------------------------------------------------------------------------

function Get-EnvironmentSummary {
    [CmdletBinding()]
    param()

    $computerSystem = Get-CimInstance `
        -ClassName Win32_ComputerSystem `
        -ErrorAction Stop

    $operatingSystem = Get-CimInstance `
        -ClassName Win32_OperatingSystem `
        -ErrorAction Stop

    $registryPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'

    $windowsRegistry = Get-ItemProperty `
        -LiteralPath $registryPath `
        -ErrorAction Stop

    $installDate = $null

    if ($windowsRegistry.InstallDate) {
        try {
            $installDate = [DateTimeOffset]::FromUnixTimeSeconds(
                [long]$windowsRegistry.InstallDate
            ).LocalDateTime.ToString('yyyy-MM-dd HH:mm:ss')
        }
        catch {
            $installDate = 'Unavailable or invalid'
        }
    }

    [PSCustomObject]@{
        ComputerName       = $env:COMPUTERNAME
        UserName           = $env:USERNAME
        Manufacturer       = $computerSystem.Manufacturer
        Model              = $computerSystem.Model
        Domain             = $computerSystem.Domain
        DomainJoined       = [bool]$computerSystem.PartOfDomain
        WindowsCaption     = $operatingSystem.Caption
        WindowsVersion     = $operatingSystem.Version
        WindowsBuild       = $operatingSystem.BuildNumber
        DisplayVersion     = $windowsRegistry.DisplayVersion
        WindowsEdition     = $windowsRegistry.EditionID
        InstallDate        = $installDate
        LastBootTime       = $operatingSystem.LastBootUpTime
        SystemArchitecture = $operatingSystem.OSArchitecture
        TotalMemoryGB      = [math]::Round(
            $computerSystem.TotalPhysicalMemory / 1GB,
            2
        )
    }
}

# ---------------------------------------------------------------------------
# Local account inventory
# ---------------------------------------------------------------------------

function Get-LocalAccountInventory {
    [CmdletBinding()]
    param()

    if (-not (Get-Command Get-LocalUser -ErrorAction SilentlyContinue)) {
        throw 'Get-LocalUser is unavailable on this Windows installation.'
    }

    $users = @(Get-LocalUser -ErrorAction Stop)

    foreach ($user in $users) {
        [PSCustomObject]@{
            Name        = $user.Name
            Enabled     = $user.Enabled
            Description = $user.Description
            LastLogon   = $user.LastLogon
            PasswordRequired = $user.PasswordRequired
            PasswordExpires  = $user.PasswordExpires
        }
    }
}

# ---------------------------------------------------------------------------
# Network adapter inventory
# ---------------------------------------------------------------------------

function Get-NetworkAdapterInventory {
    [CmdletBinding()]
    param()

    if (-not (Get-Command Get-NetAdapter -ErrorAction SilentlyContinue)) {
        throw 'Get-NetAdapter is unavailable.'
    }

    $adapters = @(Get-NetAdapter -ErrorAction Stop)

    foreach ($adapter in $adapters) {
        $result = [ordered]@{
            Name                = $adapter.Name
            InterfaceDescription = $adapter.InterfaceDescription
            Status              = [string]$adapter.Status
            LinkSpeed            = [string]$adapter.LinkSpeed
            InterfaceIndex       = $adapter.InterfaceIndex
            MediaType            = [string]$adapter.MediaType
            PhysicalMediaType    = [string]$adapter.PhysicalMediaType
            MacAddressIncluded   = $false
        }

        if ($Detailed) {
            $result.DriverInformation = $null

            try {
                $driver = Get-NetAdapterDriver `
                    -Name $adapter.Name `
                    -ErrorAction Stop

                $result.DriverInformation = [PSCustomObject]@{
                    DriverDescription = $driver.DriverDescription
                    DriverVersion     = $driver.DriverVersion
                    DriverDate        = $driver.DriverDate
                    DriverProvider    = $driver.DriverProvider
                }
            }
            catch {
                $result.DriverInformation = 'Unavailable'
            }
        }

        [PSCustomObject]$result
    }
}

# ---------------------------------------------------------------------------
# Network configuration inventory
# ---------------------------------------------------------------------------

function Get-NetworkConfigurationInventory {
    [CmdletBinding()]
    param()

    if (-not (Get-Command Get-NetIPConfiguration -ErrorAction SilentlyContinue)) {
        throw 'Get-NetIPConfiguration is unavailable.'
    }

    $configurations = @(
        Get-NetIPConfiguration -ErrorAction Stop
    )

    foreach ($configuration in $configurations) {
        $ipv4Addresses = @(
            $configuration.IPv4Address |
                ForEach-Object { $_.IPAddress }
        )

        $ipv6Addresses = @(
            $configuration.IPv6Address |
                ForEach-Object { $_.IPAddress }
        )

        [PSCustomObject]@{
            InterfaceAlias = $configuration.InterfaceAlias
            InterfaceIndex = $configuration.InterfaceIndex
            IPv4Addresses  = $ipv4Addresses
            IPv6Addresses  = $ipv6Addresses
            IPv4Gateway    = @(
                $configuration.IPv4DefaultGateway |
                    ForEach-Object { $_.NextHop }
            )
            IPv6Gateway    = @(
                $configuration.IPv6DefaultGateway |
                    ForEach-Object { $_.NextHop }
            )
            DNSServers     = @(
                $configuration.DNSServer.ServerAddresses
            )
        }
    }
}

# ---------------------------------------------------------------------------
# Display and GPU inventory
# ---------------------------------------------------------------------------

function Get-DisplayInventory {
    [CmdletBinding()]
    param()

    $controllers = @(
        Get-CimInstance `
            -ClassName Win32_VideoController `
            -ErrorAction Stop
    )

    foreach ($controller in $controllers) {
        [PSCustomObject]@{
            Name              = $controller.Name
            AdapterCompatibility = $controller.AdapterCompatibility
            DriverVersion     = $controller.DriverVersion
            DriverDate        = $controller.DriverDate
            VideoMode         = $controller.VideoModeDescription
            CurrentResolution = if (
                $controller.CurrentHorizontalResolution -and
                $controller.CurrentVerticalResolution
            ) {
                '{0}x{1}' -f
                    $controller.CurrentHorizontalResolution,
                    $controller.CurrentVerticalResolution
            }
            else {
                $null
            }
            CurrentRefreshRate = $controller.CurrentRefreshRate
            Status             = $controller.Status
        }
    }
}

# ---------------------------------------------------------------------------
# Storage inventory
# ---------------------------------------------------------------------------

function Get-StorageInventory {
    [CmdletBinding()]
    param()

    if (-not (Get-Command Get-Volume -ErrorAction SilentlyContinue)) {
        throw 'Get-Volume is unavailable.'
    }

    $volumes = @(Get-Volume -ErrorAction Stop)

    foreach ($volume in $volumes) {
        [PSCustomObject]@{
            DriveLetter = $volume.DriveLetter
            FileSystem  = $volume.FileSystem
            Label       = $volume.FileSystemLabel
            DriveType   = [string]$volume.DriveType
            HealthStatus = [string]$volume.HealthStatus
            OperationalStatus = @($volume.OperationalStatus)
            SizeGB      = if ($null -ne $volume.Size) {
                [math]::Round($volume.Size / 1GB, 2)
            }
            else {
                $null
            }
            FreeSpaceGB = if ($null -ne $volume.SizeRemaining) {
                [math]::Round($volume.SizeRemaining / 1GB, 2)
            }
            else {
                $null
            }
        }
    }
}

# ---------------------------------------------------------------------------
# Physical memory inventory
# ---------------------------------------------------------------------------

function Get-MemoryInventory {
    [CmdletBinding()]
    param()

    $modules = @(
        Get-CimInstance `
            -ClassName Win32_PhysicalMemory `
            -ErrorAction Stop
    )

    foreach ($module in $modules) {
        [PSCustomObject]@{
            CapacityGB = [math]::Round(
                $module.Capacity / 1GB,
                2
            )
            SpeedMHz   = $module.Speed
            ConfiguredClockSpeedMHz = $module.ConfiguredClockSpeed
            Manufacturer = $module.Manufacturer
            FormFactor = $module.FormFactor
        }
    }
}

# ---------------------------------------------------------------------------
# Main assessment
# ---------------------------------------------------------------------------

Write-InventoryLog "`n=== WINDOWS ENVIRONMENT INVENTORY ===" Cyan
Write-InventoryLog "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" Gray
Write-InventoryLog "Detailed: $Detailed" Gray

$checks = @(
    @{
        Name   = 'Environment'
        Action = { Get-EnvironmentSummary }
    }
    @{
        Name   = 'LocalAccounts'
        Action = { Get-LocalAccountInventory }
    }
    @{
        Name   = 'NetworkAdapters'
        Action = { Get-NetworkAdapterInventory }
    }
    @{
        Name   = 'NetworkConfiguration'
        Action = { Get-NetworkConfigurationInventory }
    }
    @{
        Name   = 'Display'
        Action = { Get-DisplayInventory }
    }
    @{
        Name   = 'Storage'
        Action = { Get-StorageInventory }
    }
    @{
        Name   = 'PhysicalMemory'
        Action = { Get-MemoryInventory }
    }
)

$results = New-Object 'System.Collections.Generic.List[object]'

foreach ($check in $checks) {
    Write-InventoryLog "[*] Collecting $($check.Name)..." Yellow

    $result = Invoke-InventoryCheck `
        -Name $check.Name `
        -Action $check.Action

    $results.Add($result)

    if ($result.Success) {
        Write-InventoryLog "[+] $($check.Name) completed." Green
    }
    else {
        Write-InventoryLog (
            "[!] $($check.Name) unavailable: $($result.Error)"
        ) Yellow
    }
}

# ---------------------------------------------------------------------------
# Build report
# ---------------------------------------------------------------------------

$successfulChecks = @(
    $results | Where-Object { $_.Success }
)

$failedChecks = @(
    $results | Where-Object { -not $_.Success }
)

$report = [PSCustomObject]@{
    ReportName    = 'Windows Environment Inventory'
    GeneratedAt   = [DateTime]::UtcNow.ToString('o')
    ComputerName  = $env:COMPUTERNAME
    PrivacyNotice = 'Report includes potentially identifying host, user, domain, and network configuration data. Review and redact before sharing.'
    PowerShellVersion = $PSVersionTable.PSVersion.ToString()
    Detailed      = [bool]$Detailed
    CollectionSummary = [PSCustomObject]@{
        TotalChecks      = $results.Count
        SuccessfulChecks = $successfulChecks.Count
        FailedChecks     = $failedChecks.Count
    }
    Results       = $results.ToArray()
}

# ---------------------------------------------------------------------------
# Console summary
# ---------------------------------------------------------------------------

Write-InventoryLog "`n=== COLLECTION SUMMARY ===" Cyan
Write-InventoryLog "Successful checks: $($successfulChecks.Count)" Green
Write-InventoryLog "Unavailable checks: $($failedChecks.Count)" Yellow

foreach ($result in $results) {
    $status = if ($result.Success) {
        'SUCCESS'
    }
    else {
        'UNAVAILABLE'
    }

    $color = if ($result.Success) {
        'Green'
    }
    else {
        'Yellow'
    }

    Write-InventoryLog (
        ('{0,-24} {1}' -f $result.Check, $status)
    ) $color
}

# ---------------------------------------------------------------------------
# JSON export
# ---------------------------------------------------------------------------

if ($ExportReport) {
    if ([string]::IsNullOrWhiteSpace($ReportPath)) {
        $ReportPath = Join-Path `
            -Path $env:TEMP `
            -ChildPath "WindowsEnvironmentInventory_$timestamp.json"
    }

    $temporaryPath = $null

    try {
        $fullPath = [System.IO.Path]::GetFullPath($ReportPath)
        $directory = [System.IO.Path]::GetDirectoryName($fullPath)

        if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
            New-Item `
                -Path $directory `
                -ItemType Directory `
                -Force `
                -ErrorAction Stop | Out-Null
        }

        $json = ConvertTo-Json `
            -InputObject $report `
            -Depth 10 `
            -ErrorAction Stop

        $temporaryPath = Join-Path `
            -Path $directory `
            -ChildPath ([System.IO.Path]::GetRandomFileName() + '.tmp')

        [System.IO.File]::WriteAllText(
            $temporaryPath,
            $json,
            (New-Object System.Text.UTF8Encoding($false))
        )

        if (Test-Path -LiteralPath $fullPath -PathType Leaf) {
            [System.IO.File]::Replace(
                $temporaryPath,
                $fullPath,
                $null
            )
        }
        else {
            [System.IO.File]::Move(
                $temporaryPath,
                $fullPath
            )
        }

        Write-InventoryLog "`nReport exported successfully:" Green
        Write-InventoryLog $fullPath Cyan
    }
    catch {
        Write-InventoryLog (
            "`nReport export failed: $($_.Exception.Message)"
        ) Red
    }
    finally {
        if (
            -not [string]::IsNullOrWhiteSpace($temporaryPath) -and
            (Test-Path -LiteralPath $temporaryPath)
        ) {
            Remove-Item `
                -LiteralPath $temporaryPath `
                -Force `
                -ErrorAction SilentlyContinue
        }
    }
}

Write-InventoryLog "`n=== INVENTORY COMPLETE ===" Green
Write-InventoryLog "Read-only assessment. No system configuration was modified." Gray

return $report
