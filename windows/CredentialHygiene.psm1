
#Requires -Version 5.1

<#
.SYNOPSIS
    Certificate and credential hygiene review for authorized assessments.

.DESCRIPTION
    Performs read-only Windows security configuration checks.

    Covers:
      - Certificate inventory across selected Windows certificate stores.
      - Expired and near-expiry certificate identification.
      - Self-signed certificate indicators.
      - Cached Windows Credential Manager target metadata.
      - LSA protection configuration.
      - Credential Guard runtime status.

    Credential Manager passwords, hashes, and secrets are never retrieved.
    LSASS is never accessed, dumped, or modified.

.NOTES
    Compatible with Windows PowerShell 5.1.
    Some checks may require elevated permissions.
#>


function Get-CertificateInventory {
    <#
    .SYNOPSIS
        Inventories certificates in selected Windows certificate stores.

    .DESCRIPTION
        Flags expired and near-expiry certificates.

        SelfSigned is a subject/issuer equality indicator, not a complete
        cryptographic verification of a certificate's signature or trust.
    #>

    [CmdletBinding()]
    param(
        [ValidateRange(0, 3650)]
        [int]$ExpiryWarningDays = 30
    )

    $stores = @(
        'Cert:\LocalMachine\My',
        'Cert:\CurrentUser\My',
        'Cert:\LocalMachine\Root'
    )

    $now = Get-Date
    $warnDate = $now.AddDays($ExpiryWarningDays)

    $findings = @()

    foreach ($store in $stores) {
        try {
            $certificates = @(
                Get-ChildItem -Path $store -ErrorAction Stop
            )

            foreach ($certificate in $certificates) {
                $expired = $certificate.NotAfter -lt $now

                $expiringSoon = (
                    -not $expired -and
                    $certificate.NotAfter -le $warnDate
                )

                $findings += [PSCustomObject]@{
                    Store = $store
                    Subject = $certificate.Subject
                    Issuer = $certificate.Issuer
                    NotAfter = $certificate.NotAfter
                    NotBefore = $certificate.NotBefore
                    Thumbprint = $certificate.Thumbprint
                    SelfSignedIndicator = (
                        $certificate.Subject -eq $certificate.Issuer
                    )
                    Expired = $expired
                    ExpiringSoon = $expiringSoon
                    DaysUntilExpiry = [math]::Floor(
                        ($certificate.NotAfter - $now).TotalDays
                    )
                }
            }
        }
        catch {
            Write-Warning "Certificate inventory for '$store' failed: $($_.Exception.Message)"
        }
    }

    return @($findings)
}


function Get-CachedCredentialTargets {
    <#
    .SYNOPSIS
        Lists Windows Credential Manager target metadata.

    .DESCRIPTION
        Uses cmdkey /list and parses target names, entry types, and associated
        usernames where available.

        Does not retrieve, decrypt, display, or export passwords, hashes,
        authentication tokens, or other stored secrets.

        Output reflects the current user's accessible Credential Manager
        entries and may vary with Windows localization.
    #>

    [CmdletBinding()]
    param()

    $command = Get-Command cmdkey.exe -ErrorAction SilentlyContinue

    if (-not $command) {
        throw "cmdkey.exe was not found. This check requires Windows Credential Manager command-line support."
    }

    try {
        $raw = @(& $command.Source /list 2>&1)
        $exitCode = $LASTEXITCODE

        if ($exitCode -ne 0) {
            $details = ($raw | ForEach-Object { "$_" }) -join ' '
            throw "cmdkey /list failed with exit code $exitCode. $details"
        }

        $entries = @()
        $current = $null

        foreach ($line in $raw) {
            $text = [string]$line

            if ($text -match '^\s*Target\s*:\s*(.+)$') {
                if ($null -ne $current) {
                    $entries += $current
                }

                $current = [PSCustomObject]@{
                    Target = $Matches[1].Trim()
                    Type = $null
                    User = $null
                }

                continue
            }

            if ($null -eq $current) {
                continue
            }

            if ($text -match '^\s*Type\s*:\s*(.+)$') {
                $current.Type = $Matches[1].Trim()
                continue
            }

            if ($text -match '^\s*User\s*:\s*(.+)$') {
                $current.User = $Matches[1].Trim()
                continue
            }
        }

        if ($null -ne $current) {
            $entries += $current
        }

        return @($entries)
    }
    catch {
        throw "Cached credential target enumeration failed: $($_.Exception.Message)"
    }
}


function Get-CredentialProtectionStatus {
    <#
    .SYNOPSIS
        Checks LSA protection configuration and Credential Guard runtime status.

    .DESCRIPTION
        Reads the RunAsPPL registry value and queries the Windows Device Guard
        WMI/CIM provider.

        SecurityServicesRunning value 1 indicates Credential Guard.
        This is a runtime status check, not merely a configuration check.

        No interaction with LSASS occurs.
    #>

    [CmdletBinding()]
    param()

    $lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'

    $lsaPPL = $null
    $lsaPPLConfigured = $false
    $lsaRegistryStatus = 'Unknown'
    $deviceGuardServices = @()
    $credentialGuardRunning = $false
    $deviceGuardAvailable = $false
    $errors = @()

    try {
        $lsaSettings = Get-ItemProperty `
            -Path $lsaPath `
            -Name RunAsPPL `
            -ErrorAction Stop

        $lsaPPL = $lsaSettings.RunAsPPL
        $lsaRegistryStatus = 'ValuePresent'

        $lsaPPLConfigured = (
            $lsaPPL -eq 1 -or
            $lsaPPL -eq 2
        )
    }
    catch {
        if ($_.CategoryInfo.Category -eq 'ObjectNotFound') {
            $lsaRegistryStatus = 'ValueNotPresent'
            $lsaPPLConfigured = $false
        }
        else {
            $lsaRegistryStatus = 'QueryFailed'
            $errors += "LSA protection registry query: $($_.Exception.Message)"
        }
    }

    try {
        $deviceGuard = Get-CimInstance `
            -ClassName Win32_DeviceGuard `
            -Namespace 'root\Microsoft\Windows\DeviceGuard' `
            -ErrorAction Stop

        $deviceGuardAvailable = $true

        $deviceGuardServices = @(
            $deviceGuard.SecurityServicesRunning
        )

        $credentialGuardRunning = (
            $deviceGuardServices -contains 1
        )
    }
    catch {
        $errors += "Device Guard status query: $($_.Exception.Message)"
    }

    return [PSCustomObject]@{
        LsaProtectionEnabled = $lsaPPLConfigured
        LsaRegistryStatus = $lsaRegistryStatus
        LsaProtectionRegistryValue = $lsaPPL
        CredentialGuardRunning = $credentialGuardRunning
        DeviceGuardAvailable = $deviceGuardAvailable
        RawDeviceGuardServices = @($deviceGuardServices)
        Errors = @($errors)
        CollectionStatus = if ($errors.Count -gt 0) { 'Partial' } else { 'Complete' }
    }
}


function Invoke-CredentialHygieneAssessment {
    <#
    .SYNOPSIS
        Runs certificate and credential hygiene checks.

    .PARAMETER ExpiryWarningDays
        Number of days before certificate expiry to generate a warning.

    .PARAMETER OutputPath
        Optional path for the JSON report.

    .OUTPUTS
        Report object containing:
          GeneratedAt
          Certificates
          CachedCredentialTargets
          ProtectionStatus
          AssessmentErrors
    #>

    [CmdletBinding()]
    param(
        [ValidateRange(0, 3650)]
        [int]$ExpiryWarningDays = 30,

        [string]$OutputPath
    )

    $report = [PSCustomObject]@{
        GeneratedAt = (Get-Date).ToUniversalTime().ToString('o')
        Certificates = @()
        CachedCredentialTargets = @()
        ProtectionStatus = $null
        AssessmentErrors = @()
    }

    $errors = @()

    $checks = @(
        @{
            Name = 'Certificate inventory'
            Property = 'Certificates'
            Action = {
                Get-CertificateInventory -ExpiryWarningDays $ExpiryWarningDays
            }
        },
        @{
            Name = 'Cached credential targets'
            Property = 'CachedCredentialTargets'
            Action = {
                Get-CachedCredentialTargets
            }
        },
        @{
            Name = 'Credential protection status'
            Property = 'ProtectionStatus'
            Action = {
                Get-CredentialProtectionStatus
            }
        }
    )

    foreach ($check in $checks) {
        try {
            Write-Verbose "Running check: $($check.Name)"

            $result = @(& $check.Action)

            if ($check.Property -eq 'ProtectionStatus') {
                $report.ProtectionStatus = $result | Select-Object -First 1
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
    'Get-CertificateInventory',
    'Get-CachedCredentialTargets',
    'Get-CredentialProtectionStatus',
    'Invoke-CredentialHygieneAssessment'
)
