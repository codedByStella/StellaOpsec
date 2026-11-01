
#Requires -Version 5.1

<#
.SYNOPSIS
    Azure cloud posture checks for authorized assessments.

.DESCRIPTION
    Performs read-only configuration checks using the Azure CLI.

    Covers:
      - Azure Storage container public-access configuration.
      - Network Security Group inbound rules with broad internet sources.
      - Privileged Azure RBAC role assignments.
      - Azure SQL Server public network access and firewall rules.

    The module does not create, modify, or delete Azure resources.

    Entra ID directory roles and MFA registration/status are not assessed
    by this module. Azure RBAC role assignments are reported separately.

.NOTES
    Requires:
      - Azure CLI (az) installed and available on PATH.
      - An authenticated Azure CLI session (az login).
      - Sufficient read permissions for the resources being assessed.

    Compatible with Windows PowerShell 5.1.
#>

Set-StrictMode -Version 2.0


function Test-AzCliAvailable {
    <#
    .SYNOPSIS
        Checks whether Azure CLI is installed and accessible.
    #>

    [CmdletBinding()]
    param()

    $command = Get-Command az -ErrorAction SilentlyContinue

    if (-not $command) {
        throw "Azure CLI was not found on PATH. Install it from https://learn.microsoft.com/cli/azure/install-azure-cli"
    }

    return $true
}


function Invoke-AzCli {
    <#
    .SYNOPSIS
        Executes an Azure CLI command and parses its JSON output.

    .DESCRIPTION
        Uses an argument array rather than Invoke-Expression. This avoids
        evaluating dynamically assembled command strings.

        Errors are raised to the calling function so the assessment can
        record failed checks instead of silently treating them as empty.
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Arguments
    )

    $command = Get-Command az -ErrorAction Stop
    $executable = $command.Source

    if ([string]::IsNullOrWhiteSpace($executable)) {
        $executable = $command.Path
    }

    if ([string]::IsNullOrWhiteSpace($executable)) {
        throw "Unable to resolve the Azure CLI executable path."
    }

    $fullArguments = @($Arguments) + @('--output', 'json')

    $raw = @(& $executable @fullArguments 2>&1)
    $exitCode = $LASTEXITCODE

    if ($exitCode -ne 0) {
        $details = ($raw | ForEach-Object { "$_" }) -join [Environment]::NewLine

        throw "Azure CLI command failed with exit code $exitCode. Arguments: $($Arguments -join ' '). Output: $details"
    }

    $jsonText = ($raw | ForEach-Object { "$_" }) -join [Environment]::NewLine

    if ([string]::IsNullOrWhiteSpace($jsonText)) {
        return @()
    }

    try {
        return ConvertFrom-Json -InputObject $jsonText -ErrorAction Stop
    }
    catch {
        throw "Unable to parse Azure CLI JSON output: $($_.Exception.Message)"
    }
}


function Get-AzureCliSubscriptionArguments {
    <#
    .SYNOPSIS
        Returns the subscription argument pair when a subscription is supplied.
    #>

    [CmdletBinding()]
    param(
        [string]$SubscriptionId
    )

    if ([string]::IsNullOrWhiteSpace($SubscriptionId)) {
        return @()
    }

    return @('--subscription', $SubscriptionId)
}


function Get-AzurePublicStorageContainers {
    <#
    .SYNOPSIS
        Lists storage containers and identifies configured public access.

    .DESCRIPTION
        Reports whether the storage account permits blob public access and
        whether each container has public access configured.

        Container public access is only effective when account-level public
        blob access is also permitted. This check does not independently
        verify every possible data-plane access path.
    #>

    [CmdletBinding()]
    param(
        [string]$SubscriptionId
    )

    $null = Test-AzCliAvailable
    $subArgs = @(Get-AzureCliSubscriptionArguments -SubscriptionId $SubscriptionId)

    $accounts = @(
        Invoke-AzCli -Arguments (@('storage', 'account', 'list') + $subArgs)
    )

    $findings = @()

    foreach ($account in $accounts) {
        $name = [string]$account.name
        $resourceGroup = [string]$account.resourceGroup
        $allowBlobPublic = $account.allowBlobPublicAccess

        if ([string]::IsNullOrWhiteSpace($name)) {
            continue
        }

        try {
            $containers = @(
                Invoke-AzCli -Arguments (
                    @(
                        'storage', 'container', 'list',
                        '--account-name', $name,
                        '--auth-mode', 'login'
                    ) + $subArgs
                )
            )

            foreach ($container in $containers) {
                $publicAccess = $container.properties.publicAccess

                if ($null -eq $publicAccess) {
                    $publicAccess = $container.publicAccess
                }

                $containerAllowsPublic = (
                    -not [string]::IsNullOrWhiteSpace([string]$publicAccess) -and
                    [string]$publicAccess -ne 'None'
                )

                $accountPublicSettingKnown = ($null -ne $allowBlobPublic)
                $accountAllowsPublic = if ($accountPublicSettingKnown) {
                    [bool]$allowBlobPublic
                } else {
                    $null
                }

                $findings += [PSCustomObject]@{
                    StorageAccount = $name
                    ResourceGroup = $resourceGroup
                    AccountAllowsPublic = $allowBlobPublic
                    ContainerName = $container.name
                    ContainerPublicAccess = $publicAccess
                    ContainerHasPublicAccessSetting = $containerAllowsPublic
                    LikelyPublic = if (-not $accountPublicSettingKnown) {
                        $null
                    } else {
                        [bool]($accountAllowsPublic -and $containerAllowsPublic)
                    }
                    AssessmentStatus = if (-not $accountPublicSettingKnown) {
                        'InconclusiveAccountSettingUnavailable'
                    } else {
                        'Evaluated'
                    }
                }
            }
        }
        catch {
            $findings += [PSCustomObject]@{
                StorageAccount = $name
                ResourceGroup = $resourceGroup
                AccountAllowsPublic = $allowBlobPublic
                ContainerName = $null
                ContainerPublicAccess = $null
                ContainerHasPublicAccessSetting = $null
                LikelyPublic = $null
                Error = $_.Exception.Message
            }
        }
    }

    return @($findings)
}


function Get-AzureNsgAudit {
    <#
    .SYNOPSIS
        Identifies broad-source inbound NSG rules affecting sensitive ports.

    .DESCRIPTION
        Checks inbound Allow rules with broad source prefixes, including
        Internet, Any, *, IPv4 default routes, and IPv6 default routes.

        Handles singular and plural source/destination port properties.

        This is a rule-level configuration review. It does not calculate
        effective connectivity or account for every subnet, NIC, route,
        application security group, or other network control.
    #>

    [CmdletBinding()]
    param(
        [string]$SubscriptionId,

        [ValidateRange(1, 65535)]
        [int[]]$SensitivePorts = @(
            22, 3389, 1433, 3306, 5432, 6379, 9200, 27017
        )
    )

    $null = Test-AzCliAvailable
    $subArgs = @(Get-AzureCliSubscriptionArguments -SubscriptionId $SubscriptionId)

    $nsgs = @(
        Invoke-AzCli -Arguments (
            @('network', 'nsg', 'list') + $subArgs
        )
    )

    $findings = @()

    foreach ($nsg in $nsgs) {
        foreach ($rule in @($nsg.securityRules)) {
            if ($rule.direction -ne 'Inbound' -or $rule.access -ne 'Allow') {
                continue
            }

            $sourcePrefixes = @()

            if ($rule.sourceAddressPrefix) {
                $sourcePrefixes += @($rule.sourceAddressPrefix)
            }

            if ($rule.sourceAddressPrefixes) {
                $sourcePrefixes += @($rule.sourceAddressPrefixes)
            }

            $broadSources = @(
                $sourcePrefixes | Where-Object {
                    $_ -in @(
                        '*',
                        'Internet',
                        '0.0.0.0/0',
                        '::/0',
                        'Any'
                    )
                } | Select-Object -Unique
            )

            if ($broadSources.Count -eq 0) {
                continue
            }

            $destinationPorts = @()

            if ($rule.destinationPortRange) {
                $destinationPorts += @($rule.destinationPortRange)
            }

            if ($rule.destinationPortRanges) {
                $destinationPorts += @($rule.destinationPortRanges)
            }

            $matchedPorts = @()
            $allPorts = $false

            foreach ($portEntry in $destinationPorts) {
                $portText = [string]$portEntry

                if ($portText -eq '*') {
                    $allPorts = $true
                    $matchedPorts += '*'
                    continue
                }

                if ($portText -match '^(\d+)-(\d+)$') {
                    $low = [int]$Matches[1]
                    $high = [int]$Matches[2]

                    if ($low -gt $high) {
                        continue
                    }

                    $matchesSensitive = @(
                        $SensitivePorts | Where-Object {
                            $_ -ge $low -and $_ -le $high
                        }
                    )

                    if ($matchesSensitive.Count -gt 0) {
                        $matchedPorts += $portText
                    }

                    continue
                }

                if ($portText -match '^\d+$') {
                    if ([int]$portText -in $SensitivePorts) {
                        $matchedPorts += $portText
                    }
                }
            }

            if ($allPorts -or $matchedPorts.Count -gt 0) {
                $findings += [PSCustomObject]@{
                    NsgName = $nsg.name
                    ResourceGroup = $nsg.resourceGroup
                    RuleName = $rule.name
                    Priority = $rule.priority
                    Protocol = $rule.protocol
                    DestinationPorts = @($matchedPorts | Select-Object -Unique)
                    SourcePrefixes = @($broadSources)
                    AllPorts = $allPorts
                    Access = $rule.access
                    Direction = $rule.direction
                }
            }
        }
    }

    return @($findings)
}


function Get-AzureAdUserHygiene {
    <#
    .SYNOPSIS
        Lists principals with privileged Azure RBAC role assignments.

    .DESCRIPTION
        Reports Owner, Contributor, and Administrator-named Azure RBAC
        assignments at subscription scope and below.

        This does not enumerate Entra ID directory roles, verify MFA
        registration, evaluate Conditional Access, or establish whether
        an account is currently using MFA.
    #>

    [CmdletBinding()]
    param(
        [string]$SubscriptionId
    )

    $null = Test-AzCliAvailable
    $subArgs = @(Get-AzureCliSubscriptionArguments -SubscriptionId $SubscriptionId)

    $assignments = @(
        Invoke-AzCli -Arguments (
            @('role', 'assignment', 'list', '--all') + $subArgs
        )
    )

    $findings = @(
        foreach ($assignment in $assignments) {
            $roleName = [string]$assignment.roleDefinitionName

            if (
                $roleName -match '(?i)\bOwner\b' -or
                $roleName -match '(?i)\bContributor\b' -or
                $roleName -match '(?i)\bAdministrator\b'
            ) {
                [PSCustomObject]@{
                    Principal = $assignment.principalName
                    PrincipalId = $assignment.principalId
                    PrincipalType = $assignment.principalType
                    Role = $roleName
                    Scope = $assignment.scope
                    Condition = $assignment.condition
                }
            }
        }
    )

    return @($findings)
}


function Get-AzureSqlAudit {
    <#
    .SYNOPSIS
        Identifies Azure SQL servers with broad firewall rules or public access.

    .DESCRIPTION
        Reports the server's public network access setting and identifies
        firewall rules spanning the entire IPv4 address range.

        This function does not audit Transparent Data Encryption (TDE),
        database-level encryption, TLS configuration, or private endpoint
        connectivity. It should not be described as an encryption audit.
    #>

    [CmdletBinding()]
    param(
        [string]$SubscriptionId
    )

    $null = Test-AzCliAvailable
    $subArgs = @(Get-AzureCliSubscriptionArguments -SubscriptionId $SubscriptionId)

    $servers = @(
        Invoke-AzCli -Arguments (
            @('sql', 'server', 'list') + $subArgs
        )
    )

    $findings = @()

    foreach ($server in $servers) {
        $name = [string]$server.name
        $resourceGroup = [string]$server.resourceGroup

        if (
            [string]::IsNullOrWhiteSpace($name) -or
            [string]::IsNullOrWhiteSpace($resourceGroup)
        ) {
            continue
        }

        try {
            $rules = @(
                Invoke-AzCli -Arguments (
                    @(
                        'sql', 'server', 'firewall-rule', 'list',
                        '--server', $name,
                        '--resource-group', $resourceGroup
                    ) + $subArgs
                )
            )

            $openRules = @(
                $rules | Where-Object {
                    $_.startIpAddress -eq '0.0.0.0' -and
                    $_.endIpAddress -eq '255.255.255.255'
                }
            )

            $findings += [PSCustomObject]@{
                ServerName = $name
                ResourceGroup = $resourceGroup
                PublicNetworkAccess = $server.publicNetworkAccess
                FirewallOpenToAllIpv4 = ($openRules.Count -gt 0)
                OpenFirewallRules = @(
                    $openRules | ForEach-Object {
                        [PSCustomObject]@{
                            RuleName = $_.name
                            StartIpAddress = $_.startIpAddress
                            EndIpAddress = $_.endIpAddress
                        }
                    }
                )
                FirewallRulesRetrieved = $true
            }
        }
        catch {
            $findings += [PSCustomObject]@{
                ServerName = $name
                ResourceGroup = $resourceGroup
                PublicNetworkAccess = $server.publicNetworkAccess
                FirewallOpenToAllIpv4 = $null
                OpenFirewallRules = @()
                FirewallRulesRetrieved = $false
                Error = $_.Exception.Message
            }
        }
    }

    return @($findings)
}


function Invoke-AzurePostureAssessment {
    <#
    .SYNOPSIS
        Runs the Azure posture checks and returns a consolidated report.

    .PARAMETER SubscriptionId
        Optional Azure subscription ID. When omitted, the Azure CLI's
        currently selected subscription is used.

    .PARAMETER OutputPath
        Optional destination for the JSON report.

    .OUTPUTS
        A report object containing:
          GeneratedAt
          SubscriptionId
          PublicStorageContainers
          OpenNsgRules
          PrivilegedRoleHolders
          SqlServers
          AssessmentErrors
    #>

    [CmdletBinding()]
    param(
        [string]$SubscriptionId,
        [string]$OutputPath
    )

    $null = Test-AzCliAvailable

    $report = [PSCustomObject]@{
        GeneratedAt = (Get-Date).ToUniversalTime().ToString('o')
        SubscriptionId = $SubscriptionId
        PublicStorageContainers = @()
        OpenNsgRules = @()
        PrivilegedRoleHolders = @()
        SqlServers = @()
        AssessmentErrors = @()
    }

    $checks = @(
        @{
            Name = 'Azure Storage containers'
            Property = 'PublicStorageContainers'
            Action = {
                Get-AzurePublicStorageContainers -SubscriptionId $SubscriptionId
            }
        },
        @{
            Name = 'Network Security Groups'
            Property = 'OpenNsgRules'
            Action = {
                Get-AzureNsgAudit -SubscriptionId $SubscriptionId
            }
        },
        @{
            Name = 'Azure RBAC privileged assignments'
            Property = 'PrivilegedRoleHolders'
            Action = {
                Get-AzureAdUserHygiene -SubscriptionId $SubscriptionId
            }
        },
        @{
            Name = 'Azure SQL servers'
            Property = 'SqlServers'
            Action = {
                Get-AzureSqlAudit -SubscriptionId $SubscriptionId
            }
        }
    )

    $errors = @()

    foreach ($check in $checks) {
        try {
            Write-Verbose "Running check: $($check.Name)"

            $result = @(& $check.Action)
            $report.($check.Property) = @($result)
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
            Set-Content -LiteralPath $fullPath -Value $json -Encoding UTF8 -ErrorAction Stop

            Write-Verbose "Report written to: $fullPath"
        }
        catch {
            throw "Assessment completed, but the report could not be written to '$OutputPath': $($_.Exception.Message)"
        }
    }

    return $report
}


Export-ModuleMember -Function @(
    'Test-AzCliAvailable',
    'Get-AzurePublicStorageContainers',
    'Get-AzureNsgAudit',
    'Get-AzureAdUserHygiene',
    'Get-AzureSqlAudit',
    'Invoke-AzurePostureAssessment'
)
