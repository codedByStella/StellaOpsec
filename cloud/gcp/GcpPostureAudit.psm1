
#Requires -Version 5.1
<#
.SYNOPSIS
    GCP cloud posture checks for authorized assessments.

.DESCRIPTION
    Performs read-only GCP posture checks using the authenticated Google
    Cloud CLI. Covers GCS bucket IAM exposure, internet-facing ingress
    firewall rules, project-level primitive IAM roles, and Cloud SQL
    network configuration.

    Commands retrieve resource inventories and IAM policies. Nothing
    here creates, modifies, or deletes cloud resources.

    Assessment errors are recorded separately from findings. A missing
    result must not be interpreted as proof that a resource is secure.

.NOTES
    Requires:
      - Google Cloud SDK (gcloud) on PATH
      - An authenticated gcloud session
      - Appropriate read permissions for the assessed project

    Example:
      gcloud auth login

    Reports may contain sensitive project identifiers, bucket names,
    network configuration, and IAM principals.
#>

$script:GcpAssessmentErrors = New-Object System.Collections.Generic.List[string]

function Add-GcpAssessmentError {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message
    )

    $script:GcpAssessmentErrors.Add($Message)
}

function Test-GcpProjectId {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ProjectId
    )

    # GCP project IDs are 6-30 characters, lowercase, and may contain
    # lowercase letters, numbers, and hyphens.
    return ($ProjectId -match '^[a-z][a-z0-9-]{4,28}[a-z0-9]$')
}

function Test-GcloudAvailable {
    [CmdletBinding()]
    param()

    if (-not (Get-Command gcloud -ErrorAction SilentlyContinue)) {
        Write-Warning "gcloud CLI not found on PATH. Install: https://cloud.google.com/sdk/docs/install"
        return $false
    }

    return $true
}

function Invoke-Gcloud {
    <#
    .SYNOPSIS
        Executes gcloud using a safely separated argument array.

    .DESCRIPTION
        No dynamically constructed shell command or Invoke-Expression
        is used. The command's exit code and JSON parsing errors are
        handled explicitly.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Arguments,

        [string]$ProjectId,

        [string]$Context = 'gcloud command'
    )

    if (-not (Test-GcloudAvailable)) {
        Add-GcpAssessmentError "$Context : gcloud CLI is unavailable."
        return $null
    }

    if ($ProjectId -and -not (Test-GcpProjectId -ProjectId $ProjectId)) {
        Add-GcpAssessmentError "$Context : invalid project ID."
        return $null
    }

    $finalArguments = @($Arguments)

    if ($ProjectId) {
        $finalArguments += @('--project', $ProjectId)
    }

    $finalArguments += @('--format=json')

    try {
        $rawOutput = @(& gcloud @finalArguments 2>&1)
        $exitCode = $LASTEXITCODE

        if ($exitCode -ne 0) {
            $errorText = ($rawOutput | ForEach-Object { [string]$_ }) -join ' '

            Add-GcpAssessmentError (
                "$Context failed with exit code $exitCode. $errorText"
            )

            Write-Warning "$Context failed with exit code $exitCode."
            return $null
        }

        $jsonText = ($rawOutput | ForEach-Object { [string]$_ }) -join "`n"

        if ([string]::IsNullOrWhiteSpace($jsonText)) {
            return @()
        }

        try {
            return ($jsonText | ConvertFrom-Json -ErrorAction Stop)
        }
        catch {
            Add-GcpAssessmentError (
                "$Context returned invalid JSON: $($_.Exception.Message)"
            )

            Write-Warning "$Context returned invalid JSON."
            return $null
        }
    }
    catch {
        Add-GcpAssessmentError (
            "$Context threw an exception: $($_.Exception.Message)"
        )

        Write-Warning "$Context failed: $($_.Exception.Message)"
        return $null
    }
}

function Get-GcpPublicBuckets {
    <#
    .SYNOPSIS
        Identifies GCS bucket IAM bindings granting access to allUsers
        or allAuthenticatedUsers.

    .DESCRIPTION
        allUsers permits access without authentication.
        allAuthenticatedUsers applies to authenticated Google accounts.

        This function inventories IAM bindings. It does not independently
        prove that every object in a bucket is readable or writable.
    #>
    [CmdletBinding()]
    param(
        [string]$ProjectId
    )

    if (-not (Test-GcloudAvailable)) {
        Add-GcpAssessmentError 'GCS bucket assessment skipped: gcloud unavailable.'
        return
    }

    $buckets = Invoke-Gcloud `
        -Arguments @('storage', 'buckets', 'list') `
        -ProjectId $ProjectId `
        -Context 'GCS bucket inventory'

    if ($null -eq $buckets) {
        return
    }

    foreach ($bucket in @($buckets)) {
        $name = [string]$bucket.name

        if ([string]::IsNullOrWhiteSpace($name)) {
            continue
        }

        $policy = Invoke-Gcloud `
            -Arguments @(
                'storage',
                'buckets',
                'get-iam-policy',
                "gs://$name"
            ) `
            -ProjectId $ProjectId `
            -Context "GCS IAM policy retrieval for $name"

        $anonymousBindings = New-Object System.Collections.Generic.List[string]
        $authenticatedBindings = New-Object System.Collections.Generic.List[string]

        if ($null -ne $policy -and $policy.bindings) {
            foreach ($binding in $policy.bindings) {
                foreach ($member in @($binding.members)) {
                    if ($member -eq 'allUsers') {
                        $anonymousBindings.Add(
                            "$($binding.role) -> allUsers"
                        )
                    }
                    elseif ($member -eq 'allAuthenticatedUsers') {
                        $authenticatedBindings.Add(
                            "$($binding.role) -> allAuthenticatedUsers"
                        )
                    }
                }
            }
        }

        [PSCustomObject]@{
            BucketName                    = $name
            Location                      = $bucket.location
            AnonymousAccessBindings      = @($anonymousBindings.ToArray())
            AuthenticatedAccessBindings  = @($authenticatedBindings.ToArray())
            AllowsUnauthenticatedAccess  = ($anonymousBindings.Count -gt 0)
            AllowsAuthenticatedPublicAccess = ($authenticatedBindings.Count -gt 0)
            HasBroadAccessBinding         = (
                $anonymousBindings.Count -gt 0 -or
                $authenticatedBindings.Count -gt 0
            )
        }
    }
}

function Get-GcpFirewallAudit {
    <#
    .SYNOPSIS
        Identifies ingress firewall rules with internet-wide source ranges
        and sensitive or unrestricted port access.

    .DESCRIPTION
        Checks IPv4 0.0.0.0/0 and IPv6 ::/0.
        Reports the matching source range, protocol, and port configuration.

        This is a configuration inventory, not a complete effective
        connectivity analysis. Hierarchical firewall policies, routes,
        target tags, service accounts, and other controls can affect
        actual reachability.
    #>
    [CmdletBinding()]
    param(
        [string]$ProjectId,

        [ValidateRange(1, 65535)]
        [int[]]$SensitivePorts = @(
            22, 3389, 1433, 3306, 5432,
            6379, 9200, 27017
        )
    )

    if (-not (Test-GcloudAvailable)) {
        Add-GcpAssessmentError 'Firewall assessment skipped: gcloud unavailable.'
        return
    }

    $rules = Invoke-Gcloud `
        -Arguments @('compute', 'firewall-rules', 'list') `
        -ProjectId $ProjectId `
        -Context 'Firewall rule inventory'

    if ($null -eq $rules) {
        return
    }

    foreach ($rule in @($rules)) {
        if ($rule.direction -ne 'INGRESS' -or $rule.disabled -eq $true) {
            continue
        }

        $internetRanges = @(
            $rule.sourceRanges |
                Where-Object { $_ -in @('0.0.0.0/0', '::/0') }
        )

        if ($internetRanges.Count -eq 0) {
            continue
        }

        foreach ($allowed in @($rule.allowed)) {
            $protocol = [string]$allowed.IPProtocol
            $portSpecs = @($allowed.ports)

            # Port numbers apply to TCP, UDP, and SCTP. ICMP/ESP/AH do not
            # have TCP-style ports. 'all' includes port-based protocols.
            $portBasedProtocol = $protocol -in @('tcp', 'udp', 'sctp', 'all')
            $allPorts = ($portSpecs.Count -eq 0 -and $portBasedProtocol)
            $portHits = New-Object System.Collections.Generic.List[int]

            if ($allPorts) {
                foreach ($port in $SensitivePorts) {
                    $portHits.Add($port)
                }
            }
            else {
                foreach ($portSpec in $portSpecs) {
                    $portSpec = [string]$portSpec

                    if ($portSpec -match '^\d+$') {
                        $portNumber = [int]$portSpec

                        if ($portNumber -in $SensitivePorts) {
                            $portHits.Add($portNumber)
                        }
                    }
                    elseif ($portSpec -match '^(\d+)-(\d+)$') {
                        $lower = [int]$Matches[1]
                        $upper = [int]$Matches[2]

                        if ($lower -gt $upper) {
                            continue
                        }

                        foreach ($port in $SensitivePorts) {
                            if ($port -ge $lower -and $port -le $upper) {
                                $portHits.Add($port)
                            }
                        }
                    }
                }
            }

            if ($allPorts -or $portHits.Count -gt 0) {
                [PSCustomObject]@{
                    RuleName          = $rule.name
                    Network           = $rule.network
                    Direction         = $rule.direction
                    Protocol          = $protocol
                    Ports             = ($portSpecs -join ',')
                    AllPorts          = $allPorts
                    SensitivePortsHit = @($portHits.ToArray() | Sort-Object -Unique)
                    InternetSourceRanges = @($internetRanges)
                    OpenToWorld       = $true
                    Disabled          = $false
                }
            }
        }
    }
}

function Get-GcpIamPrimitiveRoleAudit {
    <#
    .SYNOPSIS
        Identifies project-level Owner and Editor IAM bindings.

    .DESCRIPTION
        Reports members assigned the primitive roles roles/owner and
        roles/editor. These broad roles are indicators for review, not
        proof that a particular member has excessive effective access.

        Conditional bindings are included with their condition metadata.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ProjectId
    )

    if (-not (Test-GcpProjectId -ProjectId $ProjectId)) {
        Add-GcpAssessmentError 'IAM assessment skipped: invalid project ID.'
        return
    }

    $policy = Invoke-Gcloud `
        -Arguments @('projects', 'get-iam-policy', $ProjectId) `
        -Context "Project IAM policy retrieval for $ProjectId"

    if ($null -eq $policy -or -not $policy.bindings) {
        return
    }

    $primitiveBindings = @(
        $policy.bindings |
            Where-Object {
                $_.role -in @('roles/owner', 'roles/editor')
            }
    )

    foreach ($binding in $primitiveBindings) {
        foreach ($member in @($binding.members)) {
            [PSCustomObject]@{
                ProjectId       = $ProjectId
                Role            = $binding.role
                Member          = $member
                ConditionTitle  = $binding.condition.title
                Condition       = $binding.condition.expression
                ConditionDescription = $binding.condition.description
            }
        }
    }
}

function Get-GcpCloudSqlAudit {
    <#
    .SYNOPSIS
        Reports Cloud SQL public IP assignments and network configuration.

    .DESCRIPTION
        Distinguishes an assigned PRIMARY IP address from the instance
        IPv4 configuration setting. Also reports SSL requirement and
        authorized networks.

        This function reports configuration; it does not test connectivity.
    #>
    [CmdletBinding()]
    param(
        [string]$ProjectId
    )

    if (-not (Test-GcloudAvailable)) {
        Add-GcpAssessmentError 'Cloud SQL assessment skipped: gcloud unavailable.'
        return
    }

    $instances = Invoke-Gcloud `
        -Arguments @('sql', 'instances', 'list') `
        -ProjectId $ProjectId `
        -Context 'Cloud SQL instance inventory'

    if ($null -eq $instances) {
        return
    }

    foreach ($instance in @($instances)) {
        $primaryAddresses = @(
            $instance.ipAddresses |
                Where-Object { $_.type -eq 'PRIMARY' }
        )

        $authorizedNetworks = @(
            $instance.settings.ipConfiguration.authorizedNetworks |
                ForEach-Object { $_.value }
        )

        [PSCustomObject]@{
            InstanceName       = $instance.name
            DatabaseVersion    = $instance.databaseVersion
            Region             = $instance.region
            PublicIpAssigned   = ($primaryAddresses.Count -gt 0)
            PublicIpAddresses  = @($primaryAddresses | ForEach-Object { $_.ipAddress })
            Ipv4Enabled        = $instance.settings.ipConfiguration.ipv4Enabled
            RequireSsl         = $instance.settings.ipConfiguration.requireSsl
            AuthorizedNetworks = @($authorizedNetworks)
        }
    }
}

function Invoke-GcpPostureAssessment {
    <#
    .SYNOPSIS
        Runs all GCP checks and returns one report object.

    .DESCRIPTION
        Returns findings and collection errors separately. An assessment
        with collection errors must not be treated as a complete clean scan.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ProjectId,

        [string]$OutputPath
    )

    if (-not (Test-GcpProjectId -ProjectId $ProjectId)) {
        throw "Invalid GCP project ID '$ProjectId'. Expected a valid lowercase GCP project ID."
    }

    $script:GcpAssessmentErrors.Clear()

    Write-Host "=== GCP Posture Assessment: $ProjectId ===" -ForegroundColor Cyan

    $publicBuckets = @(
        Get-GcpPublicBuckets -ProjectId $ProjectId
    )

    $firewallRules = @(
        Get-GcpFirewallAudit -ProjectId $ProjectId
    )

    $primitiveRoles = @(
        Get-GcpIamPrimitiveRoleAudit -ProjectId $ProjectId
    )

    $cloudSqlInstances = @(
        Get-GcpCloudSqlAudit -ProjectId $ProjectId
    )

    $report = [PSCustomObject]@{
        GeneratedAt          = (Get-Date).ToUniversalTime().ToString('o')
        ProjectId            = $ProjectId
        PublicBuckets        = @($publicBuckets)
        OpenFirewallRules    = @($firewallRules)
        PrimitiveRoleGrants  = @($primitiveRoles)
        CloudSqlInstances    = @($cloudSqlInstances)
        AssessmentErrors     = @($script:GcpAssessmentErrors.ToArray())
        CollectionSuccessful = ($script:GcpAssessmentErrors.Count -eq 0)
    }

    if ($OutputPath) {
        $parent = Split-Path -Parent $OutputPath

        if ($parent -and -not (Test-Path -LiteralPath $parent)) {
            New-Item -Path $parent -ItemType Directory -Force -ErrorAction Stop |
                Out-Null
        }

        $report |
            ConvertTo-Json -Depth 10 |
            Set-Content -LiteralPath $OutputPath -Encoding UTF8 -ErrorAction Stop

        Write-Host "Report written to $OutputPath" -ForegroundColor Green
    }

    if (-not $report.CollectionSuccessful) {
        Write-Warning "Assessment completed with $($report.AssessmentErrors.Count) collection error(s). Review AssessmentErrors."
    }

    return $report
}

Export-ModuleMember -Function @(
    'Test-GcloudAvailable',
    'Get-GcpPublicBuckets',
    'Get-GcpFirewallAudit',
    'Get-GcpIamPrimitiveRoleAudit',
    'Get-GcpCloudSqlAudit',
    'Invoke-GcpPostureAssessment'
)
