
#Requires -Version 5.1
<#
.SYNOPSIS
    Reporting layer: converts assessment objects into standalone HTML reports.

.DESCRIPTION
    Consumes report objects produced by host, Active Directory, event log,
    credential hygiene, and network assessment modules.

    Generates an HTML findings report with severity classifications,
    recommendations, and optional collapsible raw assessment data.

    This module only formats and presents previously collected information.
    It does not perform system or network collection.

.NOTES
    Treat generated reports as sensitive assessment data.
    Run only as part of authorized assessment and reporting activities.
#>

# ---------------------------------------------------------------------------
# Finding construction
# ---------------------------------------------------------------------------
function New-Finding {
    <#
    .SYNOPSIS
        Constructs a standardized finding object.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Title,

        [Parameter(Mandatory)]
        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Info')]
        [string]$Severity,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Description,

        [AllowEmptyString()]
        [string]$Evidence,

        [AllowEmptyString()]
        [string]$Recommendation
    )

    [PSCustomObject]@{
        Title          = $Title
        Severity       = $Severity
        Description    = $Description
        Evidence       = $Evidence
        Recommendation = $Recommendation
    }
}

# ---------------------------------------------------------------------------
# Automatic host findings
# ---------------------------------------------------------------------------
function Get-AutoFindings {
    <#
    .SYNOPSIS
        Generates basic findings from a host assessment report.

    .DESCRIPTION
        Identifies selected configuration conditions from the output of
        Invoke-HostAssessment.

        These checks are indicators for review, not independent proof of
        exploitability or confirmed security impact.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        $HostReport
    )

    $findings = New-Object 'System.Collections.Generic.List[object]'

    # Unquoted service executable paths.
    $services = @()

    if ($null -ne $HostReport.ServiceConfig) {
        $services = @(
            $HostReport.ServiceConfig |
                Where-Object {
                    $_.PSObject.Properties['UnquotedPathRisk'] -and
                    $_.UnquotedPathRisk -eq $true
                }
        )
    }

    foreach ($service in $services) {
        $findings.Add(
            (New-Finding `
                -Title "Unquoted service path: $($service.Name)" `
                -Severity 'Medium' `
                -Description (
                    'The service executable path contains whitespace and ' +
                    'is not enclosed in quotation marks. This configuration ' +
                    'warrants review, but exploitability depends on executable ' +
                    'resolution and relevant directory permissions.'
                ) `
                -Evidence $service.PathName `
                -Recommendation (
                    'Review the service ImagePath and directory permissions. ' +
                    'Quote the executable path where appropriate.'
                ))
        )
    }

    # Accounts configured without a password requirement.
    $localUsers = @()

    if (
        $null -ne $HostReport.LocalAccounts -and
        $null -ne $HostReport.LocalAccounts.LocalUsers
    ) {
        $localUsers = @($HostReport.LocalAccounts.LocalUsers)
    }

    foreach ($user in $localUsers) {
        if ($user.PasswordRequired -eq $false) {
            $findings.Add(
                (New-Finding `
                    -Title "Password not required: $($user.Name)" `
                    -Severity 'High' `
                    -Description (
                        'The local account is configured so that Windows ' +
                        'does not require a password. This does not establish ' +
                        'whether the account currently has a blank password.'
                    ) `
                    -Evidence $user.Name `
                    -Recommendation (
                        'Review whether the account requires password-based ' +
                        'authentication. Apply an appropriate password ' +
                        'requirement or disable the account if unused.'
                    ))
            )
        }
    }

    # Disabled firewall profiles.
    $firewallProfiles = @()

    if ($null -ne $HostReport.NetworkPosture) {
        $firewallProfiles = @(
            $HostReport.NetworkPosture.FirewallProfiles
        )
    }

    $disabledProfiles = @(
        $firewallProfiles |
            Where-Object {
                $_.PSObject.Properties['Enabled'] -and
                $_.Enabled -eq $false
            }
    )

    if ($disabledProfiles.Count -gt 0) {
        $profileNames = @(
            $disabledProfiles |
                ForEach-Object { $_.Name }
        ) -join ', '

        $findings.Add(
            (New-Finding `
                -Title 'Windows Firewall profile disabled' `
                -Severity 'Medium' `
                -Description (
                    'One or more Windows Firewall profiles are disabled. ' +
                    'Review the host network security policy and any ' +
                    'compensating controls.'
                ) `
                -Evidence $profileNames `
                -Recommendation (
                    'Enable the affected firewall profiles unless an ' +
                    'explicitly documented alternative control is in place.'
                ))
        )
    }

    return $findings.ToArray()
}

# ---------------------------------------------------------------------------
# HTML report generation
# ---------------------------------------------------------------------------
function ConvertTo-HtmlReport {
    <#
    .SYNOPSIS
        Generates a standalone HTML assessment report.

    .PARAMETER EngagementName
        Display name of the assessment or engagement.

    .PARAMETER Findings
        Finding objects generated by New-Finding or supplied independently.

    .PARAMETER RawReports
        Hashtable containing report names and their associated assessment
        objects. Included as collapsible JSON sections.

    .PARAMETER OutputPath
        Destination path for the generated HTML file.

    .OUTPUTS
        PSCustomObject containing the report path, finding count, severity
        counts, and export status.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$EngagementName,

        [AllowEmptyCollection()]
        [array]$Findings = @(),

        [hashtable]$RawReports = @{},

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$OutputPath
    )

    # -----------------------------------------------------------------------
    # HTML encoding helper
    # -----------------------------------------------------------------------
    function ConvertTo-HtmlSafeText {
        param(
            [AllowNull()]
            $Value
        )

        if ($null -eq $Value) {
            return ''
        }

        return [System.Net.WebUtility]::HtmlEncode(
            [string]$Value
        )
    }

    # -----------------------------------------------------------------------
    # Severity configuration
    # -----------------------------------------------------------------------
    $severityColor = @{
        Critical = '#7a0d0d'
        High     = '#c0392b'
        Medium   = '#d68910'
        Low      = '#2e86c1'
        Info     = '#5d6d7e'
    }

    $sortOrder = @{
        Critical = 0
        High     = 1
        Medium   = 2
        Low      = 3
        Info     = 4
    }

    # -----------------------------------------------------------------------
    # Normalize and validate finding objects
    # -----------------------------------------------------------------------
    $normalizedFindings = New-Object 'System.Collections.Generic.List[object]'

    foreach ($finding in @($Findings)) {
        if ($null -eq $finding) {
            continue
        }

        $requiredProperties = @(
            'Title'
            'Severity'
            'Description'
        )

        $validStructure = $true

        foreach ($property in $requiredProperties) {
            if (-not $finding.PSObject.Properties[$property]) {
                $validStructure = $false
                break
            }
        }

        if (-not $validStructure) {
            Write-Warning 'Skipping a finding with missing required properties.'
            continue
        }

        $severity = [string]$finding.Severity

        if (-not $sortOrder.ContainsKey($severity)) {
            Write-Warning "Skipping finding with invalid severity: $severity"
            continue
        }

        $normalizedFindings.Add(
            ([PSCustomObject]@{
                Title = [string]$finding.Title
                Severity = $severity
                Description = [string]$finding.Description
                Evidence = if ($finding.PSObject.Properties['Evidence']) {
                    [string]$finding.Evidence
                } else {
                    ''
                }
                Recommendation = if (
                    $finding.PSObject.Properties['Recommendation']
                ) {
                    [string]$finding.Recommendation
                } else {
                    ''
                }
            })
        )
    }

    $sortedFindings = @(
        $normalizedFindings.ToArray() |
            Sort-Object {
                $sortOrder[$_.Severity]
            }
    )

    # -----------------------------------------------------------------------
    # Render findings
    # -----------------------------------------------------------------------
    $findingsHtml = if ($sortedFindings.Count -gt 0) {
        (
            $sortedFindings |
                ForEach-Object {
                    $finding = $_
                    $color = $severityColor[$finding.Severity]

                    $title = ConvertTo-HtmlSafeText $finding.Title
                    $severity = ConvertTo-HtmlSafeText $finding.Severity
                    $description = ConvertTo-HtmlSafeText $finding.Description

                    $evidenceHtml = ''

                    if (-not [string]::IsNullOrWhiteSpace($finding.Evidence)) {
                        $evidence = ConvertTo-HtmlSafeText $finding.Evidence
                        $evidenceHtml = "<pre>$evidence</pre>"
                    }

                    $recommendationHtml = ''

                    if (
                        -not [string]::IsNullOrWhiteSpace(
                            $finding.Recommendation
                        )
                    ) {
                        $recommendation = ConvertTo-HtmlSafeText(
                            $finding.Recommendation
                        )

                        $recommendationHtml = (
                            "<p><strong>Recommendation:</strong> " +
                            "$recommendation</p>"
                        )
                    }

@"
<div class="finding" style="border-left: 5px solid $color;">
  <h3>$title <span class="badge" style="background:$color;">$severity</span></h3>
  <p>$description</p>
  $evidenceHtml
  $recommendationHtml
</div>
"@
                }
        ) -join "`n"
    }
    else {
        '<p>No findings recorded.</p>'
    }

    # -----------------------------------------------------------------------
    # Severity counts
    # -----------------------------------------------------------------------
    $summaryCounts = @(
        foreach ($severity in @(
            'Critical', 'High', 'Medium', 'Low', 'Info'
        )) {
            $count = @(
                $sortedFindings |
                    Where-Object { $_.Severity -eq $severity }
            ).Count

            $color = $severityColor[$severity]
            $safeSeverity = ConvertTo-HtmlSafeText $severity

            "<span class='count-pill' style='background:$color'>" +
                "$safeSeverity`: $count</span>"
        }
    )

    # -----------------------------------------------------------------------
    # Raw report sections
    # -----------------------------------------------------------------------
    $rawSections = @(
        foreach ($key in @($RawReports.Keys | Sort-Object)) {
            $json = $null

            try {
                $json = ConvertTo-Json `
                    -InputObject $RawReports[$key] `
                    -Depth 8 `
                    -ErrorAction Stop
            }
            catch {
                $json = "Unable to serialize this report: $($_.Exception.Message)"
            }

            $safeName = ConvertTo-HtmlSafeText $key
            $safeJson = ConvertTo-HtmlSafeText $json

@"
<details>
  <summary>$safeName</summary>
  <pre>$safeJson</pre>
</details>
"@
        }
    ) -join "`n"

    # -----------------------------------------------------------------------
    # HTML document
    # -----------------------------------------------------------------------
    $safeEngagementName = ConvertTo-HtmlSafeText $EngagementName
    $generatedAt = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz')

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>$safeEngagementName - Assessment Report</title>
<style>
  body {
    font-family: -apple-system, Segoe UI, Roboto, sans-serif;
    max-width: 960px;
    margin: 40px auto;
    padding: 0 20px;
    color: #1a1a1a;
    background: #fafafa;
  }

  h1 {
    border-bottom: 3px solid #2c3e50;
    padding-bottom: 10px;
  }

  .meta {
    color: #666;
    font-size: 0.9em;
    margin-bottom: 30px;
  }

  .finding {
    background: #fff;
    padding: 15px 20px;
    margin-bottom: 15px;
    border-radius: 4px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.1);
    overflow-wrap: anywhere;
  }

  .finding h3 {
    margin-top: 0;
  }

  .badge {
    color: #fff;
    padding: 2px 10px;
    border-radius: 12px;
    font-size: 0.75em;
    vertical-align: middle;
  }

  .count-pill {
    display: inline-block;
    color: #fff;
    padding: 4px 12px;
    border-radius: 12px;
    font-size: 0.85em;
    margin: 0 8px 8px 0;
  }

  pre {
    background: #f4f4f4;
    padding: 10px;
    overflow-x: auto;
    border-radius: 4px;
    font-size: 0.85em;
    white-space: pre-wrap;
    overflow-wrap: anywhere;
  }

  details {
    margin-bottom: 10px;
    background: #fff;
    padding: 10px 15px;
    border-radius: 4px;
    overflow-wrap: anywhere;
  }

  summary {
    cursor: pointer;
    font-weight: 600;
  }
</style>
</head>
<body>
  <h1>$safeEngagementName — Assessment Report</h1>

  <div class="meta">
    Generated: $generatedAt
  </div>

  <h2>Findings Summary</h2>
  <div>
    $($summaryCounts -join "`n")
  </div>

  <h2>Findings</h2>
  $findingsHtml

  <h2>Raw Collected Data</h2>
  $rawSections
</body>
</html>
"@

    # -----------------------------------------------------------------------
    # Write report safely
    # -----------------------------------------------------------------------
    $fullPath = $null

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

        $tempPath = Join-Path $directory (
            [System.IO.Path]::GetRandomFileName() + '.tmp'
        )

        try {
            [System.IO.File]::WriteAllText(
                $tempPath,
                $html,
                (New-Object System.Text.UTF8Encoding($false))
            )

            # Replace the destination only after the temporary report
            # has been completely written.
            if (Test-Path -LiteralPath $fullPath -PathType Leaf) {
                [System.IO.File]::Replace(
                    $tempPath,
                    $fullPath,
                    $null
                )
            }
            else {
                [System.IO.File]::Move(
                    $tempPath,
                    $fullPath
                )
            }
        }
        finally {
            if (
                -not [string]::IsNullOrWhiteSpace($tempPath) -and
                (Test-Path -LiteralPath $tempPath)
            ) {
                Remove-Item -LiteralPath $tempPath -Force `
                    -ErrorAction SilentlyContinue
            }
        }

        $counts = [PSCustomObject]@{
            Critical = @($sortedFindings | Where-Object Severity -eq 'Critical').Count
            High     = @($sortedFindings | Where-Object Severity -eq 'High').Count
            Medium   = @($sortedFindings | Where-Object Severity -eq 'Medium').Count
            Low      = @($sortedFindings | Where-Object Severity -eq 'Low').Count
            Info     = @($sortedFindings | Where-Object Severity -eq 'Info').Count
        }

        [PSCustomObject]@{
            Success       = $true
            OutputPath    = $fullPath
            FindingCount  = $sortedFindings.Count
            SeverityCount = $counts
            Error         = $null
        }
    }
    catch {
        Write-Warning "HTML report export failed: $($_.Exception.Message)"

        [PSCustomObject]@{
            Success       = $false
            OutputPath    = $fullPath
            FindingCount  = $sortedFindings.Count
            SeverityCount = $null
            Error         = $_.Exception.Message
        }
    }
}

Export-ModuleMember -Function @(
    'New-Finding'
    'Get-AutoFindings'
    'ConvertTo-HtmlReport'
)
