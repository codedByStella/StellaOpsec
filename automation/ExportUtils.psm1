
#Requires -Version 5.1
<#
.SYNOPSIS
    CSV / Excel export layer for assessment findings and raw report data.

.DESCRIPTION
    Converts object-based assessment output into CSV files or Excel workbooks.
    This module performs formatting and export only; it does not collect data.

    Excel export uses ImportExcel when available. If ImportExcel is unavailable
    or Excel export fails, the module falls back to CSV exports.

    Spreadsheet-bound text is sanitized against formula injection. Exported
    reports may contain sensitive client information and should be protected.
#>

function Test-ImportExcelAvailable {
    [CmdletBinding()]
    param()

    try {
        if (-not (Get-Module -ListAvailable -Name ImportExcel)) {
            return $false
        }

        Import-Module ImportExcel -ErrorAction Stop

        $requiredCommands = @(
            'Export-Excel',
            'Open-ExcelPackage',
            'Close-ExcelPackage',
            'Add-ConditionalFormatting'
        )

        foreach ($commandName in $requiredCommands) {
            if (-not (Get-Command $commandName -ErrorAction SilentlyContinue)) {
                Write-Warning "ImportExcel is installed, but '$commandName' is unavailable."
                return $false
            }
        }

        return $true
    }
    catch {
        Write-Warning "ImportExcel could not be loaded: $($_.Exception.Message)"
        return $false
    }
}

function Get-ExportProperties {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $InputObject
    )

    if ($InputObject -is [System.Collections.IDictionary]) {
        foreach ($key in $InputObject.Keys) {
            [PSCustomObject]@{
                Name  = [string]$key
                Value = $InputObject[$key]
            }
        }

        return
    }

    foreach ($property in $InputObject.PSObject.Properties) {
        if ($property.MemberType -in @('NoteProperty', 'Property', 'AliasProperty', 'ScriptProperty')) {
            [PSCustomObject]@{
                Name  = $property.Name
                Value = $property.Value
            }
        }
    }
}

function ConvertTo-ExportValue {
    [CmdletBinding()]
    param(
        $Value
    )

    if ($null -eq $Value) {
        return $null
    }

    if (
        $Value -is [System.Collections.IDictionary] -or
        $Value -is [PSCustomObject] -or
        ($Value -is [System.Collections.IEnumerable] -and
         $Value -isnot [string] -and
         $Value -isnot [byte[]])
    ) {
        try {
            return ($Value | ConvertTo-Json -Depth 10 -Compress -ErrorAction Stop)
        }
        catch {
            return [string]$Value
        }
    }

    return $Value
}

function ConvertTo-SafeSpreadsheetRows {
    <#
    .SYNOPSIS
        Converts objects into flat rows and neutralizes spreadsheet formulas.
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]
        $InputObject
    )

    begin {
        $rows = New-Object System.Collections.Generic.List[object]
    }

    process {
        if ($null -eq $InputObject) {
            return
        }

        $properties = @(Get-ExportProperties -InputObject $InputObject)
        $row = [ordered]@{}

        if ($properties.Count -eq 0) {
            $value = ConvertTo-ExportValue -Value $InputObject
            if ($value -is [string] -and $value -match '^\s*[=+\-@]') {
                $value = "'" + $value
            }
            $row['Value'] = $value
        }
        else {
            foreach ($property in $properties) {
                $value = ConvertTo-ExportValue -Value $property.Value

                if ($value -is [string]) {
                    # Excel and other spreadsheet applications may interpret
                    # cells beginning with these characters as formulas.
                    if ($value -match '^\s*[=+\-@]') {
                        $value = "'" + $value
                    }
                }

                $row[$property.Name] = $value
            }
        }

        $rows.Add([PSCustomObject]$row)
    }

    end {
        return $rows.ToArray()
    }
}

function Get-SafeFileName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    $invalidChars = [System.IO.Path]::GetInvalidFileNameChars()
    $safeName = $Name

    foreach ($char in $invalidChars) {
        $safeName = $safeName.Replace([string]$char, '_')
    }

    $safeName = $safeName.Trim().TrimEnd('.')

    if ([string]::IsNullOrWhiteSpace($safeName)) {
        $safeName = 'Export'
    }

    return $safeName
}

function Get-UniqueWorksheetName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [hashtable]$UsedNames
    )

    $safeName = $Name -replace '[\[\]\*\?/\\:]', '_'
    $safeName = $safeName.Trim().Trim("'")

    if ([string]::IsNullOrWhiteSpace($safeName)) {
        $safeName = 'Sheet'
    }

    if ($safeName.Length -gt 31) {
        $safeName = $safeName.Substring(0, 31)
    }

    $candidate = $safeName
    $counter = 1

    while ($UsedNames.ContainsKey($candidate.ToLowerInvariant())) {
        $suffix = "_$counter"
        $maxLength = 31 - $suffix.Length

        if ($maxLength -lt 1) {
            throw "Unable to generate a unique worksheet name for '$Name'."
        }

        $baseName = $safeName

        if ($baseName.Length -gt $maxLength) {
            $baseName = $baseName.Substring(0, $maxLength)
        }

        $candidate = "$baseName$suffix"
        $counter++
    }

    $UsedNames[$candidate.ToLowerInvariant()] = $true
    return $candidate
}

function Export-FindingsToCsv {
    <#
    .SYNOPSIS
        Exports assessment findings to CSV.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [array]$Findings,

        [Parameter(Mandatory)]
        [string]$OutputPath
    )

    $parent = [System.IO.Path]::GetDirectoryName([System.IO.Path]::GetFullPath($OutputPath))

    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -Path $parent -ItemType Directory -Force -ErrorAction Stop | Out-Null
    }

    $sortOrder = @{
        Critical = 0
        High     = 1
        Medium   = 2
        Low      = 3
        Info     = 4
    }

    $sorted = @(
        $Findings |
            Sort-Object {
                $severity = [string]$_.Severity

                if ($sortOrder.ContainsKey($severity)) {
                    $sortOrder[$severity]
                }
                else {
                    99
                }
            }
    )

    $rows = @(
        $sorted |
            Select-Object Title, Severity, Description, Evidence, Recommendation |
            ConvertTo-SafeSpreadsheetRows
    )

    if ($rows.Count -gt 0) {
        $rows | Export-Csv -LiteralPath $OutputPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
    }
    else {
        '"Title","Severity","Description","Evidence","Recommendation"' |
            Set-Content -LiteralPath $OutputPath -Encoding UTF8 -ErrorAction Stop
    }

    Write-Host "Findings CSV written to $OutputPath" -ForegroundColor Green
}

function Export-ReportSectionsToCsv {
    <#
    .SYNOPSIS
        Exports top-level report sections into individual CSV files.
        Nested objects are exported one level deeper.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Report,

        [Parameter(Mandatory)]
        [string]$OutputFolder
    )

    if (-not (Test-Path -LiteralPath $OutputFolder)) {
        New-Item -Path $OutputFolder -ItemType Directory -Force -ErrorAction Stop | Out-Null
    }

    foreach ($property in (Get-ExportProperties -InputObject $Report)) {
        $name = [string]$property.Name
        $value = $property.Value

        if ($null -eq $value) {
            continue
        }

        $nestedProperties = @(Get-ExportProperties -InputObject $value)
        $isNestedObject = (
            $value -is [System.Collections.IDictionary] -or
            $value -is [PSCustomObject]
        )

        if ($isNestedObject -and $nestedProperties.Count -gt 0) {
            foreach ($subProperty in $nestedProperties) {
                if ($null -eq $subProperty.Value) {
                    continue
                }

                $fileName = "$(Get-SafeFileName -Name $name)_$(Get-SafeFileName -Name $subProperty.Name).csv"
                $path = Join-Path $OutputFolder $fileName

                try {
                    $rows = @(
                        @($subProperty.Value) |
                            ConvertTo-SafeSpreadsheetRows
                    )

                    if ($rows.Count -gt 0) {
                        $rows | Export-Csv -LiteralPath $path -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
                    }
                    else {
                        Write-Warning "Skipped '$name.$($subProperty.Name)': section contained no rows."
                    }
                }
                catch {
                    Write-Warning "Skipped '$name.$($subProperty.Name)': $($_.Exception.Message)"
                }
            }

            continue
        }

        $path = Join-Path $OutputFolder "$(Get-SafeFileName -Name $name).csv"

        try {
            $rows = @(
                @($value) |
                    ConvertTo-SafeSpreadsheetRows
            )

            if ($rows.Count -gt 0) {
                $rows | Export-Csv -LiteralPath $path -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
            }
            else {
                Write-Warning "Skipped '$name': section contained no rows."
            }
        }
        catch {
            Write-Warning "Skipped '$name': $($_.Exception.Message)"
        }
    }

    Write-Host "Report sections exported to $OutputFolder" -ForegroundColor Green
}

function Export-AssessmentToExcel {
    <#
    .SYNOPSIS
        Exports findings and report sections to one Excel workbook.
        Falls back to CSV if ImportExcel is unavailable or Excel export fails.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()]
        [array]$Findings = @(),

        [hashtable]$RawReports = @{},

        [Parameter(Mandatory)]
        [string]$OutputPath
    )

    $parent = Split-Path -Parent $OutputPath

    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -Path $parent -ItemType Directory -Force -ErrorAction Stop | Out-Null
    }

    $fallbackFolder = [System.IO.Path]::Combine(
        [System.IO.Path]::GetDirectoryName([System.IO.Path]::GetFullPath($OutputPath)),
        [System.IO.Path]::GetFileNameWithoutExtension($OutputPath) + '_CSV'
    )

    $excelAvailable = Test-ImportExcelAvailable

    if (-not $excelAvailable) {
        if ($Findings.Count -gt 0) {
            Export-FindingsToCsv -Findings $Findings -OutputPath (Join-Path $fallbackFolder 'Findings.csv')
        }

        foreach ($key in $RawReports.Keys) {
            $sectionFolder = Join-Path $fallbackFolder (Get-SafeFileName -Name ([string]$key))
            Export-ReportSectionsToCsv -Report $RawReports[$key] -OutputFolder $sectionFolder
        }

        Write-Warning "Excel export unavailable. CSV files were written to $fallbackFolder"
        return
    }

    $tempPath = Join-Path $parent (
        [System.IO.Path]::GetFileNameWithoutExtension($OutputPath) +
        '_' + [guid]::NewGuid().ToString('N') + '.xlsx'
    )

    $usedSheets = @{}
    $hasWorkbookContent = $false

    try {
        if ($Findings.Count -gt 0) {
            $sortOrder = @{
                Critical = 0
                High     = 1
                Medium   = 2
                Low      = 3
                Info     = 4
            }

            $sorted = @(
                $Findings |
                    Sort-Object {
                        $severity = [string]$_.Severity

                        if ($sortOrder.ContainsKey($severity)) {
                            $sortOrder[$severity]
                        }
                        else {
                            99
                        }
                    } |
                    Select-Object Title, Severity, Description, Evidence, Recommendation
            )

            $findingRows = @($sorted | ConvertTo-SafeSpreadsheetRows)

            if ($findingRows.Count -gt 0) {
                $findingSheet = Get-UniqueWorksheetName -Name 'Findings' -UsedNames $usedSheets

                $findingRows |
                    Export-Excel -Path $tempPath `
                        -WorksheetName $findingSheet `
                        -AutoSize `
                        -FreezeTopRow `
                        -AutoFilter `
                        -TableStyle Medium2 `
                        -ErrorAction Stop

                $hasWorkbookContent = $true

                try {
                    $excelPkg = Open-ExcelPackage -Path $tempPath -ErrorAction Stop

                    try {
                        $ws = $excelPkg.Workbook.Worksheets[$findingSheet]

                        if ($null -ne $ws -and $sorted.Count -gt 0) {
                            $colorMap = @{
                                Critical = 'DarkRed'
                                High     = 'Red'
                                Medium   = 'Orange'
                                Low      = 'LightBlue'
                                Info     = 'LightGray'
                            }

                            foreach ($severity in $colorMap.Keys) {
                                Add-ConditionalFormatting `
                                    -Worksheet $ws `
                                    -Range "B2:B$($sorted.Count + 1)" `
                                    -RuleType Equal `
                                    -ConditionValue $severity `
                                    -BackgroundColor $colorMap[$severity] `
                                    -ErrorAction SilentlyContinue
                            }
                        }
                    }
                    finally {
                        Close-ExcelPackage $excelPkg
                    }
                }
                catch {
                    Write-Warning "Severity formatting could not be applied: $($_.Exception.Message)"
                }
            }
        }

        foreach ($key in $RawReports.Keys) {
            $report = $RawReports[$key]

            if ($null -eq $report) {
                continue
            }

            foreach ($property in (Get-ExportProperties -InputObject $report)) {
                $value = $property.Value

                if ($null -eq $value) {
                    continue
                }

                $baseName = "$key-$($property.Name)"
                $nestedProperties = @(Get-ExportProperties -InputObject $value)

                $isNestedObject = (
                    $value -is [System.Collections.IDictionary] -or
                    $value -is [PSCustomObject]
                )

                if ($isNestedObject -and $nestedProperties.Count -gt 0) {
                    foreach ($subProperty in $nestedProperties) {
                        if ($null -eq $subProperty.Value) {
                            continue
                        }

                        $requestedName = "$baseName-$($subProperty.Name)"
                        $sheetName = Get-UniqueWorksheetName -Name $requestedName -UsedNames $usedSheets

                        try {
                            $rows = @(
                                @($subProperty.Value) |
                                    ConvertTo-SafeSpreadsheetRows
                            )

                            if ($rows.Count -eq 0) {
                                continue
                            }

                            $exportParams = @{
                                Path          = $tempPath
                                WorksheetName = $sheetName
                                AutoSize      = $true
                                FreezeTopRow  = $true
                                AutoFilter    = $true
                                ErrorAction   = 'Stop'
                            }

                            if ($hasWorkbookContent) {
                                $exportParams['Append'] = $true
                            }

                            $rows | Export-Excel @exportParams
                            $hasWorkbookContent = $true
                        }
                        catch {
                            Write-Warning "Skipped sheet '$sheetName': $($_.Exception.Message)"
                        }
                    }

                    continue
                }

                $sheetName = Get-UniqueWorksheetName -Name $baseName -UsedNames $usedSheets

                try {
                    $rows = @(
                        @($value) |
                            ConvertTo-SafeSpreadsheetRows
                    )

                    if ($rows.Count -eq 0) {
                        continue
                    }

                    $exportParams = @{
                        Path          = $tempPath
                        WorksheetName = $sheetName
                        AutoSize      = $true
                        FreezeTopRow  = $true
                        AutoFilter    = $true
                        ErrorAction   = 'Stop'
                    }

                    if ($hasWorkbookContent) {
                        $exportParams['Append'] = $true
                    }

                    $rows | Export-Excel @exportParams
                    $hasWorkbookContent = $true
                }
                catch {
                    Write-Warning "Skipped sheet '$sheetName': $($_.Exception.Message)"
                }
            }
        }

        if (-not $hasWorkbookContent -or -not (Test-Path -LiteralPath $tempPath)) {
            throw 'No exportable findings or report sections were available to create a workbook.'
        }

        # Move-Item -Force replaces the destination without an explicit
        # delete-first window. The temporary workbook remains intact until move.
        Move-Item -LiteralPath $tempPath -Destination $OutputPath -Force -ErrorAction Stop

        Write-Host "Excel workbook written to $OutputPath" -ForegroundColor Green
    }
    catch {
        if (Test-Path -LiteralPath $tempPath) {
            Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
        }

        Write-Warning "Excel export failed: $($_.Exception.Message)"
        Write-Warning "Falling back to CSV export."

        if ($Findings.Count -gt 0) {
            Export-FindingsToCsv -Findings $Findings -OutputPath (Join-Path $fallbackFolder 'Findings.csv')
        }

        foreach ($key in $RawReports.Keys) {
            $sectionFolder = Join-Path $fallbackFolder (Get-SafeFileName -Name ([string]$key))
            Export-ReportSectionsToCsv -Report $RawReports[$key] -OutputFolder $sectionFolder
        }

        Write-Warning "CSV fallback was attempted in $fallbackFolder. Check the warnings above and verify expected files before treating the export as complete."
    }
}

Export-ModuleMember -Function @(
    'Test-ImportExcelAvailable',
    'Export-FindingsToCsv',
    'Export-ReportSectionsToCsv',
    'Export-AssessmentToExcel'
)
