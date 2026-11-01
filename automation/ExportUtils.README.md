# ExportUtils

PowerShell helpers for saving structured data as CSV files or Excel workbooks.

## What it contains

- `Export-FindingsToCsv`
- `Export-ReportSectionsToCsv`
- `Export-AssessmentToExcel`

The module handles output formatting. It does not collect information from a computer, network, directory, or cloud account.

## Requirements

- PowerShell 5.1 or later.
- ImportExcel is optional and is needed for Excel workbook output. CSV output does not require it.

## Notes

Text values beginning with spreadsheet formula characters are prefixed to reduce formula-injection risk. This does not guarantee that every spreadsheet application or later transformation will handle every value safely.

Warnings should be checked and expected output files verified. An attempted fallback does not mean the file was successfully created.

Files produced by these helpers may contain sensitive information from the original data. Review them before sharing.
