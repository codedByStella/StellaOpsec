# ReportGenerator

PowerShell helpers for turning structured data into finding objects and standalone HTML reports.

## What it contains

- `New-Finding` creates a finding object with title, severity, description, evidence, and recommendation fields.
- `Get-AutoFindings` creates a limited set of heuristic observations from host data.
- `ConvertTo-HtmlReport` creates an HTML report.

## Requirements

- PowerShell 5.1 or later.
- No additional PowerShell module is required by the report generator itself.

## Notes

The generated severity values are labels used by the script, not a formal risk methodology. An unquoted service path or an account configured without a password requirement does not, by itself, establish exploitability or prove that an account has a blank password.

The output is only a formatted presentation of the supplied data and script-generated observations. It does not verify whether an issue is real or determine what should be done about it.

HTML reports may include raw host information and evidence. Review the contents and protect the files.
