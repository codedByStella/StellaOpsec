# Automation and Reporting

These modules handle data after it has been collected. They provide report formatting and file export; they do not gather information from Windows, networks, Active Directory, or cloud accounts.

## Modules

- [ExportUtils.psm1](ExportUtils.psm1) — saves structured data as CSV or Excel.
- [ReportGenerator.psm1](ReportGenerator.psm1) — builds finding objects and standalone HTML reports.

## Development notes

The modules were written in PowerShell 5.1 or later. Excel workbook output uses the optional ImportExcel module; CSV output does not.

The report functions expect structured input from the other project scripts or compatible objects. Automatically generated labels and summaries are based on limited heuristics, not a formal risk-rating method.

Generated files can contain usernames, host details, configuration values, and other operational information. Treat them as sensitive.
