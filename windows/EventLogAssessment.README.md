# EventLogAssessment

A PowerShell module I developed to summarize selected Windows event-log activity.

## Functions in the module

- `Get-LogonEventSummary`
- `Get-FailedLogonPattern`
- `Get-PowerShellLogSummary`
- `Get-RecentFileActivity`
- `Invoke-EventLogAssessment`

## Development requirements

- Windows and PowerShell 5.1 or later.
- Access to the event logs being queried.
- Available events depend on audit policy, log retention, and system configuration.

## Limitations

Event logs may be disabled, incomplete, overwritten, or inaccessible. Reaching the configured maximum event count can truncate the returned sample; failed-logon results include a `MayBeTruncated` indicator.

Patterns in event data do not establish malicious activity or user intent. Logs may contain usernames, domain names, addresses, and file paths, so output should be handled carefully.
