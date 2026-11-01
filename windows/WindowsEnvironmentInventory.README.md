# WindowsEnvironmentInventory

A standalone PowerShell script I wrote to collect selected information about a Windows environment.

## What it collects

The script gathers selected computer and Windows details, local account information, network adapter and configuration data, display information, storage information, and memory information. The `-Detailed` switch includes additional configuration metadata.

## Development requirements

- Windows and PowerShell 5.1 or later.
- Administrator privileges are not generally required, though some fields may be unavailable depending on permissions and provider support.

## Limitations and privacy

The report may contain usernames, computer names, domain details, IP configuration, hardware information, and installed configuration metadata. Review the output before sharing it.

This is an inventory script, not a security assessment. Empty or unavailable results do not establish that a component or configuration is absent.
