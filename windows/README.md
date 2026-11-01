# Windows Scripts

This directory contains personal PowerShell projects for collecting selected Windows inventory and configuration information.

- [HostAssessment](HostAssessment.README.md) — host, account, process, patch, software, scheduled task, service, network, and SMB information.
- [CredentialHygiene](CredentialHygiene.README.md) — selected certificate, cached-credential target, and credential-protection information.
- [EventLogAssessment](EventLogAssessment.README.md) — selected Windows event-log summaries and activity patterns.
- [WindowsEnvironmentInventory](WindowsEnvironmentInventory.README.md) — Windows, hardware, display, network, and storage inventory.
- [Active Directory notes](active-directory/) — directory and Group Policy scripting.

Most of the scripts were written for PowerShell 5.1 or later. Individual checks may depend on Windows components, permissions, or additional modules.

The output is limited to the information each script collects. It is not proof that a system is secure, compliant, or compromised. Inventory can include sensitive host and user details.
