# HostAssessment

A read-only PowerShell module I developed to collect selected Windows host and configuration information.

## Areas covered

- Operating-system and hardware summary.
- Local users and local Administrators group membership.
- IPv4 configuration, TCP listeners, and firewall profiles.
- Process snapshots and cumulative CPU-time information.
- Installed hotfix and software inventory.
- Scheduled task and service configuration.
- Local or remote SMB share enumeration.

## Development requirements

- Windows and PowerShell 5.1 or later.
- Some information may require local administrator privileges.
- Remote SMB information depends on permissions and connectivity.

## Limitations

Installed hotfix information does not prove that a system is fully patched. Software inventory reads selected uninstall registry entries and may not include every installed application. An unquoted service path is an observation, not proof of exploitable privilege escalation. Process CPU information is cumulative, not interval-based utilization. The service path checks do not establish the relevant filesystem permissions.

Some information may be unavailable because of permissions or provider errors. Reports can contain usernames, internal addresses, service accounts, process details, and software inventory.
