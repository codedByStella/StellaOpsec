# Active Directory Notes

This directory contains a personal PowerShell module for exploring Active Directory and Group Policy inventory.

The module was written as a read-only information-gathering experiment. Its intended operational use is limited to StellaAudits when a business owner specifically requests relevant information gathering. It is not intended for independent third-party operation.

## What it collects

- User account details, including last logon, enabled state, password settings, and selected administrative indicators.
- Membership in selected high-value domain groups.
- Default and fine-grained password policies.
- User accounts with Service Principal Names (SPNs).
- Domain trust relationships.
- Group Policy Object names, identifiers, status, and timestamps.

The Group Policy inventory records GPO metadata only. It does not enumerate linked organizational units or inspect individual policy settings.

## Requirements

- Windows PowerShell 5.1 or later.
- The ActiveDirectory PowerShell module from RSAT.
- The GroupPolicy module for Group Policy inventory.
- Sufficient permissions for the relevant directory queries.

## Limitations

The module performs directory enumeration. It does not request service tickets, extract ticket material, crack credentials, modify directory objects, or change domain configuration.

Results depend on available permissions, domain state, and the behavior of the installed Windows modules. Some checks may return incomplete results or warnings. Account indicators such as `AdminCount` are not definitive proof of effective privileges.

Directory output can contain sensitive identity and infrastructure information. It should be handled carefully and not published.

This is a personal hobby project, not a security assessment service or a substitute for qualified Active Directory review.
