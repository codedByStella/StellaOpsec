# CredentialHygiene

A PowerShell module for collecting selected information about certificates, cached credential targets, and Windows credential-protection settings.

## Functions in the module

- `Get-CertificateInventory`
- `Get-CachedCredentialTargets`
- `Get-CredentialProtectionStatus`
- `Invoke-CredentialHygieneAssessment`

## Development requirements

- Windows and PowerShell 5.1 or later.
- Some information may require elevated permissions or Windows components that are not available on every edition or configuration.

## Limitations

The module does not retrieve or decode passwords. A missing value, inaccessible registry location, or unavailable provider does not necessarily mean that a protection feature is enabled or disabled. The returned status and errors matter.

Certificate metadata and cached-target information can be sensitive. This script only collects selected local information; it does not certify that credentials are protected.
