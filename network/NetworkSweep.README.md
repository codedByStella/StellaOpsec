# NetworkSweep

A PowerShell module I developed to experiment with basic network discovery and protocol checks.

## Functions in the module

- `Invoke-HostDiscovery` — checks whether specified hosts respond.
- `Expand-CidrRange` — expands a supplied CIDR range into addresses.
- `Invoke-PortSweep` — checks selected TCP ports on supplied targets.
- `Test-DnsZoneTransfer` — checks how a DNS server responds to a zone-transfer request.
- `Test-TlsConfig` — inspects TLS connectivity and records certificate-validation observations.

## Development requirements

- PowerShell 7.0 or later.
- Network access to the systems involved.

## Notes and limitations

A failed connection does not prove that a service is absent. Filtering, routing, and temporary failures can produce the same result.

The TLS inspection code may allow a handshake to continue with an invalid certificate so it can record the validation state. That behavior is limited to the inspection connection; it should not be confused with normal certificate validation in an application.

The results are observations from a particular point in time. The module does not exploit services or establish that a host is secure.
