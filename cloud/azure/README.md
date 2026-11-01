# Azure Configuration Script

This PowerShell script uses the Azure CLI to retrieve information about selected Azure settings. The source module is named `AzurePostureAudit.psm1`; that name reflects the original project code, not a professional audit service.

## Areas covered

The script includes queries for selected areas such as:

- Azure Storage public-access configuration.
- Network Security Group inbound rules with broad internet sources.
- Azure RBAC role assignments.
- Azure SQL public network access and firewall configuration.

It does not cover every Azure security feature. For example, Entra ID directory roles and MFA registration/status are outside its current coverage.

## Development requirements

- PowerShell 5.1 or later.
- Azure CLI (`az`) installed and available on PATH.
- An authenticated Azure CLI session.
- Read permissions for the subscription and resources being queried.

## Limitations

The results depend on CLI output, API permissions, resource coverage, and the configuration present when the information is collected. A setting or rule needs context; its presence alone does not establish exposure or impact.

This is one of my experiments in using automation to gather cloud configuration information. It is not a complete Azure review or a determination that an environment is secure.
