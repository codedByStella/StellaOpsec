# Google Cloud Configuration Script

This PowerShell script uses the gcloud CLI to retrieve information about selected Google Cloud settings. The source module is named `GcpPostureAudit.psm1`; that name reflects the original project code, not a professional audit service.

## Areas covered

The script includes selected queries for:

- Cloud Storage bucket access configuration.
- Firewall rules and broad source ranges.
- Primitive IAM role assignments.
- Cloud SQL network exposure settings.

## Development requirements

- PowerShell 5.1 or later.
- Google Cloud CLI (`gcloud`) installed and available on PATH.
- An authenticated gcloud session with access to the relevant project and resources.
- Read permissions for the information being queried.

## Limitations

Coverage is selective and depends on gcloud/API permissions and provider behavior. A broad firewall source or primitive role assignment may need context; neither alone proves exploitable exposure or compromise.

This is a personal scripting project for exploring cloud configuration collection. It is not a complete Google Cloud review or a determination that a project is secure.
