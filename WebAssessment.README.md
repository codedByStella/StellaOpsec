# WebAssessment

A PowerShell module I developed to inspect selected HTTP responses and web transport details.

## Areas covered

- HTTP/HTTPS request and response metadata.
- Selected HTTP security headers, including HSTS where applicable.
- Cookie security attributes.
- TLS-related protocol and cipher metadata exposed by the implementation.

## Development requirements

- PowerShell 5.1 or later.
- Network access to the web endpoints being queried.

## Limitations

The presence of a header does not amount to a web-application security review. Cookie parsing is limited, and the TLS information exposed by the implementation may not identify every detail of a negotiated cipher suite. HTTP status codes, redirects, proxies, and server behavior can all affect the results.

The script reports selected response details. It does not establish that a website is secure.
