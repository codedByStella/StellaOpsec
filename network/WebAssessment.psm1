
#Requires -Version 5.1
<#
.SYNOPSIS
    Passive web application configuration checks for authorized assessments.

.DESCRIPTION
    Sends ordinary HTTP(S) GET requests and inspects response headers,
    cookie attributes, TLS protocol negotiation, and certificate metadata.

    No fuzzing, parameter injection, authentication bypass, exploitation,
    or modification of remote systems is performed.

.NOTES
    TLS negotiation results depend on the local Windows and .NET environment.
    Assessment output may contain sensitive infrastructure metadata.
#>

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

function Resolve-WebAssessmentUri {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Url
    )

    $uri = $null

    if (
        -not [System.Uri]::TryCreate(
            $Url,
            [System.UriKind]::Absolute,
            [ref]$uri
        )
    ) {
        throw "Invalid absolute URL: $Url"
    }

    if ($uri.Scheme -notin @('http', 'https')) {
        throw "Unsupported URL scheme: $($uri.Scheme)"
    }

    if ([string]::IsNullOrWhiteSpace($uri.Host)) {
        throw "URL does not contain a valid host: $Url"
    }

    return $uri
}

function Get-WebResponseHeaderValues {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Headers,

        [Parameter(Mandatory)]
        [string]$Name
    )

    try {
        $values = $Headers.GetValues($Name)

        if ($null -ne $values) {
            return @($values)
        }
    }
    catch {
        # Header not present or unavailable.
    }

    return @()
}

function Get-WebResponseFinalUri {
    param(
        [Parameter(Mandatory)]
        $Response,

        [Parameter(Mandatory)]
        [string]$FallbackUrl
    )

    try {
        if ($Response.BaseResponse.ResponseUri) {
            return $Response.BaseResponse.ResponseUri.AbsoluteUri
        }
    }
    catch {
        # Use the original URL when the response URI is unavailable.
    }

    return $FallbackUrl
}

function Get-WebRequestErrorStatus {
    param(
        [Parameter(Mandatory)]
        $ErrorRecord
    )

    $statusCode = $null

    try {
        if ($ErrorRecord.Exception.Response) {
            $statusCode = [int]$ErrorRecord.Exception.Response.StatusCode
        }
    }
    catch {
        # No HTTP status was available.
    }

    return $statusCode
}

function Invoke-WebAssessmentRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Url,

        [ValidateRange(1, 120)]
        [int]$TimeoutSec = 15
    )

    $uri = Resolve-WebAssessmentUri -Url $Url

    # Certificate validation is deliberately left enabled.
    # Redirect behavior is recorded through the final response URI.
    try {
        return Invoke-WebRequest `
            -Uri $uri `
            -Method Get `
            -UseBasicParsing `
            -MaximumRedirection 10 `
            -TimeoutSec $TimeoutSec `
            -ErrorAction Stop
    }
    catch {
        # Windows PowerShell 5.1 throws for HTTP error status codes even
        # when the server returned inspectable headers and a response body.
        # Preserve that response for header/cookie inspection when available.
        $errorResponse = $_.Exception.Response
        if ($null -ne $errorResponse) {
            return $errorResponse
        }
        throw
    }
}

# ---------------------------------------------------------------------------
# Security header audit
# ---------------------------------------------------------------------------

function Get-SecurityHeaderAudit {
    <#
    .SYNOPSIS
        Checks common security-related HTTP response headers.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Url,

        [ValidateRange(1, 120)]
        [int]$TimeoutSec = 15
    )

    $expectedHeaders = @(
        'Strict-Transport-Security'
        'Content-Security-Policy'
        'X-Frame-Options'
        'X-Content-Type-Options'
        'Referrer-Policy'
        'Permissions-Policy'
    )

    try {
        $uri = Resolve-WebAssessmentUri -Url $Url
        $response = Invoke-WebAssessmentRequest `
            -Url $uri.AbsoluteUri `
            -TimeoutSec $TimeoutSec

        $found = @{}

        foreach ($header in $expectedHeaders) {
            if ($header -eq 'Strict-Transport-Security' -and $uri.Scheme -ne 'https') {
                $found[$header] = $null
                continue
            }
            $values = @(
                Get-WebResponseHeaderValues `
                    -Headers $response.Headers `
                    -Name $header
            )

            $found[$header] = if ($values.Count -gt 0) {
                $values -join '; '
            }
            else {
                $null
            }
        }

        $serverValues = @(
            Get-WebResponseHeaderValues `
                -Headers $response.Headers `
                -Name 'Server'
        )

        $poweredByValues = @(
            Get-WebResponseHeaderValues `
                -Headers $response.Headers `
                -Name 'X-Powered-By'
        )

        $missingHeaders = @(
            foreach ($header in $expectedHeaders) {
                if ($header -eq 'Strict-Transport-Security' -and $uri.Scheme -ne 'https') {
                    continue
                }
                if ([string]::IsNullOrWhiteSpace($found[$header])) {
                    $header
                }
            }
        )

        $finalUri = Get-WebResponseFinalUri `
            -Response $response `
            -FallbackUrl $uri.AbsoluteUri

        [PSCustomObject]@{
            Url                     = $uri.AbsoluteUri
            FinalUrl                = $finalUri
            Redirected              = ($finalUri -ne $uri.AbsoluteUri)
            StatusCode              = [int]$response.StatusCode
            HSTS                    = $found['Strict-Transport-Security']
            CSP                     = $found['Content-Security-Policy']
            XFrameOptions           = $found['X-Frame-Options']
            XContentTypeOptions     = $found['X-Content-Type-Options']
            ReferrerPolicy          = $found['Referrer-Policy']
            PermissionsPolicy       = $found['Permissions-Policy']
            MissingHeaders          = $missingHeaders
            ServerBanner            = $serverValues -join '; '
            XPoweredBy              = $poweredByValues -join '; '
            InfoDisclosureViaBanner = [bool](
                $serverValues.Count -gt 0 -or
                $poweredByValues.Count -gt 0
            )
            Error                   = $null
        }
    }
    catch {
        [PSCustomObject]@{
            Url        = $Url
            FinalUrl   = $null
            Redirected = $null
            StatusCode = Get-WebRequestErrorStatus -ErrorRecord $_
            Error      = $_.Exception.Message
        }
    }
}

# ---------------------------------------------------------------------------
# Cookie attribute audit
# ---------------------------------------------------------------------------

function Get-CookieFlagAudit {
    <#
    .SYNOPSIS
        Checks Set-Cookie response headers for common security attributes.

    .DESCRIPTION
        Reports cookie names and attribute presence without returning raw
        cookie values, which may contain session identifiers.

        Cookies are evaluated individually. SameSite is reported as an
        attribute value rather than assigned a universal security verdict.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Url,

        [ValidateRange(1, 120)]
        [int]$TimeoutSec = 15
    )

    try {
        $uri = Resolve-WebAssessmentUri -Url $Url

        $response = Invoke-WebAssessmentRequest `
            -Url $uri.AbsoluteUri `
            -TimeoutSec $TimeoutSec

        $setCookieHeaders = @(
            Get-WebResponseHeaderValues `
                -Headers $response.Headers `
                -Name 'Set-Cookie'
        )

        $finalUri = Get-WebResponseFinalUri `
            -Response $response `
            -FallbackUrl $uri.AbsoluteUri

        if ($setCookieHeaders.Count -eq 0) {
            return [PSCustomObject]@{
                Url        = $uri.AbsoluteUri
                FinalUrl   = $finalUri
                Redirected = ($finalUri -ne $uri.AbsoluteUri)
                CookiesSet = $false
                CookieCount = 0
                Cookies    = @()
                Error      = $null
            }
        }

        $cookieResults = New-Object 'System.Collections.Generic.List[object]'

        foreach ($raw in $setCookieHeaders) {
            # Split attributes only. The cookie value is never returned.
            $parts = @($raw -split ';')

            $nameValue = $parts[0]
            $separatorIndex = $nameValue.IndexOf('=')

            $cookieName = if ($separatorIndex -gt 0) {
                $nameValue.Substring(0, $separatorIndex).Trim()
            }
            else {
                $nameValue.Trim()
            }

            $secure = $false
            $httpOnly = $false
            $sameSite = $null
            $domain = $null
            $path = $null
            $expires = $null
            $maxAge = $null

            foreach ($part in ($parts | Select-Object -Skip 1)) {
                $attribute = $part.Trim()

                if ($attribute -match '^(?i:Secure)$') {
                    $secure = $true
                }
                elseif ($attribute -match '^(?i:HttpOnly)$') {
                    $httpOnly = $true
                }
                elseif ($attribute -match '^(?i:SameSite)\s*=\s*(.+)$') {
                    $sameSite = $Matches[1].Trim()
                }
                elseif ($attribute -match '^(?i:Domain)\s*=\s*(.+)$') {
                    $domain = $Matches[1].Trim()
                }
                elseif ($attribute -match '^(?i:Path)\s*=\s*(.+)$') {
                    $path = $Matches[1].Trim()
                }
                elseif ($attribute -match '^(?i:Expires)\s*=\s*(.+)$') {
                    $expires = $Matches[1].Trim()
                }
                elseif ($attribute -match '^(?i:Max-Age)\s*=\s*(.+)$') {
                    $maxAge = $Matches[1].Trim()
                }
            }

            $cookieResults.Add(
                [PSCustomObject]@{
                    CookieName = $cookieName
                    Secure     = $secure
                    HttpOnly   = $httpOnly
                    SameSite   = $sameSite
                    Domain     = $domain
                    Path       = $path
                    Expires    = $expires
                    MaxAge     = $maxAge
                }
            )
        }

        [PSCustomObject]@{
            Url         = $uri.AbsoluteUri
            FinalUrl    = $finalUri
            Redirected  = ($finalUri -ne $uri.AbsoluteUri)
            CookiesSet  = $true
            CookieCount = $cookieResults.Count
            Cookies     = $cookieResults.ToArray()
            Error       = $null
        }
    }
    catch {
        [PSCustomObject]@{
            Url         = $Url
            CookiesSet  = $null
            CookieCount = 0
            Cookies     = @()
            Error       = $_.Exception.Message
        }
    }
}

# ---------------------------------------------------------------------------
# TLS protocol and cipher audit
# ---------------------------------------------------------------------------

function Get-TlsCipherAudit {
    <#
    .SYNOPSIS
        Tests TLS protocol negotiation and reports negotiated cipher metadata.

    .DESCRIPTION
        Attempts a separate TLS handshake for each protocol available to
        the local runtime.

        A failed handshake is classified as Inconclusive because failure
        can originate from the client, server, network, or local policy.

        Certificate validation errors are recorded. The callback permits
        the handshake to complete for inspection, but the report explicitly
        identifies whether normal certificate validation succeeded.

        This function does not modify global certificate validation settings.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName,

        [ValidateRange(1, 65535)]
        [int]$Port = 443,

        [ValidateRange(1, 120)]
        [int]$TimeoutSec = 10
    )

    $protocolsToTest = [ordered]@{
        Ssl3  = [System.Security.Authentication.SslProtocols]::Ssl3
        Tls   = [System.Security.Authentication.SslProtocols]::Tls
        Tls11 = [System.Security.Authentication.SslProtocols]::Tls11
        Tls12 = [System.Security.Authentication.SslProtocols]::Tls12
    }

    # TLS 1.3 may not be available in the .NET Framework runtime.
    try {
        $tls13 = [System.Security.Authentication.SslProtocols]::Tls13
        $protocolsToTest['Tls13'] = $tls13
    }
    catch {
        $protocolsToTest['Tls13'] = $null
    }

    $results = New-Object 'System.Collections.Generic.List[object]'

    foreach ($name in $protocolsToTest.Keys) {
        $protocol = $protocolsToTest[$name]

        if ($null -eq $protocol) {
            $results.Add(
                [PSCustomObject]@{
                    Protocol        = $name
                    Supported       = $null
                    Result          = 'UnsupportedByClient'
                    Deprecated      = $name -in @('Ssl3', 'Tls', 'Tls11')
                    CipherAlgorithm = $null
                    CipherStrength  = $null
                    HashAlgorithm   = $null
                    KeyExchange     = $null
                    CertificateValid = $null
                    CertificateErrors = @()
                    Error           = 'Protocol enum is unavailable in this runtime.'
                }
            )

            continue
        }

        $tcp = $null
        $ssl = $null
        $validation = @{
            Errors = $null
            ChainStatus = @()
        }

        $result = 'Inconclusive'
        $errorMessage = $null
        $cipherAlgorithm = $null
        $cipherStrength = $null
        $hashAlgorithm = $null
        $keyExchange = $null
        $certificateValid = $null
        $certificateErrors = @()

        try {
            $tcp = New-Object System.Net.Sockets.TcpClient

            $connectResult = $tcp.BeginConnect(
                $ComputerName,
                $Port,
                $null,
                $null
            )

            try {
                if (-not $connectResult.AsyncWaitHandle.WaitOne(
                    [TimeSpan]::FromSeconds($TimeoutSec)
                )) {
                    throw "TCP connection timed out after $TimeoutSec seconds."
                }

                $tcp.EndConnect($connectResult)
            }
            finally {
                $connectResult.AsyncWaitHandle.Close()
            }

            $tcp.ReceiveTimeout = $TimeoutSec * 1000
            $tcp.SendTimeout = $TimeoutSec * 1000

            $callback = {
                param(
                    $sender,
                    $certificate,
                    $chain,
                    $sslPolicyErrors
                )

                $validation.Errors = [string]$sslPolicyErrors

                $validation.ChainStatus = @(
                    if ($null -ne $chain) {
                        foreach ($status in $chain.ChainStatus) {
                            [PSCustomObject]@{
                                Status = [string]$status.Status
                                Information = [string]$status.StatusInformation
                            }
                        }
                    }
                )

                # Allows the handshake to complete for inspection only.
                # Certificate validity is reported separately.
                return $true
            }.GetNewClosure()

            $ssl = New-Object System.Net.Security.SslStream(
                $tcp.GetStream(),
                $false,
                $callback
            )

            $ssl.ReadTimeout = $TimeoutSec * 1000
            $ssl.WriteTimeout = $TimeoutSec * 1000

            $ssl.AuthenticateAsClient(
                $ComputerName,
                $null,
                $protocol,
                $false
            )

            $result = 'HandshakeSucceeded'

            $cipherAlgorithm = [string]$ssl.CipherAlgorithm
            $cipherStrength = [int]$ssl.CipherStrength
            $hashAlgorithm = [string]$ssl.HashAlgorithm
            $keyExchange = [string]$ssl.KeyExchangeAlgorithm

            $certificateErrors = @($validation.Errors)

            $certificateValid = (
                $validation.Errors -eq 'None' -and
                $validation.ChainStatus.Count -eq 0
            )
        }
        catch {
            $errorMessage = $_.Exception.Message

            if (
                $errorMessage -match '(?i)protocol|handshake|authentication|secure channel'
            ) {
                $result = 'Inconclusive'
            }
            elseif (
                $errorMessage -match '(?i)timed out|refused|unreachable|actively refused'
            ) {
                $result = 'ConnectionFailed'
            }
            else {
                $result = 'Inconclusive'
            }
        }
        finally {
            if ($null -ne $ssl) {
                $ssl.Dispose()
            }

            if ($null -ne $tcp) {
                $tcp.Dispose()
            }
        }

        $results.Add(
            [PSCustomObject]@{
                Protocol          = $name
                Supported         = if ($result -eq 'HandshakeSucceeded') {
                    $true
                }
                elseif ($result -eq 'ConnectionFailed') {
                    $null
                }
                else {
                    $null
                }
                Result            = $result
                Deprecated        = $name -in @('Ssl3', 'Tls', 'Tls11')
                CipherAlgorithm   = $cipherAlgorithm
                CipherStrength    = $cipherStrength
                HashAlgorithm     = $hashAlgorithm
                KeyExchange       = $keyExchange
                CertificateValid  = $certificateValid
                CertificateErrors = $certificateErrors
                ChainStatus       = @($validation.ChainStatus)
                Error             = $errorMessage
            }
        )
    }

    return $results.ToArray()
}

# ---------------------------------------------------------------------------
# Complete web application assessment
# ---------------------------------------------------------------------------

function Invoke-WebAppAssessment {
    <#
    .SYNOPSIS
        Runs passive HTTP header, cookie, and TLS checks against supplied URLs.

    .EXAMPLE
        Invoke-WebAppAssessment `
            -Urls 'https://app.example.com','https://api.example.com' `
            -OutputPath 'C:\Reports\webapp.json'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Urls,

        [string]$OutputPath,

        [ValidateRange(1, 120)]
        [int]$TimeoutSec = 15
    )

    $results = New-Object 'System.Collections.Generic.List[object]'

    foreach ($url in $Urls) {
        Write-Verbose "Assessing $url"

        try {
            $uri = Resolve-WebAssessmentUri -Url $url

            $headers = Get-SecurityHeaderAudit `
                -Url $uri.AbsoluteUri `
                -TimeoutSec $TimeoutSec

            $cookies = Get-CookieFlagAudit `
                -Url $uri.AbsoluteUri `
                -TimeoutSec $TimeoutSec

            $tls = if ($uri.Scheme -eq 'https') {
                Get-TlsCipherAudit `
                    -ComputerName $uri.DnsSafeHost `
                    -Port $uri.Port `
                    -TimeoutSec $TimeoutSec
            }
            else {
                @()
            }

            $results.Add(
                [PSCustomObject]@{
                    Url             = $uri.AbsoluteUri
                    Scheme          = $uri.Scheme
                    Host            = $uri.DnsSafeHost
                    Port            = $uri.Port
                    SecurityHeaders = $headers
                    Cookies         = $cookies
                    TlsCiphers      = @($tls)
                    Error           = $null
                }
            )
        }
        catch {
            $results.Add(
                [PSCustomObject]@{
                    Url             = $url
                    Scheme          = $null
                    Host            = $null
                    Port            = $null
                    SecurityHeaders = $null
                    Cookies         = $null
                    TlsCiphers      = @()
                    Error           = $_.Exception.Message
                }
            )
        }
    }

    $report = [PSCustomObject]@{
        GeneratedAt = [DateTime]::UtcNow.ToString('o')
        TargetCount = $results.Count
        Results     = $results.ToArray()
        Export      = $null
    }

    if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
        $tempPath = $null

        try {
            $fullPath = [System.IO.Path]::GetFullPath($OutputPath)
            $directory = [System.IO.Path]::GetDirectoryName($fullPath)

            if (
                -not [string]::IsNullOrWhiteSpace($directory) -and
                -not (Test-Path -LiteralPath $directory -PathType Container)
            ) {
                New-Item -Path $directory -ItemType Directory -Force `
                    -ErrorAction Stop | Out-Null
            }

            $json = ConvertTo-Json `
                -InputObject $report `
                -Depth 10 `
                -ErrorAction Stop

            $tempPath = Join-Path $directory (
                [System.IO.Path]::GetRandomFileName() + '.tmp'
            )

            [System.IO.File]::WriteAllText(
                $tempPath,
                $json,
                (New-Object System.Text.UTF8Encoding($false))
            )

            if (Test-Path -LiteralPath $fullPath -PathType Leaf) {
                [System.IO.File]::Replace(
                    $tempPath,
                    $fullPath,
                    $null
                )
            }
            else {
                [System.IO.File]::Move(
                    $tempPath,
                    $fullPath
                )
            }

            $report.Export = [PSCustomObject]@{
                Success    = $true
                OutputPath = $fullPath
                Error      = $null
            }
        }
        catch {
            $report.Export = [PSCustomObject]@{
                Success    = $false
                OutputPath = $OutputPath
                Error      = $_.Exception.Message
            }

            Write-Warning "Report export failed: $($_.Exception.Message)"
        }
        finally {
            if (
                -not [string]::IsNullOrWhiteSpace($tempPath) -and
                (Test-Path -LiteralPath $tempPath)
            ) {
                Remove-Item -LiteralPath $tempPath -Force `
                    -ErrorAction SilentlyContinue
            }
        }
    }

    return $report
}

Export-ModuleMember -Function @(
    'Get-SecurityHeaderAudit'
    'Get-CookieFlagAudit'
    'Get-TlsCipherAudit'
    'Invoke-WebAppAssessment'
)
