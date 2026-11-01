
#Requires -Version 7.0
<#
.SYNOPSIS
    Network discovery and configuration assessment toolkit.

.DESCRIPTION
    Provides basic ICMP host discovery, bounded IPv4 CIDR expansion,
    TCP connection checks, DNS zone-transfer configuration checks,
    and TLS certificate inspection.

    Designed for scoped, authorized assessments.

    Uses Windows PowerShell 5.1-compatible PowerShell and .NET APIs.
    Network checks are sequential and do not implement stealth,
    fragmentation, timing evasion, or service exploitation.

.NOTES
    Run only against systems and networks you are explicitly authorized
    to assess.
#>

# ---------------------------------------------------------------------------
# Host discovery
# ---------------------------------------------------------------------------
function Invoke-HostDiscovery {
    <#
    .SYNOPSIS
        Checks ICMP reachability for a supplied list of hosts.

    .DESCRIPTION
        Uses System.Net.NetworkInformation.Ping.
        Hosts that do not respond are not necessarily offline; ICMP may
        be filtered by a firewall or network device.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$ComputerName,

        [ValidateRange(1, 60000)]
        [int]$TimeoutMs = 1000
    )

    foreach ($target in $ComputerName) {
        if ([string]::IsNullOrWhiteSpace($target)) {
            continue
        }

        $ping = $null

        try {
            $ping = New-Object System.Net.NetworkInformation.Ping
            $reply = $ping.Send($target, $TimeoutMs)

            [PSCustomObject]@{
                Host        = $target
                Alive       = ($reply.Status -eq 'Success')
                Status      = $reply.Status.ToString()
                Address     = if ($reply.Address) {
                    $reply.Address.ToString()
                } else {
                    $null
                }
                RoundtripMs = if ($reply.Status -eq 'Success') {
                    $reply.RoundtripTime
                } else {
                    $null
                }
                Error       = $null
            }
        }
        catch {
            [PSCustomObject]@{
                Host        = $target
                Alive       = $false
                Status      = 'Error'
                Address     = $null
                RoundtripMs = $null
                Error       = $_.Exception.Message
            }
        }
        finally {
            if ($null -ne $ping) {
                $ping.Dispose()
            }
        }
    }
}

# ---------------------------------------------------------------------------
# IPv4 CIDR expansion
# ---------------------------------------------------------------------------
function Expand-CidrRange {
    <#
    .SYNOPSIS
        Expands a bounded IPv4 CIDR range into individual addresses.

    .DESCRIPTION
        Accepts IPv4 prefixes from /16 through /32.
        For /17 through /30, network and broadcast addresses are excluded.
        For /31, both addresses are returned.
        For /32, the single address is returned.

        The /16 boundary limits expansion to a maximum of 65,534 addresses.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Cidr
    )

    if ($Cidr -notmatch '^([^/]+)/(\d{1,2})$') {
        throw "Invalid CIDR notation: $Cidr"
    }

    $addressText = $Matches[1]
    $prefixText = $Matches[2]

    $ip = $null

    if (
        -not [System.Net.IPAddress]::TryParse(
            $addressText,
            [ref]$ip
        )
    ) {
        throw "Invalid IP address: $addressText"
    }

    if ($ip.AddressFamily -ne
        [System.Net.Sockets.AddressFamily]::InterNetwork) {
        throw 'Only IPv4 CIDR ranges are supported.'
    }

    $prefix = [int]$prefixText

    if ($prefix -lt 16 -or $prefix -gt 32) {
        throw "Prefix must be between /16 and /32. Received: /$prefix"
    }

    $bytes = $ip.GetAddressBytes()

    # Convert network-order bytes into an unsigned 32-bit integer.
    [Array]::Reverse($bytes)
    $ipInt = [uint64][BitConverter]::ToUInt32($bytes, 0)

    $hostBits = 32 - $prefix
    $blockSize = [uint64][math]::Pow(2, $hostBits)

    $networkInt = [uint64](
        [math]::Floor($ipInt / $blockSize) * $blockSize
    )

    $lastInt = $networkInt + $blockSize - 1

    if ($prefix -eq 32) {
        $startInt = $networkInt
        $endInt = $networkInt
    }
    elseif ($prefix -eq 31) {
        $startInt = $networkInt
        $endInt = $lastInt
    }
    else {
        $startInt = $networkInt + 1
        $endInt = $lastInt - 1
    }

    for ($current = $startInt; $current -le $endInt; $current++) {
        $currentBytes = [BitConverter]::GetBytes(
            [uint32]$current
        )

        [Array]::Reverse($currentBytes)

        ([System.Net.IPAddress]::new($currentBytes)).ToString()
    }
}

# ---------------------------------------------------------------------------
# TCP connectivity checks
# ---------------------------------------------------------------------------
function Invoke-PortSweep {
    <#
    .SYNOPSIS
        Checks TCP connection reachability for supplied hosts and ports.

    .DESCRIPTION
        Uses ordinary TCP connections through System.Net.Sockets.TcpClient.

        Results distinguish successful connections, refused connections,
        timeouts, and other connection errors.

        A timeout does not establish that a port is closed.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$ComputerName,

        [ValidateNotNullOrEmpty()]
        [int[]]$Ports = @(
            22, 80, 135, 139, 443, 445,
            1433, 3306, 3389, 5985, 5986
        ),

        [ValidateRange(1, 60000)]
        [int]$TimeoutMs = 1000
    )

    foreach ($port in $Ports) {
        if ($port -lt 1 -or $port -gt 65535) {
            throw "Invalid TCP port: $port. Valid ports are 1 through 65535."
        }
    }

    foreach ($target in $ComputerName) {
        if ([string]::IsNullOrWhiteSpace($target)) {
            continue
        }

        foreach ($port in $Ports) {
            $client = $null
            $asyncResult = $null
            $waitHandle = $null

            $status = 'Error'
            $errorMessage = $null

            try {
                $client = New-Object System.Net.Sockets.TcpClient

                $asyncResult = $client.BeginConnect(
                    $target,
                    $port,
                    $null,
                    $null
                )

                $waitHandle = $asyncResult.AsyncWaitHandle

                $completed = $waitHandle.WaitOne($TimeoutMs)

                if (-not $completed) {
                    $status = 'TimedOut'
                    $errorMessage = 'Connection attempt exceeded timeout.'
                }
                else {
                    try {
                        $client.EndConnect($asyncResult)

                        if ($client.Connected) {
                            $status = 'Open'
                        }
                        else {
                            $status = 'ConnectionFailed'
                        }
                    }
                    catch {
                        $socketException = $_.Exception

                        while (
                            $null -ne $socketException.InnerException
                        ) {
                            $socketException = $socketException.InnerException
                        }

                        if (
                            $socketException -is
                            [System.Net.Sockets.SocketException]
                        ) {
                            switch ($socketException.SocketErrorCode) {
                                'ConnectionRefused' {
                                    $status = 'Closed'
                                }
                                'TimedOut' {
                                    $status = 'TimedOut'
                                }
                                'HostUnreachable' {
                                    $status = 'Unreachable'
                                }
                                'NetworkUnreachable' {
                                    $status = 'Unreachable'
                                }
                                default {
                                    $status = 'ConnectionFailed'
                                }
                            }

                            $errorMessage = $socketException.Message
                        }
                        else {
                            $status = 'ConnectionFailed'
                            $errorMessage = $_.Exception.Message
                        }
                    }
                }
            }
            catch {
                $status = 'Error'
                $errorMessage = $_.Exception.Message
            }
            finally {
                if ($null -ne $waitHandle) {
                    $waitHandle.Close()
                }

                if ($null -ne $client) {
                    $client.Close()
                }
            }

            [PSCustomObject]@{
                Host   = $target
                Port   = $port
                Status = $status
                Open   = ($status -eq 'Open')
                Error  = $errorMessage
            }
        }
    }
}

# ---------------------------------------------------------------------------
# DNS zone-transfer configuration check
# ---------------------------------------------------------------------------
function Test-DnsZoneTransfer {
    <#
    .SYNOPSIS
        Checks whether a DNS server permits an AXFR zone transfer.

    .DESCRIPTION
        Uses nslookup to request an AXFR transfer.

        Only an explicit successful-transfer indicator is reported as
        allowed. Refusal indicators are reported separately.
        Ambiguous output is classified as inconclusive.

        Raw output may contain DNS records and should be treated as
        potentially sensitive assessment data.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Zone,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$NameServer
    )

    $nslookup = Get-Command nslookup.exe -ErrorAction SilentlyContinue

    if (-not $nslookup) {
        $nslookup = Get-Command nslookup -ErrorAction SilentlyContinue
    }

    if (-not $nslookup) {
        return [PSCustomObject]@{
            Zone            = $Zone
            NameServer      = $NameServer
            Status          = 'Unavailable'
            TransferAllowed = $null
            RawOutput       = $null
            Error           = 'nslookup was not found.'
        }
    }

    try {
        $output = @(
            & $nslookup.Source "-type=AXFR" $Zone $NameServer 2>&1
        )

        $raw = ($output | ForEach-Object { "$_" }) -join "`n"

        if (
            $raw -match '(?i)connection refused|connection reset|not authorized|not permitted|permission denied|transfer refused|refused by server|not allowed'
        ) {
            $status = 'Refused'
            $allowed = $false
        }
        elseif (
            $raw -match '(?i)XFR size:\s*\d+|zone transfer successful'
        ) {
            $status = 'Allowed'
            $allowed = $true
        }
        else {
            $status = 'Inconclusive'
            $allowed = $null
        }

        [PSCustomObject]@{
            Zone            = $Zone
            NameServer      = $NameServer
            Status          = $status
            TransferAllowed = $allowed
            RawOutput       = $raw
            Error           = $null
        }
    }
    catch {
        [PSCustomObject]@{
            Zone            = $Zone
            NameServer      = $NameServer
            Status          = 'Error'
            TransferAllowed = $null
            RawOutput       = $null
            Error           = $_.Exception.Message
        }
    }
}

# ---------------------------------------------------------------------------
# TLS configuration inspection
# ---------------------------------------------------------------------------
function Test-TlsConfig {
    <#
    .SYNOPSIS
        Inspects negotiated TLS protocol and remote certificate information.

    .DESCRIPTION
        Establishes a TLS handshake and records certificate validation
        errors, certificate identity, and expiration information.

        The validation callback allows the handshake to complete so that
        certificate details can be inspected even when the certificate is
        invalid. The result explicitly reports validation status.

        This is an assessment-only connection. It must not be used to
        establish trust in the remote endpoint.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName,

        [ValidateRange(1, 65535)]
        [int]$Port = 443,

        [ValidateRange(1, 60000)]
        [int]$TimeoutMs = 5000
    )

    $tcp = $null
    $sslStream = $null
    $asyncResult = $null
    $waitHandle = $null

    $validationErrors = $null
    $chainStatus = @()
    $certificate = $null

    try {
        $tcp = New-Object System.Net.Sockets.TcpClient

        $asyncResult = $tcp.BeginConnect(
            $ComputerName,
            $Port,
            $null,
            $null
        )

        $waitHandle = $asyncResult.AsyncWaitHandle

        if (-not $waitHandle.WaitOne($TimeoutMs)) {
            throw "TCP connection to ${ComputerName}:$Port timed out."
        }

        $tcp.EndConnect($asyncResult)

        $validationState = @{ Errors = $null; ChainStatus = @() }
        $callback = {
            param(
                $sender,
                $remoteCertificate,
                $remoteChain,
                $sslPolicyErrors
            )

            $validationState.Errors = $sslPolicyErrors
            $validationState.ChainStatus = @()

            if ($null -ne $remoteChain) {
                $validationState.ChainStatus = @(
                    $remoteChain.ChainStatus |
                        ForEach-Object {
                            [PSCustomObject]@{
                                Status = $_.Status.ToString()
                                Information = $_.StatusInformation.Trim()
                            }
                        }
                )
            }

            # This permits inspection only. The report records whether
            # normal certificate validation would have succeeded.
            return $true
        }.GetNewClosure()

        $sslStream = New-Object System.Net.Security.SslStream(
            $tcp.GetStream(),
            $false,
            $callback
        )

        $sslStream.ReadTimeout = $TimeoutMs
        $sslStream.WriteTimeout = $TimeoutMs

        $sslStream.AuthenticateAsClient($ComputerName)

        $validationErrors = $validationState.Errors
        $chainStatus = @($validationState.ChainStatus)

        $certificate = New-Object `
            System.Security.Cryptography.X509Certificates.X509Certificate2(
                $sslStream.RemoteCertificate
            )

        $now = Get-Date
        $expired = ($certificate.NotAfter -lt $now)
        $notYetValid = ($certificate.NotBefore -gt $now)

        $chainValid = (
            $validationErrors -eq
            [System.Net.Security.SslPolicyErrors]::None
        )

        [PSCustomObject]@{
            Host                         = $ComputerName
            Port                         = $Port
            Status                       = 'Connected'
            Protocol                     = $sslStream.SslProtocol.ToString()
            CertSubject                  = $certificate.Subject
            CertIssuer                   = $certificate.Issuer
            CertThumbprint               = $certificate.Thumbprint
            CertNotBefore                = $certificate.NotBefore
            CertNotAfter                 = $certificate.NotAfter
            CertExpired                  = $expired
            CertNotYetValid              = $notYetValid
            ChainValid                   = $chainValid
            ValidationErrors             = "$validationErrors"
            ChainStatus                  = $chainStatus
            ValidationBypassedForInspection = $true
            Error                        = $null
        }
    }
    catch {
        [PSCustomObject]@{
            Host                            = $ComputerName
            Port                            = $Port
            Status                          = 'Error'
            Protocol                        = $null
            CertSubject                     = $null
            CertIssuer                      = $null
            CertThumbprint                  = $null
            CertNotBefore                   = $null
            CertNotAfter                    = $null
            CertExpired                     = $null
            CertNotYetValid                 = $null
            ChainValid                      = $null
            ValidationErrors                = "$validationErrors"
            ChainStatus                     = $chainStatus
            ValidationBypassedForInspection = $true
            Error                           = $_.Exception.Message
        }
    }
    finally {
        if ($null -ne $sslStream) {
            $sslStream.Dispose()
        }

        if ($null -ne $tcp) {
            $tcp.Close()
        }

        if ($null -ne $waitHandle) {
            $waitHandle.Close()
        }

        if ($null -ne $certificate) {
            $certificate.Dispose()
        }

        Remove-Variable __NetworkSweepTlsValidationErrors `
            -Scope Script -ErrorAction SilentlyContinue

        Remove-Variable __NetworkSweepTlsChainStatus `
            -Scope Script -ErrorAction SilentlyContinue
    }
}

Export-ModuleMember -Function @(
    'Invoke-HostDiscovery'
    'Expand-CidrRange'
    'Invoke-PortSweep'
    'Test-DnsZoneTransfer'
    'Test-TlsConfig'
)
