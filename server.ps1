# NetScope Web Server & High-Concurrency Network Matrix Engine
# Author: Kerr (https://github.com/kerr20801)
# Pure ASCII/UTF-8 encoding - 100% portable on Windows 10/11/Server

param(
    [int]$Port = 8900,
    [switch]$NoBrowser
)

$Prefix = "http://localhost:$($Port)/"
$HtmlPath = Join-Path $PSScriptRoot "index.html"

$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add($Prefix)

try {
    $listener.Start()
} catch {
    Write-Host "Failed to start listener on port $Port : $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " NetScope - Network Matrix & Packet Threat Scope is RUNNING!" -ForegroundColor Green
Write-Host " URL: $Prefix" -ForegroundColor Yellow
Write-Host " Engine: High-Concurrency Async Socket + PacketScope" -ForegroundColor Green
Write-Host " Press Ctrl + C to stop the service." -ForegroundColor Gray
Write-Host "==========================================================" -ForegroundColor Cyan

# Auto open browser
if (-not $NoBrowser) {
    Start-Process $Prefix
}

function Send-JsonResponse($response, $data, [int]$statusCode = 200) {
    $json = $data | ConvertTo-Json -Depth 6 -Compress
    $buffer = [System.Text.Encoding]::UTF8.GetBytes($json)
    $response.StatusCode = $statusCode
    $response.ContentType = "application/json; charset=utf-8"
    $response.ContentLength64 = $buffer.Length
    $response.OutputStream.Write($buffer, 0, $buffer.Length)
    $response.OutputStream.Close()
}

function Send-HtmlResponse($response, $filePath) {
    if (Test-Path $filePath) {
        $buffer = [System.IO.File]::ReadAllBytes($filePath)
        $response.StatusCode = 200
        $response.ContentType = "text/html; charset=utf-8"
        $response.ContentLength64 = $buffer.Length
        $response.OutputStream.Write($buffer, 0, $buffer.Length)
    } else {
        $response.StatusCode = 404
    }
    $response.OutputStream.Close()
}

while ($listener.IsListening) {
    $context = $listener.GetContext()
    $request = $context.Request
    $response = $context.Response

    # Restrict CORS to localhost only for security
    $origin = $request.Headers["Origin"]
    if ($origin -and ($origin -like "http://localhost:*" -or $origin -like "http://127.0.0.1:*")) {
        $response.AddHeader("Access-Control-Allow-Origin", $origin)
    } else {
        $response.AddHeader("Access-Control-Allow-Origin", "http://localhost:$Port")
    }
    $response.AddHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
    $response.AddHeader("Access-Control-Allow-Headers", "Content-Type")

    if ($request.HttpMethod -eq "OPTIONS") {
        $response.StatusCode = 200
        $response.OutputStream.Close()
        continue
    }

    $rawUrl = $request.RawUrl

    # 1. Serve index.html
    if ($rawUrl -eq "/" -or $rawUrl -eq "/index.html") {
        Send-HtmlResponse $response $HtmlPath
        continue
    }

    # 2. API: System Info & Local IP
    if ($rawUrl -eq "/api/sysinfo" -and $request.HttpMethod -eq "GET") {
        try {
            $hostname = [System.Net.Dns]::GetHostName()
            $ips = [System.Net.Dns]::GetHostAddresses($hostname) | Where-Object { 
                $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork -and -not $_.IPAddressToString.StartsWith("127.") 
            } | Select-Object -ExpandProperty IPAddressToString
            
            Send-JsonResponse $response @{
                success  = $true
                hostname = $hostname
                ips      = @($ips)
                time     = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            }
        } catch {
            Send-JsonResponse $response @{ success = $false; message = $_.Exception.Message }
        }
        continue
    }

    # 3. API: Parallel High-Concurrency Network Matrix Probe
    if ($rawUrl -eq "/api/probe" -and $request.HttpMethod -eq "POST") {
        $reader = New-Object System.IO.StreamReader($request.InputStream, [System.Text.Encoding]::UTF8)
        $body = $reader.ReadToEnd() | ConvertFrom-Json

        $targets = $body.targets
        if (-not $targets -or $targets.Count -eq 0) {
            Send-JsonResponse $response @{ success = $false; message = "No probe targets provided." }
            continue
        }

        $batchTimeoutMs = if ($body.timeoutMs) { [int]$body.timeoutMs } else { 2500 }
        $totalSw = [System.Diagnostics.Stopwatch]::StartNew()

        # Step A: Resolve DNS and prepare socket tasks
        $socketTasks = @()
        $immediateResults = @()

        foreach ($item in $targets) {
            $h = ("" + $item.host).Trim()
            $p = if ($item.port) { [int]$item.port } else { 80 }
            $proto = if ($item.protocol) { ("" + $item.protocol).ToLower().Trim() } else { "tcp" }
            $label = ("" + $item.label).Trim()
            $category = if ($item.category) { ("" + $item.category).Trim() } else { "General" }

            # DNS Resolution
            $resolvedIp = $null
            try {
                $addrList = [System.Net.Dns]::GetHostAddresses($h)
                if ($addrList -and $addrList.Length -gt 0) {
                    $resolvedIp = $addrList[0].IPAddressToString
                }
            } catch {
                # DNS failure
            }

            if (-not $resolvedIp) {
                $immediateResults += [PSCustomObject]@{
                    host      = $h
                    ip        = ""
                    port      = $p
                    protocol  = $proto
                    label     = $label
                    category  = $category
                    status    = "DNS_ERROR"
                    latencyMs = 0
                    message   = "DNS 解析失敗 (無法解析主機名稱)"
                }
                continue
            }

            # Handle ICMP Ping
            if ($proto -eq "icmp" -or $proto -eq "ping") {
                try {
                    $ping = New-Object System.Net.NetworkInformation.Ping
                    $pingSw = [System.Diagnostics.Stopwatch]::StartNew()
                    $reply = $ping.Send($resolvedIp, $batchTimeoutMs)
                    $pingSw.Stop()
                    if ($reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) {
                        $immediateResults += [PSCustomObject]@{
                            host      = $h
                            ip        = $resolvedIp
                            port      = 0
                            protocol  = "icmp"
                            label     = $label
                            category  = $category
                            status    = "PASS"
                            latencyMs = $reply.RoundtripTime
                            message   = "Ping 回應正常 ($($reply.RoundtripTime)ms)"
                        }
                    } else {
                        $immediateResults += [PSCustomObject]@{
                            host      = $h
                            ip        = $resolvedIp
                            port      = 0
                            protocol  = "icmp"
                            label     = $label
                            category  = $category
                            status    = "DROP"
                            latencyMs = $pingSw.ElapsedMilliseconds
                            message   = "Ping 逾時無回應 ($($reply.Status))"
                        }
                    }
                } catch {
                    $immediateResults += [PSCustomObject]@{
                        host      = $h
                        ip        = $resolvedIp
                        port      = 0
                        protocol  = "icmp"
                        label     = $label
                        category  = $category
                        status    = "DROP"
                        latencyMs = $batchTimeoutMs
                        message   = "Ping 失敗: $($_.Exception.Message)"
                    }
                }
                continue
            }

            # Handle UDP Probe
            if ($proto -eq "udp") {
                try {
                    $udp = New-Object System.Net.Sockets.UdpClient
                    $swItem = [System.Diagnostics.Stopwatch]::StartNew()
                    $udp.Connect($resolvedIp, $p)

                    # Prepare UDP payload based on common port semantics
                    $payload = [byte[]]@(0x00)
                    if ($p -eq 53) {
                        # Standard DNS root query (17 bytes)
                        $payload = [byte[]]@(0x12,0x34,0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x01)
                    } elseif ($p -eq 123) {
                        # Standard NTP client request (48 bytes, mode 3 client)
                        $payload = ,0 * 48
                        $payload[0] = 0x1B
                    } elseif ($p -eq 161) {
                        # SNMP v2c GetRequest PDU
                        $payload = [byte[]]@(0x30,0x26,0x02,0x01,0x01,0x04,0x06,0x70,0x75,0x62,0x6c,0x69,0x63,0xa0,0x19,0x02,0x04,0x00,0x00,0x00,0x01,0x02,0x01,0x00,0x02,0x01,0x00,0x30,0x0b,0x30,0x09,0x06,0x05,0x2b,0x06,0x01,0x02,0x01,0x05,0x00)
                    }

                    [void]$udp.Send($payload, $payload.Length)
                    $ar = $udp.BeginReceive($null, $null)
                    $socketTasks += [PSCustomObject]@{
                        Client    = $udp
                        Async     = $ar
                        Host      = $h
                        Ip        = $resolvedIp
                        Port      = $p
                        Protocol  = "udp"
                        Label     = $label
                        Category  = $category
                        Sw        = $swItem
                    }
                } catch {
                    $swItem.Stop()
                    $inner = if ($_.Exception.InnerException) { $_.Exception.InnerException } else { $_.Exception }
                    $fullErr = $inner.Message
                    $socketErr = if ($inner -is [System.Net.Sockets.SocketException]) { $inner.SocketErrorCode } else { $null }
                    $isRst = ($socketErr -eq [System.Net.Sockets.SocketError]::ConnectionReset -or $fullErr -like "*closed by the remote host*" -or $fullErr -like "*forcibly closed*")
                    $status = if ($isRst) { "REFUSED" } else { "DROP" }
                    $msg = if ($isRst) { "防火牆已開通，但收到 ICMP Port Unreachable (目標主機存活但無服務監聽 UDP Port $($p))" } else { "UDP 錯誤: $fullErr" }
                    try { $udp.Close() } catch {}
                    $immediateResults += [PSCustomObject]@{
                        host      = $h
                        ip        = $resolvedIp
                        port      = $p
                        protocol  = "udp"
                        label     = $label
                        category  = $category
                        status    = $status
                        latencyMs = $swItem.ElapsedMilliseconds
                        message   = $msg
                    }
                }
                continue
            }

            # For TCP: initiate async socket connect without blocking
            try {
                $tcp = New-Object System.Net.Sockets.TcpClient
                $swItem = [System.Diagnostics.Stopwatch]::StartNew()
                $ar = $tcp.BeginConnect($resolvedIp, $p, $null, $null)
                $socketTasks += [PSCustomObject]@{
                    Client    = $tcp
                    Async     = $ar
                    Host      = $h
                    Ip        = $resolvedIp
                    Port      = $p
                    Protocol  = "tcp"
                    Label     = $label
                    Category  = $category
                    Sw        = $swItem
                }
            } catch {
                $immediateResults += [PSCustomObject]@{
                    host      = $h
                    ip        = $resolvedIp
                    port      = $p
                    protocol  = "tcp"
                    label     = $label
                    category  = $category
                    status    = "DROP"
                    latencyMs = 0
                    message   = "Socket 初始化異常: $($_.Exception.Message)"
                }
            }
        }

        # Step B: Wait for all sockets with polling loop until batchTimeoutMs
        $deadline = [DateTime]::UtcNow.AddMilliseconds($batchTimeoutMs)
        while ($socketTasks | Where-Object { -not $_.Async.IsCompleted }) {
            if ([DateTime]::UtcNow -ge $deadline) { break }
            Start-Sleep -Milliseconds 15
        }

        # Step C: Inspect results of all concurrent TCP and UDP sockets
        $asyncResults = @()
        foreach ($s in $socketTasks) {
            $s.Sw.Stop()
            $elapsed = $s.Sw.ElapsedMilliseconds
            $isDone = $s.Async.IsCompleted
            $status = "DROP"
            $errorMsg = ""

            if ($s.Protocol -eq "udp") {
                if ($isDone) {
                    try {
                        $ep = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
                        $recvBytes = $s.Client.EndReceive($s.Async, [ref]$ep)
                        $status = "PASS"
                        $errorMsg = "UDP 握手/回應成功 (收到 $($recvBytes.Length) 位元組回應，延遲 $($elapsed)ms)"
                    } catch {
                        $inner = if ($_.Exception.InnerException) { $_.Exception.InnerException } else { $_.Exception }
                        $fullErr = $inner.Message
                        $socketErr = if ($inner -is [System.Net.Sockets.SocketException]) { $inner.SocketErrorCode } else { $null }
                        if ($socketErr -eq [System.Net.Sockets.SocketError]::ConnectionReset -or $fullErr -like "*closed by the remote host*" -or $fullErr -like "*forcibly closed*") {
                            $status = "REFUSED"
                            $errorMsg = "防火牆已開通，但收到 ICMP Port Unreachable (目標主機存活但無服務監聽 UDP Port $($s.Port))"
                        } else {
                            $status = "DROP"
                            $errorMsg = "UDP 探測失敗: $fullErr"
                        }
                    }
                } else {
                    $status = "DROP"
                    $errorMsg = "UDP 逾時無回應 (未收到回應或 ICMP 回覆，可能被防火牆丟包或為單向 UDP 服務)"
                }
            } else {
                # TCP
                if ($isDone) {
                    try {
                        $s.Client.EndConnect($s.Async)
                        $status = "PASS"
                        $errorMsg = "TCP Handshake 握手成功 ($($elapsed)ms)"
                    } catch {
                        $inner = if ($_.Exception.InnerException) { $_.Exception.InnerException } else { $_.Exception }
                        $fullErr = if ($inner) { $inner.Message } else { $_.Exception.Message }
                        $socketErr = if ($inner -is [System.Net.Sockets.SocketException]) { $inner.SocketErrorCode } else { $null }
                        # Check for ConnectionRefused (TCP RST received -> Firewall passed!)
                        if ($socketErr -eq [System.Net.Sockets.SocketError]::ConnectionRefused -or $fullErr -like "*refused*" -or $fullErr -like "*拒絕*" -or $fullErr -like "*actively refused*") {
                            $status = "REFUSED"
                            $errorMsg = "防火牆已開通，但連線被拒絕 (收到 TCP RST，目標主機未監聽 Port $($s.Port))"
                        } else {
                            $status = "DROP"
                            $errorMsg = "連線失敗: $fullErr"
                        }
                    }
                } else {
                    $status = "DROP"
                    $errorMsg = "連線逾時 (防火牆未開通或路由丟包 Silent Drop)"
                }
            }

            try { $s.Client.Close() } catch {}

            $asyncResults += [PSCustomObject]@{
                host      = $s.Host
                ip        = $s.Ip
                port      = $s.Port
                protocol  = $s.Protocol
                label     = $s.Label
                category  = $s.Category
                status    = $status
                latencyMs = $elapsed
                message   = $errorMsg
            }
        }

        $allResults = @($immediateResults) + @($asyncResults)
        $totalSw.Stop()

        # Generate summary stats
        $totalCount   = @($allResults).Count
        $passCount    = @($allResults | Where-Object { $_.status -eq "PASS" }).Count
        $refusedCount = @($allResults | Where-Object { $_.status -eq "REFUSED" }).Count
        $dropCount    = @($allResults | Where-Object { $_.status -eq "DROP" }).Count
        $dnsErrCount  = @($allResults | Where-Object { $_.status -eq "DNS_ERROR" }).Count

        Send-JsonResponse $response @{
            success        = $true
            totalTimeMs    = $totalSw.ElapsedMilliseconds
            summary        = @{
                total    = $totalCount
                pass     = $passCount
                refused  = $refusedCount
                drop     = $dropCount
                dnsError = $dnsErrCount
            }
            results        = $allResults
        }
        continue
    }

    # 4. API: Live Probe Trace for PacketScope Integration
    # Generates tcpdump-compatible packet logs for the tested destination so PacketScope can analyze it
    if ($rawUrl -eq "/api/trace-packets" -and $request.HttpMethod -eq "POST") {
        $reader = New-Object System.IO.StreamReader($request.InputStream, [System.Text.Encoding]::UTF8)
        $body = $reader.ReadToEnd() | ConvertFrom-Json

        $targetHost = ("" + $body.host).Trim()
        $targetPort = if ($body.port) { [int]$body.port } else { 80 }
        $count      = if ($body.count) { [int]$body.count } else { 3 }
        $proto      = if ($body.protocol) { ("" + $body.protocol).ToLower().Trim() } else { "tcp" }

        $localIp = "192.168.1.100"
        try {
            $hName = [System.Net.Dns]::GetHostName()
            $ipObj = [System.Net.Dns]::GetHostAddresses($hName) | Where-Object { 
                $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork -and -not $_.IPAddressToString.StartsWith("127.") 
            } | Select-Object -First 1
            if ($ipObj) { $localIp = $ipObj.IPAddressToString }
        } catch {}

        # Resolve target IP
        $targetIp = $targetHost
        try {
            $addrs = [System.Net.Dns]::GetHostAddresses($targetHost)
            if ($addrs -and $addrs.Length -gt 0) { $targetIp = $addrs[0].IPAddressToString }
        } catch {}

        $tcpdumpLines = @()
        $now = [DateTime]::Now

        for ($i = 0; $i -lt $count; $i++) {
            $clientPort = Get-Random -Minimum 50000 -Maximum 65000
            $t1 = $now.AddMilliseconds($i * 600)
            $timeStr1 = $t1.ToString("yyyy-MM-dd HH:mm:ss.ffffff")

            if ($proto -eq "udp") {
                # Determine UDP test payload
                $payload = [byte[]]@(0x00)
                if ($targetPort -eq 53) {
                    $payload = [byte[]]@(0x12,0x34,0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x01)
                } elseif ($targetPort -eq 123) {
                    $payload = ,0 * 48
                    $payload[0] = 0x1B
                }

                $tcpdumpLines += "$timeStr1 IP $($localIp).$($clientPort) > $($targetIp).$($targetPort): UDP, length $($payload.Length)"

                $sw = [System.Diagnostics.Stopwatch]::StartNew()
                $udp = New-Object System.Net.Sockets.UdpClient
                try {
                    $udp.Connect($targetIp, $targetPort)
                    [void]$udp.Send($payload, $payload.Length)
                    $ar = $udp.BeginReceive($null, $null)
                    $completed = $ar.AsyncWaitHandle.WaitOne(1500, $false)
                    $sw.Stop()

                    $t2 = $t1.AddMilliseconds($sw.ElapsedMilliseconds)
                    $timeStr2 = $t2.ToString("yyyy-MM-dd HH:mm:ss.ffffff")

                    if ($completed) {
                        try {
                            $ep = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
                            $resBytes = $udp.EndReceive($ar, [ref]$ep)
                            $tcpdumpLines += "$timeStr2 IP $($targetIp).$($targetPort) > $($localIp).$($clientPort): UDP, length $($resBytes.Length)"
                        } catch {
                            # ICMP Port Unreachable
                            $tcpdumpLines += "$timeStr2 IP $($targetIp) > $($localIp): ICMP $($targetIp) udp port $($targetPort) unreachable, length 36"
                        }
                    } else {
                        $tcpdumpLines += "# [TIMEOUT] No UDP response from $($targetIp).$($targetPort) after 1500ms (Firewall Drop / Unreachable)"
                    }
                } catch {
                    $sw.Stop()
                    $t2 = $t1.AddMilliseconds($sw.ElapsedMilliseconds)
                    $timeStr2 = $t2.ToString("yyyy-MM-dd HH:mm:ss.ffffff")
                    $tcpdumpLines += "$timeStr2 IP $($targetIp) > $($localIp): ICMP $($targetIp) udp port $($targetPort) unreachable, length 36"
                } finally {
                    try { $udp.Close() } catch {}
                }
            } else {
                # TCP Probe
                $tcpdumpLines += "$timeStr1 IP $($localIp).$($clientPort) > $($targetIp).$($targetPort): Flags [S], seq 1, win 64240, length 0"

                $sw = [System.Diagnostics.Stopwatch]::StartNew()
                $tcp = New-Object System.Net.Sockets.TcpClient
                $ar = $tcp.BeginConnect($targetIp, $targetPort, $null, $null)
                $completed = $ar.AsyncWaitHandle.WaitOne(1500, $false)
                $sw.Stop()

                $t2 = $t1.AddMilliseconds($sw.ElapsedMilliseconds)
                $timeStr2 = $t2.ToString("yyyy-MM-dd HH:mm:ss.ffffff")

                if ($completed) {
                    try {
                        $tcp.EndConnect($ar)
                        # Handshake SYN-ACK received
                        $tcpdumpLines += "$timeStr2 IP $($targetIp).$($targetPort) > $($localIp).$($clientPort): Flags [SA], seq 1, ack 2, win 65535, length 0"
                        $t3 = $t2.AddMilliseconds(2)
                        $timeStr3 = $t3.ToString("yyyy-MM-dd HH:mm:ss.ffffff")
                        $tcpdumpLines += "$timeStr3 IP $($localIp).$($clientPort) > $($targetIp).$($targetPort): Flags [A], seq 2, ack 2, win 64240, length 0"
                    } catch {
                        # RST received (Connection Refused)
                        $tcpdumpLines += "$timeStr2 IP $($targetIp).$($targetPort) > $($localIp).$($clientPort): Flags [R], seq 1, win 0, length 0"
                    }
                } else {
                    # Timeout / Drop
                    $tcpdumpLines += "# [TIMEOUT] No response from $($targetIp).$($targetPort) after 1500ms (Firewall Drop / Unreachable)"
                }
                try { $tcp.Close() } catch {}
            }
        }

        Send-JsonResponse $response @{
            success     = $true
            target      = "$($proto.ToUpper()) $($targetHost):$($targetPort) ($($targetIp))"
            protocol    = $proto
            packetCount = $tcpdumpLines.Count
            tcpdumpText = ($tcpdumpLines -join [Environment]::NewLine)
        }
        continue
    }

    $response.StatusCode = 404
    $response.OutputStream.Close()
}
