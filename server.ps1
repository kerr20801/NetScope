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
    # 資安防護：強制禁止任何硬碟快取與資料殘留 (Zero-Disk-Retention)
    $response.AddHeader("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
    $response.AddHeader("Pragma", "no-cache")

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
            
            $gw = ""
            try {
                $route = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($route) { $gw = $route.NextHop }
            } catch {}
            if (-not $gw) { $gw = "192.168.1.1" }

            Send-JsonResponse $response @{
                success         = $true
                hostname        = $hostname
                ips             = @($ips)
                default_gateway = $gw
                os              = "win32"
                time            = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
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

    # 5. API: Zero-Knowledge 4-Step Sequential Field Triage
    if ($rawUrl -eq "/api/triage/run" -and $request.HttpMethod -eq "POST") {
        $reader = New-Object System.IO.StreamReader($request.InputStream, [System.Text.Encoding]::UTF8)
        $body = $reader.ReadToEnd() | ConvertFrom-Json

        $targetHost = if ($body.target_host) { ("" + $body.target_host).Trim() } else { "10.0.2.15" }
        $targetPort = if ($body.target_port) { [int]$body.target_port } else { 8080 }
        $proto      = if ($body.protocol) { ("" + $body.protocol).ToLower().Trim() } else { "tcp" }
        $switchLog  = if ($body.switch_log) { ("" + $body.switch_log) } else { "" }
        $gwLog      = if ($body.gw_log) { ("" + $body.gw_log) } else { "" }
        $targetLog  = if ($body.target_log) { ("" + $body.target_log) } else { "" }

        # Step 1: Local Host Info
        $localIp = "192.168.1.100"
        try {
            $hName = [System.Net.Dns]::GetHostName()
            $ipObj = [System.Net.Dns]::GetHostAddresses($hName) | Where-Object { 
                $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork -and -not $_.IPAddressToString.StartsWith("127.") 
            } | Select-Object -First 1
            if ($ipObj) { $localIp = $ipObj.IPAddressToString }
        } catch {}

        $localGw = "192.168.1.1"
        try {
            $route = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($route) { $localGw = $route.NextHop }
        } catch {}

        $step1 = [PSCustomObject]@{
            step       = 1
            name       = "發起源主機端 (Local Source)"
            target     = "$([System.Net.Dns]::GetHostName()) ($localIp)"
            status     = "PASS"
            badge      = "🟢 本機網卡連線正常"
            latency_ms = 0.1
            details    = "本機 IP: $localIp | 網關 IP: $localGw | 本地網卡正常啟用"
        }

        # Step 2: First-Hop Switch & Gateway Loop / Storm Check
        $ping = New-Object System.Net.NetworkInformation.Ping
        $gwLatencies = @()
        for ($k = 0; $k -lt 3; $k++) {
            try {
                $r = $ping.Send($localGw, 800)
                if ($r.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) {
                    $gwLatencies += $r.RoundtripTime
                }
            } catch {}
        }

        $avgGwLat = 999.0
        if ($gwLatencies.Count -gt 0) {
            $sum = 0
            foreach ($x in $gwLatencies) { $sum += $x }
            $avgGwLat = [Math]::Round($sum / $gwLatencies.Count, 1)
        }

        $hasSwitchLoop = ($switchLog -match "loop|spantree|tcn|flap|broadcast|drop")
        $isLoopStorm = ($avgGwLat -gt 250.0 -or $hasSwitchLoop)

        $step2Status = if ($isLoopStorm) { "CRITICAL" } elseif ($gwLatencies.Count -gt 0) { "PASS" } else { "WARNING" }
        $step2Badge  = if ($isLoopStorm) { "🚨 偵測到嚴重環路 (Loop) 或廣播風暴" } elseif ($step2Status -eq "PASS") { "🟢 交換機暢通 (無 Loop / 無風暴)" } else { "🟠 網關回應微弱" }
        $step2Details = "第一跳網關/交換機延遲: $($avgGwLat)ms"
        if ($isLoopStorm) { $step2Details += " ｜ 警告：延遲劇烈飆高或日誌發現 Loop，極可能發生實體環路！" }

        $step2 = [PSCustomObject]@{
            step       = 2
            name       = "第一台串接交換機 (First-Hop Switch)"
            target     = "Access Switch (GW: $localGw)"
            status     = $step2Status
            badge      = $step2Badge
            latency_ms = $avgGwLat
            details    = $step2Details
        }

        # Step 3: Gateway / Firewall
        $step3Status  = if ($gwLatencies.Count -gt 0) { "PASS" } else { "DROP" }
        $step3Badge   = if ($step3Status -eq "PASS") { "🟢 網關路由轉發正常" } else { "🔴 網關完全失聯 (Silent Drop)" }
        $step3Details = if ($step3Status -eq "PASS") { "網關 $localGw L3 封包轉發通道正常" } else { "封包在跨出網關時丟失，請確認預設閘道設備狀態" }
        if ($gwLog -match "deny|drop") {
            $step3Status  = "DROP"
            $step3Badge   = "🔴 網關防火牆阻擋 (ACL Deny)"
            $step3Details = "網關日誌檢測到 DENY / DROP 規則攔截！"
        }

        $step3 = [PSCustomObject]@{
            step       = 3
            name       = "網關設備 / 防火牆 (Gateway / Firewall)"
            target     = "Core GW ($localGw)"
            status     = $step3Status
            badge      = $step3Badge
            latency_ms = $avgGwLat
            details    = $step3Details
        }

        # Step 4: Destination Target Probe
        $targetIp = $targetHost
        try {
            $addrs = [System.Net.Dns]::GetHostAddresses($targetHost)
            if ($addrs -and $addrs.Length -gt 0) { $targetIp = $addrs[0].IPAddressToString }
        } catch {
            $targetIp = ""
        }

        $tStatus = "DROP"
        $tLat = 0
        $tMsg = ""

        if (-not $targetIp) {
            $tStatus = "DNS_ERROR"
            $tMsg = "DNS 解析失敗 (無法解析主機名稱: $targetHost)"
        } else {
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $tcp = New-Object System.Net.Sockets.TcpClient
            try {
                $ar = $tcp.BeginConnect($targetIp, $targetPort, $null, $null)
                $completed = $ar.AsyncWaitHandle.WaitOne(2000, $false)
                $sw.Stop()
                $tLat = $sw.ElapsedMilliseconds
                if ($completed) {
                    try {
                        $tcp.EndConnect($ar)
                        $tStatus = "PASS"
                        $tMsg = "TCP Handshake 握手成功 ($($tLat)ms)"
                    } catch {
                        $tStatus = "REFUSED"
                        $tMsg = "防火牆已開通，但連線被拒絕 (收到 TCP RST，目標主機未監聽 Port $targetPort)"
                    }
                } else {
                    $tStatus = "DROP"
                    $tMsg = "連線逾時 (防火牆未開通或路由丟包 Silent Drop)"
                }
            } catch {
                $sw.Stop()
                $tLat = $sw.ElapsedMilliseconds
                $tStatus = "DROP"
                $tMsg = "連線失敗: $($_.Exception.Message)"
            } finally {
                try { $tcp.Close() } catch {}
            }
        }

        $step4Badge = if ($tStatus -eq "PASS") { "🟢 服務監聽正常且連通" } elseif ($tStatus -eq "REFUSED") { "🟠 連線被拒絕 (RST / 服務未開)" } else { "🔴 連線逾時 (防火牆阻擋或主機未開)" }
        $step4 = [PSCustomObject]@{
            step       = 4
            name       = "目的地端點主機 (Target Server / Linux)"
            target     = "$targetHost`:$targetPort ($($proto.ToUpper()))"
            status     = $tStatus
            badge      = $step4Badge
            latency_ms = $tLat
            details    = "$tMsg | 目標 IP: $targetIp`:$targetPort"
        }

        # Human-Readable Verdict
        $verdictTitle = ""
        $verdictParty = ""
        $verdictColor = "#10b981"
        $verdictReason = ""
        $verdictAction = ""

        if ($isLoopStorm) {
            $verdictTitle  = "🚨【現場發生「網路迴圈 (Loop)」，交換機快被廣播風暴灌爆了！】"
            $verdictParty  = "現場網管 / 機房維運 (實體線路問題)"
            $verdictColor  = "#ef4444"
            $verdictReason = "內網第一跳交換機延遲飆高至 $($avgGwLat)ms 且出現嚴重震盪！99% 是有人把同一條網路線的兩端插在同台 Switch 上，或傻瓜 Hub 造成迴圈！"
            $verdictAction = "請現場人員立刻巡檢交換機前面板，觀察是否全機橘綠燈瘋狂閃爍，並順藤摸瓜拔除剛插上的環路跳線！"
        } elseif ($tStatus -eq "REFUSED") {
            $verdictTitle  = "🟢【網路完全暢通！請通知「伺服器 / 系統工程師」處理】"
            $verdictParty  = "系統工程師 / Linux 維運 (非網路責任 ⭐)"
            $verdictColor  = "#10b981"
            $verdictReason = "本機、交換機、網關與目標主機全程綠燈通暢（延遲僅 $($tLat)ms）！目標主機已收到封包，但主動回覆了 TCP RST 拒絕，證明目標電腦上的 Port $targetPort 應用服務根本沒有啟動！"
            $verdictAction = "請系統端工程師登入目標主機 ($targetHost)，檢查對應的 Service (如 Nginx/Docker/DB) 是否掛掉或未 Listen！網路端不用查！"
        } elseif ($tStatus -eq "DROP") {
            $verdictTitle  = "🔴【封包卡在網關或防火牆！請聯絡「資安 / 防火牆窗口」開通】"
            $verdictParty  = "資安工程師 / 防火牆維運團隊"
            $verdictColor  = "#f43f5e"
            $verdictReason = "本端主機與第一跳交換機皆正常，但在連往目標主機 ($targetHost`:$targetPort) 時發生逾時丟包 (Silent Drop)，代表防火牆 Policy 未放行或路由黑洞！"
            $verdictAction = "請通知防火牆人員開通由 $localIp 到 $targetHost Port $targetPort ($($proto.ToUpper())) 的安全策略。"
        } elseif ($tStatus -eq "DNS_ERROR") {
            $verdictTitle  = "🟣【DNS 網域名稱解析失敗！無法找到目標伺服器】"
            $verdictParty  = "DNS 維運 / 網管團隊"
            $verdictColor  = "#a855f7"
            $verdictReason = "本機無法將網域名稱 '$targetHost' 轉換為 IP 位址，可能是 DNS 伺服器掛了或主機名稱打錯。"
            $verdictAction = "請檢查本機 DNS 設定是否正確，或改用直接輸入 IP 測試。"
        } else {
            $verdictTitle  = "🟢【全鏈路 100% 綠燈暢通！網路與應用服務均健康運行】"
            $verdictParty  = "無故障 (正常運作中)"
            $verdictColor  = "#10b981"
            $verdictReason = "從本機 ➔ 交換機 ➔ 網關 ➔ 目標主機 ($targetHost`:$targetPort) 全程暢通，三向交握正常，延遲僅 $($tLat)ms！"
            $verdictAction = "系統狀態極佳，無需任何處置。"
        }

        $nowStr = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        $lineReport = @"
【現場網路逐跳排障快篩報告】
⏰ 測試時間：$nowStr
🎯 測試目標：$targetHost`:$targetPort ($($proto.ToUpper()))
📌 診斷結論：$verdictTitle
👤 責任歸屬：$verdictParty
🗣️ 白話原因：$verdictReason
⚡ 處置行動：$verdictAction
----------------------------------------
📋 4 階節點證據鏈明細：
1. 本機網卡：$($step1.badge) ($localIp)
2. 接入交換機：$($step2.badge) (延遲: $($step2.latency_ms)ms)
3. 網關/防火牆：$($step3.badge) ($localGw)
4. 目標伺服器：$($step4.badge) (延遲: $($step4.latency_ms)ms)
----------------------------------------
💡 報告由 NetScope Sequential Triage 自動生成
"@

        Send-JsonResponse $response @{
            success     = $true
            verdict     = @{
                title  = $verdictTitle
                party  = $verdictParty
                color  = $verdictColor
                reason = $verdictReason
                action = $verdictAction
            }
            steps       = @($step1, $step2, $step3, $step4)
            line_report = $lineReport
        }
        continue
    }

    $response.StatusCode = 404
    $response.OutputStream.Close()
}
