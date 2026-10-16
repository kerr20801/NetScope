# ==============================================================================
# ⬡ NetScope 本機仿真模擬測試伺服器 (Local Mock Lab Service)
# ==============================================================================
# 說明：
# 在沒有實體測試主機的環境下，可執行此腳本在本機啟動臨時監聽器：
# 1. TCP 8080 (模擬 Web / API 服務 - 回應 HTTP 200 OK)
# 2. UDP 5353 (模擬 UDP 服務 - 回傳 Echo 回應)
#
# 您可以在 NetScope 的主動連通矩陣輸入：
# 127.0.0.1, 8080, 本機 Mock Web 服務, 本機測試, tcp
# 127.0.0.1, 5353, 本機 Mock UDP 服務, 本機測試, udp
# 即可直接在本機體驗 100% 真實通暢之非同步並發探測！
# ==============================================================================

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " ⬡ NetScope Local Mock Lab Service Starting..." -ForegroundColor Green
Write-Host " Listening on:" -ForegroundColor Yellow
Write-Host "   - TCP 127.0.0.1:8080 (Mock Web/API)" -ForegroundColor White
Write-Host "   - UDP 127.0.0.1:5353 (Mock UDP Echo)" -ForegroundColor White
Write-Host " Press Ctrl + C to stop." -ForegroundColor Gray
Write-Host "==========================================================" -ForegroundColor Cyan

# Start TCP Listener
$tcpListener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 8080)
$tcpListener.Start()

# Start UDP Listener
$udpListener = New-Object System.Net.Sockets.UdpClient(5353)

$running = $true

# Register Ctrl+C handler
[Console]::CancelKeyPress += {
    $script:running = $false
    try { $tcpListener.Stop() } catch {}
    try { $udpListener.Close() } catch {}
}

Write-Host "[READY] Waiting for NetScope probes..." -ForegroundColor Green

while ($running) {
    # Check TCP
    if ($tcpListener.Pending()) {
        try {
            $client = $tcpListener.AcceptTcpClient()
            $stream = $client.GetStream()
            $ep = $client.Client.RemoteEndPoint.ToString()
            Write-Host "[$(Get-Date -Format 'HH:mm:ss.fff')] [TCP:8080] Connection accepted from $ep (Handshake SUCCESS)" -ForegroundColor Green
            
            $responseBytes = [System.Text.Encoding]::ASCII.GetBytes("HTTP/1.1 200 OK`r`nContent-Length: 2`r`n`r`nOK")
            $stream.Write($responseBytes, 0, $responseBytes.Length)
            $client.Close()
        } catch {}
    }

    # Check UDP
    if ($udpListener.Available -gt 0) {
        try {
            $remoteEp = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
            $bytes = $udpListener.Receive([ref]$remoteEp)
            Write-Host "[$(Get-Date -Format 'HH:mm:ss.fff')] [UDP:5353] Received $($bytes.Length) bytes from $($remoteEp.ToString()), echoing back..." -ForegroundColor Cyan
            $udpListener.Send($bytes, $bytes.Length, $remoteEp) | Out-Null
        } catch {}
    }

    Start-Sleep -Milliseconds 20
}

Write-Host "Mock service stopped." -ForegroundColor Yellow
