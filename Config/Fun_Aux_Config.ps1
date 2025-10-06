
function Test-HttpService {
    param(
        [string]$TargetHost,
        [int]$Port,
        [int]$Timeout = 5000
    )
    
    try {
        $SSLPorts = @(443, 8443, 9443, 8444, 9444)
        $UseSSL = $Port -in $SSLPorts
        
        $WebPorts = @(80, 443, 8080, 8443, 8888, 9080, 9090, 8000, 3000, 5000, 7443, 9443)
        
        if ($Port -in $WebPorts) {
            # PRIMEIRO: Tenta WebRequest (HEAD) - Mais rápido e limpo
            $headBanner = Invoke-WebRequestMethod -TargetHost $TargetHost -Port $Port -Timeout $Timeout -Method "HEAD" -UseSSL $UseSSL
            
            # SEGUNDO: Se HEAD não retornou Server header, tenta GET
            if ($headBanner -and -not $headBanner.Contains("Server:")) {
                $getBanner = Invoke-WebRequestMethod -TargetHost $TargetHost -Port $Port -Timeout $Timeout -Method "GET" -UseSSL $UseSSL
                if ($getBanner -and $getBanner.Contains("Server:")) {
                    return $getBanner
                }
            }
            
            # TERCEIRO: Se WebRequest falhou, tenta Socket
            if (-not $headBanner) {
                $socketBanner = Get-HttpViaSocket -TargetHost $TargetHost -Port $Port -Timeout $Timeout -UseSSL $UseSSL
                return $socketBanner
            }
            
            return $headBanner
        }
        else {
            return $null
        }
    }
    catch {
        return $null
    }
}

# === Função auxiliar da auxiliar para Test-HttpService via socket ===
function Invoke-WebRequestMethod {
    param(
        [string]$TargetHost,
        [int]$Port,
        [int]$Timeout,
        [string]$Method,
        [bool]$UseSSL
    )
    
    try {
        $uri = if ($UseSSL) { "https://${TargetHost}:${Port}/" } else { "http://${TargetHost}:${Port}/" }
        $request = [System.Net.WebRequest]::Create($uri)
        $request.Timeout = $Timeout
        $request.Method = $Method
        
        $UserAgents = @(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0"
        )
        $randomUserAgent = $UserAgents | Get-Random
        $request.UserAgent = $randomUserAgent
        
        $request.Headers.Add("Accept-Language", "en-US,en;q=0.9")
        $request.Headers.Add("Accept-Encoding", "gzip, deflate")
        $request.Headers.Add("DNT", "1")
        $request.Headers.Add("Connection", "close")
        
        $request.Accept = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8"
        
        try {
            $response = $request.GetResponse()
            $serverHeader = $response.Headers["Server"]
            $poweredBy = $response.Headers["X-Powered-By"]
            $statusCode = [int]$response.StatusCode
            
            $bannerInfo = "HTTP/$($response.ProtocolVersion) $statusCode $($response.StatusDescription)"
            if ($serverHeader) { $bannerInfo += " | Server: $serverHeader" }
            if ($poweredBy) { $bannerInfo += " | X-Powered-By: $poweredBy" }
            
            $response.Close()
            return $bannerInfo
        }
        catch [System.Net.WebException] {
            $response = $_.Exception.Response
            if ($response) {
                $statusCode = [int]$response.StatusCode
                $serverHeader = $response.Headers["Server"]
                $bannerInfo = "HTTP/1.1 $statusCode"
                if ($serverHeader) { $bannerInfo += " | Server: $serverHeader" }
                return $bannerInfo
            }
            return $null
        }
    }
    catch {
        return $null
    }
}

function Get-HttpViaSocket {
    param(
        [string]$TargetHost,
        [int]$Port,
        [int]$Timeout,
        [bool]$UseSSL
    )
    
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $client.ReceiveTimeout = $Timeout
        $client.SendTimeout = $Timeout
        
        $connectTask = $client.ConnectAsync($TargetHost, $Port)
        if ($connectTask.Wait($Timeout)) {
            if ($client.Connected) {
                $stream = $client.GetStream()
                
                $headRequest = @"
HEAD / HTTP/1.1`r`n
Host: $TargetHost`r`n
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36`r`n
Accept: */*`r`n
Connection: close`r`n
`r`n
"@
                $headData = [System.Text.Encoding]::ASCII.GetBytes($headRequest)
                $stream.Write($headData, 0, $headData.Length)
                $stream.Flush()
                
                $headResponse = Read-StreamResponse -Stream $stream -Timeout $Timeout
                
                if (-not $headResponse -or -not $headResponse.Contains("Server:")) {
                    $getRequest = @"
GET / HTTP/1.1`r`n
Host: $TargetHost`r`n
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36`r`n
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8`r`n
Connection: close`r`n
`r`n
"@
                    $getData = [System.Text.Encoding]::ASCII.GetBytes($getRequest)
                    $stream.Write($getData, 0, $getData.Length)
                    $stream.Flush()
                    
                    $getResponse = Read-StreamResponse -Stream $stream -Timeout $Timeout
                    if ($getResponse) {
                        $headResponse = $getResponse
                    }
                }
                
                try {
                    $stream.Close()
                    $client.Close()
                }
                catch {
                    # Ignora erros de fechamento
                }
                
                if ($headResponse -match "HTTP/(\d\.\d)\s*(\d+)\s*([^\r\n]+)") {
                    $version = $matches[1]
                    $statusCode = $matches[2]
                    $statusText = $matches[3].Trim()
                    
                    $bannerInfo = "HTTP/$version $statusCode $statusText"
                    
                    if ($headResponse -match "Server:\s*([^\r\n]+)") {
                        $server = $matches[1].Trim()
                        $bannerInfo += " | Server: $server"
                    }
                    if ($headResponse -match "X-Powered-By:\s*([^\r\n]+)") {
                        $poweredBy = $matches[1].Trim()
                        $bannerInfo += " | X-Powered-By: $poweredBy"
                    }
                    
                    return $bannerInfo
                }
                
                return $headResponse.Trim()
            }
        }
        try { $client.Close() } catch { }
        return $null
    }
    catch {
        try { $client.Close() } catch { }
        return $null
    }
}

function Read-StreamResponse {
    param(
        [System.Net.Sockets.NetworkStream]$Stream,
        [int]$Timeout
    )
    
    try {
        $readBuffer = New-Object Byte[] 4096
        $responseBuilder = New-Object System.Text.StringBuilder
        $startTime = Get-Date
        
        do {
            if ($Stream.DataAvailable) {
                try {
                    $read = $Stream.Read($readBuffer, 0, 4096)
                    if ($read -gt 0) {
                        $chunk = [System.Text.Encoding]::ASCII.GetString($readBuffer, 0, $read)
                        [void]$responseBuilder.Append($chunk)
                    }
                }
                catch {
                    break
                }
            }
            Start-Sleep -Milliseconds 100
        } while ($Stream.DataAvailable -and ((Get-Date) - $startTime).TotalMilliseconds -lt $Timeout)
        
        return $responseBuilder.ToString()
    }
    catch {
        return ""
    }
}

#--- Funções auxiliares para requisições web e validação de URL ===
function Test-ValidUrl {
    param ([string]$url)
    try {
        $uri = [System.Uri]$url
        return ($uri.Scheme -eq 'http' -or $uri.Scheme -eq 'https')
    } catch {
        return $false
    }
}

function Invoke-WebRequestSafe {
    param ([string]$Uri, [string]$Method = 'Get', [int]$Timeout = 30)
    
    return Invoke-WebRequest -Uri $Uri -Method $Method -Headers $headers -ErrorAction Stop -TimeoutSec $Timeout
}

function Handle-WebError {
    param ($ErrorObject)
    if ($ErrorObject.Exception.Response.StatusCode.value__) {
        $statusCode = $ErrorObject.Exception.Response.StatusCode.value__
        Write-Host "`nErro HTTP: $statusCode" -ForegroundColor Red
        Write-Log "Erro HTTP: $statusCode" "ERROR"
    } else {
        Write-Host "`nErro: $($ErrorObject.Exception.Message)" -ForegroundColor Red
        Write-Log "Erro: $($ErrorObject.Exception.Message)" "ERROR"
    }
}

function Write-Log {
    param ([string]$message, [string]$level = "INFO")
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$level] $message"
    
    $logDir = "Logs"
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }
    
    $logFilePath = Join-Path $logDir $logFile
    
    Add-Content -Path $logFilePath -Value $logMessage
}