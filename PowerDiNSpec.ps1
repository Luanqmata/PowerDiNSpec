<#
===============================================================================
PowerDiNSpec - PowerShell DNS Recon Tool
===============================================================================

Copyright (C) 2025 Luan Calazans

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as 
published by the Free Software Foundation, either version 3 of 
the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.

===============================================================================
#>

function Logo_Menu {
    $ascii = @"
    
                                                                                   _                        _
                                       _  _      ,/\/\                            ( ) ___,      _ __    _  ( ) _ __                  ___
                                     _| || |_    | '_ \  ___//__      __ ___  _ __ \||  _'\  _ | '_ \  | | |/ | '_ \  /\/\   ___    |__ \
                                    |_  ..  _|   | |_) |/ _//\\ \ /\ / // _ \| '__|  | | | || || | | |/ __|   | |_) |/  _ \ / __|     / /
                                    |_      _|   | .__/| (//) |\ V  V /|  __/| |     | |_/ || || | | |\__ \   | .__/|  ___/| (__     |_|
                                      |_||_|     |_|    \//__/  \_/\_/  \___||_|     |____/ |_||_| |_||___/   |_|    \____| \___|
                                                        //               | |                (_)        |_|                           (_)           2.4.3v

                                         
"@ -split "`n"

    foreach ($line in $ascii) {
        Write-Host $line -ForegroundColor Red
    }
}

# =============================================
# VARIÁVEIS GLOBAIS E CONFIGURAÇÕES
# =============================================
$global:PortsForBannerScan = @(21,22,80,443,3306,5432,8080)
$global:AutoFuzzingMode = 0
#fuzzing settings
$global:FuzzingMaxDepth = 2
$global:FuzzingTimeoutMs = 3000
$global:FuzzingMaxThreads = 5
$global:FuzzingAggressive = $false
$global:FuzzingSubdomain = $false
$global:FuzzingStatusCodes = @(200, 301, 302, 403, 500)

$global:AllScans = @(
    @{ Name = "HTTP Status Code";       Enabled = 1; Function = { param($url) ScanStatusCode -url $url } },
    @{ Name = "Page Title";             Enabled = 1; Function = { param($url) ScanTitle -url $url } },
    @{ Name = "IP Address from DNS";    Enabled = 1; Function = { param($url) Get-ip-from-url -url $url } },
    @{ Name = "Allowed HTTP Methods";   Enabled = 1; Function = { param($url) ScanOptions -url $url } },
    @{ Name = "Server Headers";         Enabled = 1; Function = { param($url) ScanHeaders -url $url } },
    @{ Name = "Technologies in Use";    Enabled = 1; Function = { param($url) ScanTech -url $url } },
    @{ Name = "Security Headers Check"; Enabled = 0; Function = { param($url) Test-SecurityHeaders -url $url } },
    @{ Name = "DNS Zone Transfer Test"; Enabled = 0; Function = { param($url) Test-DNSZoneTransfer -url $url } },
    @{ Name = "Check DNS Records";      Enabled = 0; Function = { param($url) Get-DNSRecords -url $url } },
    @{ Name = "Links in HTML";          Enabled = 1; Function = { param($url) ScanLinks -url $url } },
    @{ Name = "Robots.txt";             Enabled = 1; Function = { param($url) ScanRobotsTxt -url $url } },
    @{ Name = "Sitemap.xml";            Enabled = 1; Function = { param($url) ScanSitemap -url $url } },
    @{ Name = "Port Banner Grabbing";   Enabled = 0; Function = { param($url) Get-PortBanner -url $url } },
    @{ Name = "Words for Fuzzing";      Enabled = 0; Function = { param($url) ScanHTML -url $url } }
)

# Se a variável global ScansConfig não existir, inicializa com os scans habilitados por padrão
if (-not (Get-Variable -Name "ScansConfig" -Scope Global -ErrorAction SilentlyContinue)) {
    $global:ScansConfig = $global:AllScans | Where-Object { $_.Enabled -eq 1 }
}

# Configuração atual dos scans habilitados
$global:ScansConfig = $global:AllScans | Where-Object { $_.Enabled -eq 1 }

function Show-InputPrompt {
    param(
        [string]$User = $env:USERNAME,
        [string]$input_name = "",
        [int]$PaddingLeft = 0,
        [ConsoleColor]$QuestionColor = [ConsoleColor]::White
    )
    
    $version = [System.Environment]::OSVersion.Version.ToString()
    $pad = " " * $PaddingLeft
    
    Write-Host "`n`n$pad" -NoNewline
    Write-Host " //~--~( " -NoNewline -ForegroundColor Red
    Write-Host "$User" -NoNewline -ForegroundColor Gray
    Write-Host "@Win_Version=" -NoNewline -ForegroundColor Cyan
    Write-Host "/$version/" -NoNewline -ForegroundColor Yellow
    Write-Host " )-[" -NoNewline -ForegroundColor Red
    Write-Host "~" -NoNewline -ForegroundColor White
    Write-Host "]--[" -NoNewline -ForegroundColor Red
    Write-Host "#" -NoNewline -ForegroundColor White
    Write-Host "]---> " -NoNewline -ForegroundColor Red

    Write-Host "$input_name" -ForegroundColor $QuestionColor

    Write-Host "$pad" -NoNewline
    Write-Host "/__~----~" -NoNewline -ForegroundColor Red
    Write-Host " > " -NoNewline -ForegroundColor Red
    Write-Host "@: " -NoNewline -ForegroundColor White

    $origColor = [Console]::ForegroundColor
    [Console]::ForegroundColor = "Magenta"
    $option = Read-Host
    [Console]::ForegroundColor = $origColor
    
    return $option
}

# =============================================
# FUNÇÕES AUXILIARES / Port banner grab / fuzz
# =============================================
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
            #  CORREÇÃO: URI CORRETA COM HOST HEADER
            $uri = if ($UseSSL) { "https://${TargetHost}:${Port}/" } else { "http://${TargetHost}:${Port}/" }
            
            try {
                $request = [System.Net.WebRequest]::Create($uri)
                $request.Timeout = $Timeout
                $request.Method = "HEAD"
                
                #  HEADERS COMPATÍVEIS
                $request.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                $request.Accept = "*/*"
                
                #  HOST HEADER CORRETO - EVITA HTTP 400
                $request.Host = $TargetHost
                
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
            catch {
                return $null
            }
        }
        else {
            return $null
        }
    }
    catch {
        return $null
    }
}
# === Funçoes auxiliar das auxiliares para Test-HttpService via socket etc ===
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
                
                #  CORREÇÃO: HEADER HOST CORRETO - EVITA HTTP 400
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
                        #  CORREÇÃO: SINTAXE CORRETA DO IF
                        $cleanChunk = ""
                        for ($i = 0; $i -lt $read; $i++) {
                            $byte = $readBuffer[$i]
                            # Mantém apenas caracteres ASCII imprimíveis (32-126) e quebras de linha
                            if (($byte -ge 32 -and $byte -le 126) -or $byte -eq 10 -or $byte -eq 13) {
                                $cleanChunk += [char]$byte
                            } else {
                                $cleanChunk += "?"  # Substitui caracteres inválidos
                            }
                        }
                        [void]$responseBuilder.Append($cleanChunk)
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

function Get-EstimatedTime {
    param($scans)
    
    $baseTimePerScan = 3
    $portScanTime = if ($global:ScansConfig.Name -contains "Port Banner Grabbing") {
        [math]::Round(($global:PortsForBannerScan.Count * 2) / 60, 1)
    } else { 0 }
    
    $webRequestTime = $scans.Count * $baseTimePerScan
    $totalSeconds = $webRequestTime + ($portScanTime * 60)
    
    $minutes = [math]::Max(0.5, [math]::Round($totalSeconds / 60, 1))
    
    return $minutes
}

# =============================================
# FUNÇÕES AUXILIARES / Validate-scans
# =============================================

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
    
    # CORREÇÃO: Usar headers globais
    return Invoke-WebRequest -Uri $Uri -Method $Method -Headers $global:headers -ErrorAction Stop -TimeoutSec $Timeout
}

function Write-ErrorWeb {
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
    
    $logDir = "Logs_PowerDns"
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }
    
    $logFileName = "scan_log_$(Get-Date -Format 'yyyyMMdd').txt"
    $logFilePath = Join-Path $logDir $logFileName
    
    Add-Content -Path $logFilePath -Value $logMessage
}

# =============================================
# FUNÇÕES DE SCAN HTTP/WEB
# =============================================
function ScanStatusCode {
    param ([String]$url)
    try {
        Write-Host "`n Obtaining HTTP status code..." -ForegroundColor Yellow
        Write-Log "Starting ScanStatusCode for: $url"
        
        $response = Invoke-WebRequestSafe -Uri $url
        $statusCode = $response.StatusCode
        $statusDescription = $response.StatusDescription
        
        Write-Host "`nStatus Code:" -ForegroundColor Green
        Write-Host "  $statusCode $statusDescription" -ForegroundColor White
        
        $color = switch ($statusCode) {
            { $_ -ge 200 -and $_ -lt 300 } { "Green"; break }
            { $_ -ge 300 -and $_ -lt 400 } { "Yellow"; break }
            { $_ -ge 400 -and $_ -lt 500 } { "Red"; break }
            { $_ -ge 500 } { "DarkRed"; break }
            default { "White" }
        }
        
        Write-Host "Category: $(Get-HTTPStatusCategory -StatusCode $statusCode)" -ForegroundColor $color
        Write-Log "Status Code: $statusCode $statusDescription"
        
    } catch {
        Write-ErrorWeb -ErrorObject $_
    }
}

function Get-HTTPStatusCategory {
    param([int]$StatusCode)
    switch ($StatusCode) {
        { $_ -ge 100 -and $_ -lt 200 } { return "Informational" }
        { $_ -ge 200 -and $_ -lt 300 } { return "Success" }
        { $_ -ge 300 -and $_ -lt 400 } { return "Redirection" }
        { $_ -ge 400 -and $_ -lt 500 } { return "Client Error" }
        { $_ -ge 500 } { return "Server Error" }
        default { return "Unknown" }
    }
}

function ScanTitle {
    param ([string]$url)
    try {
        Write-Host "`n Obtaining page title..." -ForegroundColor Yellow
        Write-Log "Starting ScanTitle for: $url"
        
        $response = Invoke-WebRequestSafe -Uri $url
        if ($response -and $response.ParsedHtml -and $response.ParsedHtml.title) {
            $title = $response.ParsedHtml.title.Trim()
            Write-Host "`nPage title:" -ForegroundColor Green
            Write-Host "  $title" -ForegroundColor White
            Write-Log "Page title: $title"
            
            Write-Host "`nTitle Analysis:" -ForegroundColor Cyan
            Write-Host "  Length: $($title.Length) characters" -ForegroundColor Gray
        } else {
            Write-Host "`nNo title found or title is empty." -ForegroundColor Red
            Write-Log "No title found for: $url" "WARNING"
        }
    } catch {
        Write-ErrorWeb -ErrorObject $_
    }
}

function ScanOptions {
    param ([string]$url)
    try {
        Write-Host "`n Checking supported HTTP methods..." -ForegroundColor Yellow
        Write-Log "Starting ScanOptions for: $url"

        $response = Invoke-WebRequestSafe -Uri $url -Method Options
        
        Write-Host "`nHTTP Methods Analysis:" -ForegroundColor Green
        
        if ($response.Headers.Allow) {
            $methods = $response.Headers.Allow -split ', ' | Sort-Object
            Write-Host "  $($methods -join ', ')" -ForegroundColor White
            
            $riskyMethods = @('PUT', 'DELETE', 'TRACE', 'CONNECT')
            $foundRisky = $methods | Where-Object { $riskyMethods -contains $_ }
            
            if ($foundRisky) {
                Write-Host "`n  Risky Methods Found: $($foundRisky -join ', ')" -ForegroundColor Red
                Write-Log "Risky HTTP methods detected: $($foundRisky -join ', ')" "WARNING"
            }
            
            Write-Log "Allowed methods: $($response.Headers.Allow)"
        } else {
            Write-Host "  No Allow header found in response." -ForegroundColor Yellow
        }

        $relevantHeaders = @('Access-Control-Allow-Methods', 'Access-Control-Allow-Origin', 'Access-Control-Allow-Headers')
        foreach ($header in $relevantHeaders) {
            if ($response.Headers[$header]) {
                Write-Host "  $header : $($response.Headers[$header])" -ForegroundColor Cyan
            }
        }
        
    } catch {
        Write-ErrorWeb -ErrorObject $_
    }
}

function ScanHeaders {
    param ([string]$url)
    try {
        Write-Host "`n Scanning Server Headers..." -ForegroundColor Yellow
        Write-Log "Starting ScanHeaders for: $url"

        $response = Invoke-WebRequestSafe -Uri $url -Method Head
        
        Write-Host "`nServer Information:" -ForegroundColor Green
        
        if ($response.Headers.Server) {
            $serverInfo = $response.Headers.Server
            Write-Host "  Server: $serverInfo" -ForegroundColor White
            
            if ($serverInfo -match 'Apache') {
                Write-Host "  Type: Apache Web Server" -ForegroundColor Cyan
            } elseif ($serverInfo -match 'nginx') {
                Write-Host "  Type: Nginx Web Server" -ForegroundColor Cyan
            } elseif ($serverInfo -match 'IIS') {
                Write-Host "  Type: Microsoft IIS" -ForegroundColor Cyan
            }
            
            Write-Log "Server header: $serverInfo"
        } else {
            Write-Host "  Server header not found or hidden." -ForegroundColor Yellow
        }
        
        $importantHeaders = @{
            'X-Powered-By' = 'Application Framework'
            'X-AspNet-Version' = 'ASP.NET Version'
            'X-AspNetMvc-Version' = 'ASP.NET MVC Version'
            'X-Runtime' = 'Runtime Environment'
        }
        
        foreach ($header in $importantHeaders.GetEnumerator()) {
            if ($response.Headers[$header.Key]) {
                Write-Host "  $($header.Value): $($response.Headers[$header.Key])" -ForegroundColor White
            }
        }
        
    } catch {
        Write-ErrorWeb -ErrorObject $_
    }
}

function ScanTech {
    param ([string]$url)
    try {
        Write-Host "`n Detecting technologies in use..." -ForegroundColor Yellow
        Write-Log "Starting ScanTech for: $url"

        $response = Invoke-WebRequestSafe -Uri $url
        $technologies = @()
        
        Write-Host "`nDetected Technologies:" -ForegroundColor Green

        $techHeaders = @(
            @{Header = "x-powered-by"; Name = "Backend Framework"},
            @{Header = "x-aspnet-version"; Name = "ASP.NET Version"}, 
            @{Header = "x-aspnetmvc-version"; Name = "ASP.NET MVC Version"},
            @{Header = "x-generator"; Name = "CMS/Generator"},
            @{Header = "x-drupal-cache"; Name = "Drupal"},
            @{Header = "x-joomla"; Name = "Joomla"},
            @{Header = "wp-super-cache"; Name = "WordPress Cache"}
        )

        foreach ($tech in $techHeaders) {
            if ($response.Headers[$tech.Header]) {
                $value = $response.Headers[$tech.Header]
                Write-Host "  $($tech.Name): $value" -ForegroundColor White
                $technologies += "$($tech.Name): $value"
                Write-Log "Technology detected ($($tech.Name)): $value"
            }
        }

        # Content-based detection
        if ($response.Content -match "wp-content|wp-includes") {
            Write-Host "  CMS: WordPress (detected from content)" -ForegroundColor White
            $technologies += "WordPress"
        }

        if ($response.Content -match "_wpnonce|woocommerce") {
            Write-Host "  Plugin: WooCommerce" -ForegroundColor White
            $technologies += "WooCommerce"
        }

        if ($response.Content -match "react|react-dom") {
            Write-Host "  Frontend: React" -ForegroundColor White
            $technologies += "React"
        }

        if ($response.Content -match "jquery") {
            Write-Host "  JavaScript: jQuery" -ForegroundColor White
            $technologies += "jQuery"
        }

        if ($technologies.Count -eq 0) {
            Write-Host "  No specific technologies detected in headers or content." -ForegroundColor Yellow
            Write-Host "  Note: Many modern frameworks hide their fingerprints." -ForegroundColor Gray
        } else {
            Write-Host "`n  Total technologies found: $($technologies.Count)" -ForegroundColor DarkGreen
        }

    } catch {
        Write-ErrorWeb -ErrorObject $_
    }
}

function Test-SecurityHeaders {
    param([string]$url)
    
    try {
        Write-Host "`n Checking Security Headers..." -ForegroundColor Yellow
        Write-Log "Starting Security Headers check for: $url"
        
        $securityHeaders = @(
            @{Name = 'Strict-Transport-Security'; Importance = 'High'; Description = 'Enforces HTTPS connections'},
            @{Name = 'Content-Security-Policy'; Importance = 'High'; Description = 'Prevents XSS attacks'}, 
            @{Name = 'X-Frame-Options'; Importance = 'Medium'; Description = 'Prevents clickjacking'},
            @{Name = 'X-Content-Type-Options'; Importance = 'Medium'; Description = 'Prevents MIME sniffing'},
            @{Name = 'X-XSS-Protection'; Importance = 'Low'; Description = 'Legacy XSS protection'},
            @{Name = 'Referrer-Policy'; Importance = 'Medium'; Description = 'Controls referrer information'},
            @{Name = 'Permissions-Policy'; Importance = 'Medium'; Description = 'Controls browser features'},
            @{Name = 'X-Permitted-Cross-Domain-Policies'; Importance = 'Low'; Description = 'Flash cross-domain policy'}
        )
        
        $response = Invoke-WebRequest -Uri $url -Method Head -TimeoutSec 10 -Headers $headers
        
        $foundHeaders = 0
        $missingCritical = @()
        
        foreach ($header in $securityHeaders) {
            if ($response.Headers[$header.Name]) {
                $color = if ($header.Importance -eq 'High') { "Green" } else { "Cyan" }
                Write-Host "  [PRESENT] $($header.Name)" -ForegroundColor $color
                Write-Host "    Value: $($response.Headers[$header.Name])" -ForegroundColor White
                Write-Host "    Purpose: $($header.Description)" -ForegroundColor Gray
                $foundHeaders++
                Write-Log "Security Header found: $($header.Name) = $($response.Headers[$header.Name])"
            } else {
                $color = if ($header.Importance -eq 'High') { "Red" } else { "Yellow" }
                Write-Host "  [MISSING] $($header.Name)" -ForegroundColor $color
                Write-Host "    Importance: $($header.Importance)" -ForegroundColor Gray
                Write-Host "    Purpose: $($header.Description)" -ForegroundColor Gray
                
                if ($header.Importance -eq 'High') {
                    $missingCritical += $header.Name
                }
                
                Write-Log "Security Header missing: $($header.Name)" "WARNING"
            }
            Write-Host ""
        }
        
        # Security rating
        $securityScore = [math]::Round(($foundHeaders / $securityHeaders.Count) * 100, 1)
        Write-Host "  Security Headers Score: $securityScore%" -ForegroundColor $(if ($securityScore -ge 70) { "Green" } elseif ($securityScore -ge 40) { "Yellow" } else { "Red" })
        Write-Host "  Found: $foundHeaders/$($securityHeaders.Count) security headers" -ForegroundColor White
        
        if ($missingCritical.Count -gt 0) {
            Write-Host "`n  Critical headers missing: $($missingCritical -join ', ')" -ForegroundColor Red
        }
        
        Write-Log "Security Headers check completed: $foundHeaders headers found, Score: $securityScore%"
        
    }
    catch {
        Write-Host "  Failed to check security headers: $($_.Exception.Message)" -ForegroundColor Red
        Write-Log "Security Headers check failed: $($_.Exception.Message)" "ERROR"
    }
}

function ScanLinks {
    param ([string]$url)
    try {
        Write-Host "`n Searching for links on the page..." -ForegroundColor Yellow
        Write-Log "Starting ScanLinks for: $url"

        $response = Invoke-WebRequestSafe -Uri $url
        Write-Host "`n Links found:" -ForegroundColor Green
        $links = $response.Links.Href | Where-Object { $_ -match '^http' } | Select-Object -Unique
        if ($links) {
            $links | ForEach-Object {
                Write-Host "   $_" -ForegroundColor White
            }
            Write-Log "Found $($links.Count) unique links"
        } else {
            Write-Host "No HTTP links found." -ForegroundColor Red
        }
    } catch {
        Write-ErrorWeb -ErrorObject $_
    }
}
function ScanRobotsTxt {
    param ([string]$url)
    try {
        Write-Host "`n Looking for robots.txt..." -ForegroundColor Yellow
        Write-Log "Starting ScanRobotsTxt for: $url"
        
        $robotsUrl = "$url/robots.txt"
        $response = Invoke-WebRequestSafe -Uri $robotsUrl
        
        # CORREÇÃO: DEFINIR $content ANTES DE USAR
        $content = $response.Content.Trim()
        $lines = $content -split "`n" | Where-Object { $_.Trim() -ne '' }

        # VERIFICAÇÃO DE CONTEÚDO VÁLIDO
        if ([string]::IsNullOrWhiteSpace($content) -or $lines.Count -eq 0) {
            Write-Host "`n  robots.txt found but appears to be empty or malformed." -ForegroundColor Yellow
            Write-Host "  Raw content:" -ForegroundColor Cyan
            Write-Host $content -ForegroundColor Gray
            Write-Log "Robots.txt is empty or malformed" "WARNING"
            return
        }

        Write-Host "`n  robots.txt FOUND AND ANALYZED" -ForegroundColor Green
        
        # EXTRAÇÃO ROBUSTA COM VERIFICAÇÕES
        $userAgents = @()
        $disallowed = @()
        $allowed = @()
        $sitemaps = @()
        $crawlDelays = @()

        foreach ($line in $lines) {
            $trimmedLine = $line.Trim()
            
            if ($trimmedLine -match '^User-agent:\s*(.+)') {
                $userAgents += $matches[1].Trim()
            }
            elseif ($trimmedLine -match '^Disallow:\s*(.+)') {
                $disallowed += $matches[1].Trim()
            }
            elseif ($trimmedLine -match '^Allow:\s*(.+)') {
                $allowed += $matches[1].Trim()
            }
            elseif ($trimmedLine -match '^Sitemap:\s*(.+)') {
                $sitemaps += $matches[1].Trim()
            }
            elseif ($trimmedLine -match '^Crawl-delay:\s*(.+)') {
                $crawlDelays += $matches[1].Trim()
            }
        }

        # ANÁLISE DE USER AGENTS
        if ($userAgents.Count -gt 0) {
            Write-Host "`nUSER AGENTS TARGETED ($($userAgents.Count)):" -ForegroundColor Cyan
            $userAgents | ForEach-Object {
                if (-not [string]::IsNullOrWhiteSpace($_)) {
                    Write-Host "  - $_" -ForegroundColor White
                }
            }
        } else {
            Write-Host "`nUSER AGENTS: No specific user agents defined (applies to all crawlers)" -ForegroundColor Yellow
        }

        # ANÁLISE DE PATHS DISALLOWED
        if ($disallowed.Count -gt 0) {
            Write-Host "`nDISALLOWED PATHS ($($disallowed.Count)):" -ForegroundColor Red
            $disallowed | ForEach-Object {
                if ([string]::IsNullOrWhiteSpace($_)) {
                    Write-Host "  - (Empty - allows all)" -ForegroundColor Green
                } else {
                    Write-Host "  - $_" -ForegroundColor Yellow
                }
            }

            # DETECÇÃO DE PATHS SENSÍVEIS
            $sensitivePaths = $disallowed | Where-Object { 
                -not [string]::IsNullOrWhiteSpace($_) -and 
                $_ -match '(admin|login|config|setup|debug|backup|sql|database|\.env|\.git|wp-|phpmyadmin|cpanel|\.bak|\.old|\.tmp|password|secret|private)'
            }
            
            if ($sensitivePaths.Count -gt 0) {
                Write-Host "`nSENSITIVE PATHS FOUND ($($sensitivePaths.Count)):" -ForegroundColor Red
                $sensitivePaths | ForEach-Object {
                    Write-Host "  [!] $_" -ForegroundColor Red
                }
                
                # SCORE DE SEGURANÇA
                $securityScore = 100 - ($sensitivePaths.Count * 10)
                if ($securityScore -lt 0) { $securityScore = 0 }
                
                Write-Host "`n  SECURITY ASSESSMENT:" -ForegroundColor $(if ($securityScore -ge 70) { "Green" } elseif ($securityScore -ge 40) { "Yellow" } else { "Red" })
                Write-Host "    Score: $securityScore/100" -ForegroundColor White
                Write-Host "    Warning: $($sensitivePaths.Count) sensitive paths exposed" -ForegroundColor $(if ($sensitivePaths.Count -gt 3) { "Red" } else { "Yellow" })
            }
        } else {
            Write-Host "`nDISALLOWED PATHS: None found (all paths are accessible to crawlers)" -ForegroundColor Green
        }

        # ANÁLISE DE PATHS ALLOWED
        if ($allowed.Count -gt 0) {
            Write-Host "`nALLOWED PATHS ($($allowed.Count)):" -ForegroundColor Green
            $allowed | ForEach-Object {
                if (-not [string]::IsNullOrWhiteSpace($_)) {
                    Write-Host "  - $_" -ForegroundColor White
                }
            }
        }
        
        # SITEMAP REFERENCES
        if ($sitemaps.Count -gt 0) {
            Write-Host "`nSITEMAP REFERENCES ($($sitemaps.Count)):" -ForegroundColor Magenta
            $sitemaps | ForEach-Object {
                if (-not [string]::IsNullOrWhiteSpace($_)) {
                    Write-Host "  - $_" -ForegroundColor White
                }
            }
        }
        
        # CRAWL DELAYS
        if ($crawlDelays.Count -gt 0) {
            Write-Host "`nCRAWL DELAYS:" -ForegroundColor Yellow
            $crawlDelays | ForEach-Object {
                if (-not [string]::IsNullOrWhiteSpace($_)) {
                    Write-Host "  - $_ seconds" -ForegroundColor White
                }
            }
        }

        # EXIBIÇÃO DO CONTEÚDO COMPLETO
        Write-Host "`nCOMPLETE RAW CONTENT:" -ForegroundColor DarkRed
        if ($content.Length -gt 2000) {
            Write-Host $content.Substring(0, 2000) -ForegroundColor Gray
            Write-Host "`n... (content truncated - too large)" -ForegroundColor DarkGray
        } else {
            Write-Host $content -ForegroundColor Gray
        }
        
        # ESTATÍSTICAS DETALHADAS
        $contentLength = $content.Length
        Write-Host "`nFILE INFORMATION:" -ForegroundColor Yellow
        Write-Host "  Content Length: $contentLength characters" -ForegroundColor White
        Write-Host "  Approx. Size: $([math]::Round($contentLength / 1024, 2)) KB" -ForegroundColor White
        Write-Host "  Lines: $($lines.Count)" -ForegroundColor White
        Write-Host "  User Agents: $($userAgents.Count)" -ForegroundColor White
        Write-Host "  Disallowed Paths: $($disallowed.Count)" -ForegroundColor White
        Write-Host "  Allowed Paths: $($allowed.Count)" -ForegroundColor White
        Write-Host "  Sitemap References: $($sitemaps.Count)" -ForegroundColor White
        Write-Host "  Crawl Delays: $($crawlDelays.Count)" -ForegroundColor White
        
        # LOG COMPLETO
        Write-Log "Robots.txt analysis completed: $($lines.Count) lines, $contentLength chars, $($disallowed.Count) disallowed paths"
        
    } catch {
        Write-Host "`n  robots.txt not found or inaccessible." -ForegroundColor Red
        Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor DarkRed
        Write-Log "Robots.txt not found: $($_.Exception.Message)" "WARNING"
    }
}
function ScanSitemap {
    param ([string]$url)
    try {
        Write-Host "`n Checking sitemap.xml..." -ForegroundColor Yellow
        Write-Log "Starting ScanSitemap for: $url"
        
        $sitemapUrl = "$url/sitemap.xml"
        $response = Invoke-WebRequestSafe -Uri $sitemapUrl
        
        #  CORREÇÃO: DEFINIR $content ANTES DE USAR
        $content = $response.Content.Trim()
        $lines = $content -split "`n" | Where-Object { $_.Trim() -ne '' }

        #  VERIFICAÇÃO DE CONTEÚDO VÁLIDO
        if ([string]::IsNullOrWhiteSpace($content)) {
            Write-Host "`n  sitemap.xml found but content is empty" -ForegroundColor Yellow
            Write-Log "Sitemap.xml is empty" "WARNING"
            return
        }
        
        if ($content -match '<urlset') {
            Write-Host "`n  STANDARD SITEMAP DETECTED (XML FORMAT)" -ForegroundColor Green
            $urls = @()
            
            #  EXTRAÇÃO MELHORADA DE URLs
            $locMatches = [regex]::Matches($content, '<loc>\s*([^<]+)\s*</loc>', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            $urls += $locMatches | ForEach-Object { 
                if ($_.Groups[1].Success) {
                    $_.Groups[1].Value.Trim()
                }
            }
            
            $urlMatches = [regex]::Matches($content, '<url>\s*<loc>([^<]+)</loc>', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            $urls += $urlMatches | ForEach-Object { 
                if ($_.Groups[1].Success) {
                    $_.Groups[1].Value.Trim()
                }
            }
            
            #  FILTRAGEM MELHORADA
            $urls = $urls | Where-Object { 
                -not [string]::IsNullOrWhiteSpace($_) -and $_.StartsWith('http')
            } | Select-Object -Unique
            
            Write-Host "`nTOTAL URLs EXTRACTED: $($urls.Count)" -ForegroundColor Green
            
            if ($urls.Count -gt 0) {
                Write-Host "`nALL URLs FOUND:" -ForegroundColor Cyan
                $urls | ForEach-Object {
                    Write-Host "  - $_" -ForegroundColor White
                }
                
                #  CATEGORIZAÇÃO MELHORADA
                $categories = @{
                    "Images" = $urls | Where-Object { $_ -match '\.(jpg|jpeg|png|gif|bmp|svg|webp)(\?|$)' }
                    "PDFs" = $urls | Where-Object { $_ -match '\.pdf(\?|$)' }
                    "Documents" = $urls | Where-Object { $_ -match '\.(doc|docx|xls|xlsx|ppt|pptx)(\?|$)' }
                    "Admin" = $urls | Where-Object { $_ -match '(admin|login|dashboard|panel|wp-admin|administrator)' }
                    "API" = $urls | Where-Object { $_ -match '(api|json|xml|rest|graphql|soap)' }
                    "JavaScript" = $urls | Where-Object { $_ -match '\.(js|jsx|ts|tsx)(\?|$)' }
                    "CSS" = $urls | Where-Object { $_ -match '\.(css|scss|sass|less)(\?|$)' }
                }
                
                Write-Host "`nURL CATEGORIES:" -ForegroundColor Magenta
                foreach ($category in $categories.Keys) {
                    $count = $categories[$category].Count
                    if ($count -gt 0) {
                        Write-Host "  $category`: $count URLs" -ForegroundColor White
                    }
                }
                
                #  DETECÇÃO DE URLs INTERESSANTES
                $interestingUrls = $urls | Where-Object { 
                    $_ -match '(admin|login|config|setup|debug|backup|test|dev|staging|secret|private|internal)' 
                }
                if ($interestingUrls.Count -gt 0) {
                    Write-Host "`nINTERESTING/ADMIN URLs:" -ForegroundColor Red
                    $interestingUrls | ForEach-Object {
                        Write-Host "  [!] $_" -ForegroundColor Red
                    }
                }
            } else {
                Write-Host "`n  No valid URLs found in sitemap" -ForegroundColor Yellow
            }
            
        } elseif ($content -match '^http' -or $content -match 'sitemap') {
            Write-Host "`n  SITEMAP INDEX DETECTED" -ForegroundColor Green
            $sitemapRefs = $content -split "`n" | Where-Object { 
                $_ -match '^http' -or $_ -match 'sitemap' -or $_ -match '\.xml'
            } | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
            
            Write-Host "`nSITEMAP REFERENCES FOUND: $($sitemapRefs.Count)" -ForegroundColor Green
            
            if ($sitemapRefs.Count -gt 0) {
                Write-Host "`nALL SITEMAP REFERENCES:" -ForegroundColor Yellow
                $sitemapRefs | ForEach-Object {
                    Write-Host "  - $_" -ForegroundColor White
                }
            } else {
                Write-Host "`n  No valid sitemap references found" -ForegroundColor Yellow
            }
            
        } else {
            Write-Host "`nUNKNOWN SITEMAP FORMAT" -ForegroundColor Yellow
            Write-Host "  Raw content:" -ForegroundColor Gray
            Write-Host $content -ForegroundColor DarkGray
        }
        
        #  EXIBIÇÃO DO CONTEÚDO CRU (SE NÃO FOR MUITO GRANDE)
        $contentLength = $content.Length
        if ($contentLength -lt 5000) {
            Write-Host "`nCOMPLETE RAW CONTENT:" -ForegroundColor DarkYellow
            Write-Host $content -ForegroundColor Gray
        } else {
            Write-Host "`nCONTENT PREVIEW (first 1000 chars):" -ForegroundColor DarkYellow
            Write-Host $content.Substring(0, 1000) -ForegroundColor Gray
            Write-Host "`n... (content truncated - too large)" -ForegroundColor DarkGray
        }

        Write-Host "`nFILE INFORMATION:" -ForegroundColor Yellow
        Write-Host "  Content Length: $contentLength characters" -ForegroundColor White
        Write-Host "  Approx. Size: $([math]::Round($contentLength / 1024, 2)) KB" -ForegroundColor White
        Write-Host "  Lines: $($lines.Count)" -ForegroundColor White
        
        Write-Log "Sitemap.xml analysis completed: $contentLength characters, $($urls.Count) URLs found" "INFO"
        
    } catch {
        Write-Host "`n  sitemap.xml not found or inaccessible." -ForegroundColor Red
        Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor DarkRed
        Write-Log "Sitemap.xml not found: $($_.Exception.Message)" "WARNING"
    }
}

function ScanHTML {
    param ([string]$url)
    try {
        Write-Host "`n Obtaining words from the HTML source code..." -ForegroundColor Yellow
        Write-Log "Starting ScanHTML for: $url"
        Start-Sleep -Seconds 2

        $response = Invoke-WebRequestSafe -Uri $url
        $htmlContent = $response.Content

        # CORREÇÃO DO ENCODING - Converte caracteres malformados
        $encoding = [System.Text.Encoding]::GetEncoding("ISO-8859-1")
        $bytes = $encoding.GetBytes($htmlContent)
        $htmlContent = [System.Text.Encoding]::UTF8.GetString($bytes)

        # SUA FUNÇÃO ORIGINAL - SEM MUDANÇAS
        $palavras = ($htmlContent -split '[^\p{L}0-9_\-]+') |
                    Where-Object { $_.Length -gt 2 } |
                    Select-Object -Unique |
                    Sort-Object

        # Remove apenas palavras extremamente comuns se necessário
        $commonWords = @('NON9')
        $palavras = $palavras | Where-Object { $commonWords -notcontains $_.ToLower() }

        Write-Host "`nTotal unique words found: $($palavras.Count)" -ForegroundColor Green
        Write-Log "Found $($palavras.Count) unique words for fuzzing"

        if ($palavras.Count -gt 0) {
            Write-Host "`nExample of found words (first 15):" -ForegroundColor Yellow
            $palavras | Select-Object -First 15 | ForEach-Object {
                Write-Host "   $_" -ForegroundColor White
            }

            # Salvamento automático ou por confirmação
            $save = "Y"
            if ($global:AutoFuzzingMode -ne 1) {
                $save = Read-Host "`nDo you want to save the words to a file for fuzzing? (Y/N)"
            }

            if ($save -eq 'Y' -or $save -eq 'y' -or $global:AutoFuzzingMode -eq 1) {
                $fuzzingDir = "Fuzz_files"
                if (-not (Test-Path $fuzzingDir)) {
                    New-Item -ItemType Directory -Path $fuzzingDir -Force | Out-Null
                    Write-Host "`nCreated directory: $fuzzingDir" -ForegroundColor Green
                }

                $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                $domainName = ([System.Uri]$url).Host -replace '\.', '_'
                $filePath = "wordlist_${domainName}_${timestamp}.txt"
                $fullPath = Join-Path $fuzzingDir $filePath
                
                $palavras | Out-File -FilePath $fullPath -Encoding UTF8
                
                Write-Host "`nWords saved to: $fullPath" -ForegroundColor Green
                Write-Host "Total words: $($palavras.Count)" -ForegroundColor Gray
                Write-Log "Words saved to: $fullPath"

                return @{
                    Words = $palavras
                    SavedFilePath = $fullPath
                    TotalWords = $palavras.Count
                }
            }
        } else {
            Write-Host "`nNo relevant words were found in the HTML." -ForegroundColor Red
        }

        return @{
            Words = $palavras
            SavedFilePath = $null
            TotalWords = $palavras.Count
        }

    } catch {
        Write-ErrorWeb -ErrorObject $_
        return @{
            Words = @()
            SavedFilePath = $null
            TotalWords = 0
        }
    }
}
# =============================================
# FUNÇÕES DE SCAN DNS/REDE
# =============================================
function Get-ip-from-url {
    param (
        [Parameter(Mandatory=$true)]
        [String]$url
    )

    try {
        Write-Host "`n Searching for IP's DNS ..." -ForegroundColor Yellow
        Write-Log "Starting Get-ip-from-url for: $url"

        $domain = ($url -replace '^https?://', '') -replace '/.*$', ''

        $results = Resolve-DnsName -Name $domain -ErrorAction Stop
        
        Write-Host "`nIPv4 Address:" -ForegroundColor Green
        $ipv4 = $results | Where-Object { $_.Type -eq 'A' }
        if ($ipv4) {
            $ipv4 | ForEach-Object { 
                Write-Host "  $($_.IPAddress)" -ForegroundColor White
                #Write-Host "  Domain: $domain" -ForegroundColor White
            }
        } else {
            Write-Host "  Nenhum IPv4 encontrado" -ForegroundColor Red
        }
        
        Write-Host "`nIPv6 Address:" -ForegroundColor Green
        $ipv6 = $results | Where-Object { $_.Type -eq 'AAAA' }
        if ($ipv6) {
            $ipv6 | ForEach-Object { 
                Write-Host "  $($_.IPAddress)" -ForegroundColor White
            }
        } else {
            Write-Host "  Nenhum IPv6 encontrado" -ForegroundColor Red
        }

        Write-Log "Successfully resolved $domain - IPv4: $($ipv4.IPAddress -join ', ') IPv6: $($ipv6.IPAddress -join ', ')"
    }
    catch {
        Write-Host "`nErro ao resolver DNS para: $url" -ForegroundColor Red
        Write-Host "Detalhes: $($_.Exception.Message)" -ForegroundColor DarkRed
        Write-Log "DNS Resolution Error for $url : $($_.Exception.Message)" "ERROR"
    }
}

function Test-DNSZoneTransfer {
    param([string]$url)
    
    $domain = ($url -replace '^https?://', '') -replace '/.*$', ''
    
    Write-Host "`n  Testing DNS Zone Transfer for: $domain ..." -ForegroundColor Yellow
    
    try {
        $nsServers = Resolve-DnsName -Name $domain -Type NS -ErrorAction Stop | Where-Object Type -eq 'NS'
        
        if (-not $nsServers) {
            Write-Host "  No NS records found" -ForegroundColor Red
            return
        }
        
        Write-Host "   Found $($nsServers.Count) name servers" -ForegroundColor Green
        
        $zoneTransferVulnerable = $false
        
        foreach ($ns in $nsServers) {
            Write-Host "`n   Trying zone transfer from: $($ns.NameServer)" -ForegroundColor Cyan
            try {
                $zone = Resolve-DnsName -Name $domain -Type Any -Server $ns.NameServer -ErrorAction Stop
                if ($zone) {
                    Write-Host "`n   [!]ZONE TRANSFER VULNERABLE[!]" -ForegroundColor Red
                    Write-Host "   All DNS records exposed:" -ForegroundColor Yellow
                    
                    $zone | Select-Object -First 10 | Format-Table Name, Type, IPAddress -AutoSize
                    
                    Write-Host "   Total records exposed: $($zone.Count)" -ForegroundColor Red
                    $zoneTransferVulnerable = $true
                }
            } catch {
                Write-Host "     Zone transfer blocked (safe config!)" -ForegroundColor DarkGreen
            }
        }
        
        if (-not $zoneTransferVulnerable) {
            Write-Host "`n  All name servers are secure" -ForegroundColor Green
        }
        
    } catch {
        Write-Host "  Failed to get NS records: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Get-DNSRecords {
    param([string]$url)

    $domain = ($url -replace '^https?://', '') -replace '/.*$', ''

    Write-Host "`n Checking DNS records for: $domain" -ForegroundColor Yellow
    Write-Log "Starting DNS records check for: $domain" "INFO"

    $DNSResults = @{
        Domain = $domain
        Timestamp = Get-Date
        Records = @{}
    }

    $recordTypes = @(
        @{Type = "A"; Name = "A Records (IPv4)"; Color = "Green"},
        @{Type = "AAAA"; Name = "AAAA Records (IPv6)"; Color = "Blue"},
        @{Type = "MX"; Name = "MX Records"; Color = "Yellow"},
        @{Type = "NS"; Name = "NS Records"; Color = "Magenta"},
        @{Type = "SOA"; Name = "SOA Record"; Color = "DarkYellow"},
        @{Type = "CNAME"; Name = "CNAME Record"; Color = "DarkGreen"},
        @{Type = "TXT"; Name = "TXT Records"; Color = "DarkCyan"}
    )

    $recordsFound = $false
    $ips = @()
    $ipv4Addresses = @()
    $ipv6Addresses = @()

    foreach ($record in $recordTypes) {
        try {
            Write-Log "Looking for $($record.Type) records for: $domain" "INFO"
            $result = Resolve-DnsName -Name $domain -Type $record.Type -ErrorAction Stop
            
            if ($result) {
                if (-not $recordsFound) {
                    Write-host "`n Records found:" -ForegroundColor Green
                    $recordsFound = $true
                }
                
                Write-Host "`n   $($record.Name):" -ForegroundColor $record.Color
                $DNSResults.Records[$record.Type] = $result
                
                switch ($record.Type) {
                    "A" {
                        $result | ForEach-Object { 
                            Write-Host "     $($_.IPAddress)"
                            $ips += $_.IPAddress
                            $ipv4Addresses += $_.IPAddress
                        }
                    }
                    "AAAA" {
                        $result | ForEach-Object { 
                            Write-Host "     $($_.IPAddress)"
                            $ips += $_.IPAddress
                            $ipv6Addresses += $_.IPAddress
                        }
                    }
                    "MX" {
                        $result | ForEach-Object { 
                            Write-Host "     $($_.NameExchange) (Pref: $($_.Preference))"
                        }
                    }
                    "NS" {
                        $result | ForEach-Object { 
                            Write-Host "     $($_.NameHost)"
                        }
                    }
                    "SOA" {
                        $result | ForEach-Object { 
                            Write-Host "     Primary Server: $($_.PrimaryServer)"
                            Write-Host "     Admin: $($_.NameAdministrator)"
                            Write-Host "     Serial: $($_.SerialNumber)"
                            Write-Host "     Refresh: $($_.RefreshInterval)"
                            Write-Host "     Retry: $($_.RetryInterval)"
                            Write-Host "     Expire: $($_.ExpireLimit)"
                            Write-Host "     Minimum TTL: $($_.MinimumTimeToLive)"
                        }
                    }
                    "CNAME" {
                        $result | ForEach-Object { 
                            if ($_.NameAlias -and $_.NameHost) {
                                Write-Host "     $($_.NameAlias) -> $($_.NameHost)"
                            }
                        }
                    }
                    "TXT" {
                        $result | ForEach-Object { 
                            $txtString = $_.Strings -join '; '
                            Write-Host "     $txtString"
                        }
                    }
                }
                
                Write-Log "$($record.Type) records found for: $domain" "INFO"
            }
        }
        catch {
            Write-Host "     No $($record.Type) records found" -ForegroundColor Red
            Write-Log "No $($record.Type) records found for: $domain" "WARNING"
        }
    }

    if ($ips.Count -gt 0) {
        Write-Host "`n   Reverse Lookup (PTR):" -ForegroundColor Cyan
        Write-Log "Starting PTR lookups for $($ips.Count) IP addresses ($($ipv4Addresses.Count) IPv4, $($ipv6Addresses.Count) IPv6)" "INFO"
        
        $ptrResults = @()
        $ptrIPv4Results = @()
        $ptrIPv6Results = @()
        
        # Processa IPv4
        foreach ($ip in $ipv4Addresses) {
            try {
                $hostEntry = [System.Net.Dns]::GetHostEntry($ip)
                Write-Host "     IPv4: $ip -> $($hostEntry.HostName)" -ForegroundColor Green
                $ptrResults += @{IP=$ip; Hostname=$hostEntry.HostName; Type="IPv4"}
                $ptrIPv4Results += @{IP=$ip; Hostname=$hostEntry.HostName}
                Write-Log "PTR found for IPv4 $ip : $($hostEntry.HostName)" "INFO"
            }
            catch {
                Write-Host "     IPv4: $ip -> PTR not found" -ForegroundColor Red
                Write-Log "PTR not found for IPv4: $ip" "WARNING"
                $ptrResults += @{IP=$ip; Hostname="Not Found"; Type="IPv4"}
                $ptrIPv4Results += @{IP=$ip; Hostname="Not Found"}
            }
        }
        
        foreach ($ip in $ipv6Addresses) {
            try {
                $hostEntry = [System.Net.Dns]::GetHostEntry($ip)
                Write-Host "     IPv6: $ip -> $($hostEntry.HostName)`n" -ForegroundColor Green
                $ptrResults += @{IP=$ip; Hostname=$hostEntry.HostName; Type="IPv6"}
                $ptrIPv6Results += @{IP=$ip; Hostname=$hostEntry.HostName}
                Write-Log "PTR found for IPv6 $ip : $($hostEntry.HostName)" "INFO"
            }
            catch {
                Write-Host "     IPv6: $ip -> PTR not found" -ForegroundColor Red
                Write-Log "PTR not found for IPv6: $ip" "WARNING"
                $ptrResults += @{IP=$ip; Hostname="Not Found"; Type="IPv6"}
                $ptrIPv6Results += @{IP=$ip; Hostname="Not Found"}
            }
        }
        
        $DNSResults.Records.PTR = $ptrResults
        $DNSResults.Records.PTR_IPv4 = $ptrIPv4Results
        $DNSResults.Records.PTR_IPv6 = $ptrIPv6Results
    }
    else {
        Write-Host "`n   No IP addresses found for reverse lookup." -ForegroundColor Red
        Write-Log "No A or AAAA records found for reverse lookup: $domain" "INFO"
    }

    if (-not $recordsFound) {
        Write-Host "`n   No DNS records found for: $domain" -ForegroundColor Red
    }

    Write-Log "DNS records check completed for: $domain" "INFO"
    
}

# =============================================
# FUNÇÕES DE SCAN DE PORTAS/SERVIÇOS
# =============================================

function Get-PortBanner {
    param (
        [string]$url
    )

    Write-Host "`n Checking Port Banner's ... `n" -ForegroundColor Yellow
    Write-Log "Starting Get-PortBanner" "INFO"
    $uri = [System.Uri]$url
    $CleanHost = $uri.Host

    Write-Host "    Scanning ports: `n [ $($global:PortsForBannerScan -join ', ') ]`n" -ForegroundColor White
    
    $estimatedPortTime = [math]::Round(($global:PortsForBannerScan.Count * 2) / 60, 1)
    Write-Host " Estimated time for port scan: $estimatedPortTime minutes" -ForegroundColor Yellow  
    
    $webPorts = @(80, 443, 8080, 8443, 8888, 9080, 9090, 8000, 3000, 5000, 7443, 9443)
    
    $protocolCommands = @{
        21    = "USER anonymous`r`n"  # FTP
        22    = "SSH-2.0-Client`r`n"  # SSH
        23    = "`r`n"  # Telnet
        25    = "EHLO example.com`r`n" # SMTP
        53    = ""  # DNS (requer pacote específico)
        110   = "USER test`r`n" # POP3
        135   = ""  # RPC
        139   = ""  # NetBIOS
        143   = "A01 LOGIN test test`r`n" # IMAP
        445   = ""  # SMB
        993   = "A01 LOGIN test test`r`n" # IMAPS
        995   = "USER test`r`n" # POP3S
        1433  = "" # SQL Server
        3306  = "" # MySQL
        3389  = "" # RDP
        5432  = "" # PostgreSQL
        5900  = "" # VNC
        5985  = "" # WinRM
        6379  = "" # Redis
        9000  = "" # PHP-FPM
        9200  = "" # Elasticsearch
        27017 = "" # MongoDB
    }

    $PortsShuffled = $global:PortsForBannerScan | Sort-Object {Get-Random}
    $portCounter = 0
    $totalPorts = $PortsShuffled.Count

    foreach ($Port in $PortsShuffled) {
        $portCounter++
        $percentComplete = [math]::Round(($portCounter / $totalPorts) * 100)
        
        Write-Progress -Activity "Port Banner Grabbing" `
                    -Status "Testing port $Port ($portCounter/$totalPorts)" `
                    -PercentComplete $percentComplete `
                    -CurrentOperation "Target: $CleanHost"
        
        $delay = Get-Random -Minimum 50 -Maximum 500
        Start-Sleep -Milliseconds $delay

        try {
            if ($Port -in $webPorts) {
                Write-Host "`n    Testing web service on port $Port..." -ForegroundColor Cyan
                $banner = Test-HttpService -TargetHost $CleanHost -Port $Port -Timeout 5000
                
                if ($banner) {
                    Write-Host "[${CleanHost}:${Port}] HTTP Banner: $banner" -ForegroundColor Green
                    Write-Log "HTTP Banner found on ${CleanHost}:${Port} - $banner" "INFO"
                } else {
                    Write-Host "[${CleanHost}:${Port}] No HTTP banner received" -ForegroundColor Yellow
                    Write-Log "No HTTP banner on ${CleanHost}:${Port}" "INFO"
                }
                continue
            }
            
            $client = New-Object System.Net.Sockets.TcpClient
            $client.ReceiveTimeout = 5000
            $client.SendTimeout = 5000
            
            try {
                $connectTask = $client.ConnectAsync($CleanHost, $Port)
                
                $connectionSuccess = $false
                try {
                    $connectionSuccess = $connectTask.Wait(5000)
                }
                catch {
                    # Ignora erros do Wait() - tratamos pela conexão abaixo
                    $connectionSuccess = $false
                }
                
                if ($connectionSuccess -and $client.Connected) {
                    $stream = $client.GetStream()
                    $stream.ReadTimeout = 5000
                    
                    Start-Sleep -Milliseconds 100
                    
                    $initialBuffer = New-Object Byte[] 4096
                    $initialResponse = ""
                    
                    if ($stream.DataAvailable) {
                        try {
                            $read = $stream.Read($initialBuffer, 0, 4096)
                            $initialResponse = [System.Text.Encoding]::ASCII.GetString($initialBuffer, 0, $read)
                        }
                        catch {
                            # Ignora erros de leitura
                            $initialResponse = ""
                        }
                    }
                    
                    if (-not $initialResponse -and $protocolCommands.ContainsKey($Port)) {
                        $command = $protocolCommands[$Port]
                        if ($command) {
                            try {
                                $sendBuffer = [System.Text.Encoding]::ASCII.GetBytes($command)
                                $stream.Write($sendBuffer, 0, $sendBuffer.Length)
                                $stream.Flush()
                                Start-Sleep -Milliseconds 500
                            }
                            catch {
                                # Ignora erros de envio
                            }
                        }
                    }
                    
                    $finalBuffer = New-Object Byte[] 4096
                    $finalResponse = ""
                    
                    if ($stream.DataAvailable) {
                        try {
                            $read = $stream.Read($finalBuffer, 0, 4096)
                            $finalResponse = [System.Text.Encoding]::ASCII.GetString($finalBuffer, 0, $read)
                        }
                        catch {
                            # Ignora erros de leitura
                            $finalResponse = ""
                        }
                    }
                    
                    $fullResponse = ($initialResponse + $finalResponse).Trim()
                    
                    if ($fullResponse) {
                        $displayResponse = $fullResponse
                        if ($displayResponse.Length -gt 200) {
                            $displayResponse = $displayResponse.Substring(0, 200) + "..."
                        }
                        Write-Host "[${CleanHost}:${Port}] Banner Found: $displayResponse" -ForegroundColor Green
                        
                        $logResponse = $fullResponse.Replace("`r`n", " ").Replace("`n", " ")
                        $logLength = [Math]::Min(100, $logResponse.Length)
                        $safeLogResponse = $logResponse.Substring(0, $logLength)
                        Write-Log "Banner found on ${CleanHost}:${Port} - $safeLogResponse" "INFO"
                    } else {
                        Write-Host "[${CleanHost}:${Port}] Successful - connection but no banner Visible" -ForegroundColor Yellow
                        Write-Log "Successful connection but no banner on ${CleanHost}:${Port}" "INFO"
                    }
                    
                    try {
                        $stream.Close()
                        $client.Close()
                    }
                    catch {
                        # Ignora erros de fechamento
                    }
                }
                else {
                    Write-Host "[${CleanHost}:${Port}] Timeout - No Connection" -ForegroundColor DarkRed
                    Write-Log "Timeout connecting to ${CleanHost}:${Port}" "WARNING"
                    try { $client.Close() } catch { }
                }
            }
            catch {
                Write-Host "[${CleanHost}:${Port}] Erro: $($_.Exception.Message)" -ForegroundColor Red
                Write-Log "Error connecting to ${CleanHost}:${Port} - $($_.Exception.Message)" "WARNING"
                try { $client.Close() } catch { }
            }
        }
        catch {
            Write-Host "[${CleanHost}:${Port}] Erro geral: $($_.Exception.Message)" -ForegroundColor Red
            Write-Log "General error on ${CleanHost}:${Port} - $($_.Exception.Message)" "WARNING"
        }
    }
    
    Write-Progress -Activity "Port Banner Grabbing" -Status "Completed!" -Completed
}

# =============================================
# FUNÇÕES DE CONFIGURAÇÃO
# =============================================

function Set-PortsForBanner {
    while ($true) {
        Clear-Host 
        Logo_Menu
        Write-Host "`n                                                                   === Configure Ports for Banner Scan ===" -ForegroundColor Red
        Write-Host "`n`n                                        Selected Ports for Banner Grabing (Option:11) `n               [ $($global:PortsForBannerScan -join ', ') ]`n" -ForegroundColor White       
        Write-Host "`n                                                        [Preset's]`n" -ForegroundColor Red
        Write-Host "                                                                    Press " -NoNewline -ForegroundColor DarkRed
        Write-Host "[C]" -NoNewline -ForegroundColor DarkGreen
        Write-Host " - to use Common Used Ports" -ForegroundColor Gray
        Write-Host "                                                                            [     21:FTP      ]" -ForegroundColor Gray
        Write-Host "                                                                            [     22:SSH      ]" -ForegroundColor Gray
        Write-Host "                                                                            [    23:TELNET    ]" -ForegroundColor Gray
        Write-Host "                                                                            [     25:SMTP     ]" -ForegroundColor Gray
        Write-Host "                                                                            [     53:DNS      ]" -ForegroundColor Gray
        Write-Host "                                                                            [     80:HTTP     ]" -ForegroundColor Gray
        Write-Host "                                                                            [    443:HTTPS    ]" -ForegroundColor Gray
        Write-Host "                                                                            [    3306:MySQL   ]" -ForegroundColor Gray
        Write-Host "                                                                            [     3389:RDP    ]" -ForegroundColor Gray   
        Write-Host "                                                                            [ 5432:PostgreSQL ]" -ForegroundColor Gray
        Write-Host "                                                                            [  8080:HTTP-ALT  ]`n" -ForegroundColor Gray
        Write-Host "                                                                         Press " -ForegroundColor DarkRed -NoNewline
        Write-Host "[W]" -ForegroundColor DarkGreen -NoNewline
        Write-Host " - Web Services" -ForegroundColor Gray
        Write-Host "                                                                         Press " -ForegroundColor DarkRed -NoNewline
        Write-Host "[D]" -ForegroundColor DarkGreen -NoNewline
        Write-Host " - Databases" -ForegroundColor Gray
        Write-Host "                                                                         Press " -ForegroundColor DarkRed -NoNewline
        Write-Host "[E]" -ForegroundColor DarkGreen -NoNewline
        Write-Host " - Email" -ForegroundColor Gray
        Write-Host "                                                                         Press " -ForegroundColor DarkRed -NoNewline
        Write-Host "[R]" -ForegroundColor DarkGreen -NoNewline
        Write-Host " - Network/Admin" -ForegroundColor Gray
        Write-Host "                                                                         Press " -ForegroundColor DarkRed -NoNewline
        Write-Host "[A]" -ForegroundColor DarkGreen -NoNewline
        Write-Host " - APIs/Services" -ForegroundColor Gray
        Write-Host "                                                                         Press " -ForegroundColor DarkRed -NoNewline
        Write-Host "[F]" -ForegroundColor DarkGreen -NoNewline
        Write-Host " - Frequent Ports" -ForegroundColor Gray

        Write-Host "`n`n`n                                                       - Or Enter type ports separated by ',' (ex: 80,443,8080,8443)`n" -ForegroundColor Yellow

        $escolha = Show-InputPrompt -input_name "   Press [Enter] to save and Exit" -PaddingLeft 16 -QuestionColor Green
        
        if ([string]::IsNullOrWhiteSpace($escolha)) {
            Write-Host "`n                    Selected Ports: $($global:PortsForBannerScan -join ', ')" -ForegroundColor Yellow
            Write-host "`n      Configuration Saved!" -ForegroundColor Green
            Start-Sleep -Seconds 1
            return
        }
    
        # Opções rápidas com letras
        switch ($escolha.ToUpper()) {
            'C' {
                $global:PortsForBannerScan = @(21,22,23,25,53,80,443,3306,3389,5432,8080)
                Write-Host "`n                    Common ports set: $($global:PortsForBannerScan -join ', ')" -ForegroundColor Green
                Start-Sleep -Seconds 1
                continue
            }
            'W' {
                $global:PortsForBannerScan = @(80,443,8080,8443,8888,9090,9080,8000,3000,5000)
                Write-Host "`n                    Web services set: $($global:PortsForBannerScan -join ', ')" -ForegroundColor Green
                Start-Sleep -Seconds 1
                continue
            }
            'D' {
                $global:PortsForBannerScan = @(1433,1521,3306,5432,27017,6379,5984,9200,9300,11211)
                Write-Host "`n                    Databases set: $($global:PortsForBannerScan -join ', ')" -ForegroundColor Green
                Start-Sleep -Seconds 1
                continue
            }
            'E' {
                $global:PortsForBannerScan = @(25,110,143,465,587,993,995,2525)
                Write-Host "`n                    Email services set: $($global:PortsForBannerScan -join ', ')" -ForegroundColor Green
                Start-Sleep -Seconds 1
                continue
            }
            'R' {
                $global:PortsForBannerScan = @(21,22,23,53,135,139,445,161,162,389,636,3389,5985,5986)
                Write-Host "`n                    Network/Admin set: $($global:PortsForBannerScan -join ', ')" -ForegroundColor Green
                Start-Sleep -Seconds 1
                continue
            }
            'A' {
                $global:PortsForBannerScan = @(3000,5000,5601,5984,6379,7474,7687,8000,8080,8081,8090,8443,8888,9000,9200,11211,15672,27017)
                Write-Host "`n                    APIs/Services set: $($global:PortsForBannerScan -join ', ')" -ForegroundColor Green
                Start-Sleep -Seconds 1
                continue
            }
            'F' {
                $global:PortsForBannerScan = @(21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,3306,3389,5432,5900,5985,6379,8080,8443,9000,9200,27017)
                Write-Host "`n                    Frequent ports set: $($global:PortsForBannerScan -join ', ')" -ForegroundColor Green
                Start-Sleep -Seconds 1
                continue
            }
            'ALL' {
                Write-Host "`n                      Warning: Scanning all 65535 ports may take a long time and Borken Style program Because print Port's!" -ForegroundColor Red
                Write-Host "`n                            Press [Enter] to confirm or any other key to cancel..." -ForegroundColor Yellow
                $key = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                if ($key.VirtualKeyCode -ne 13) {
                    Write-Host "`n                      Action cancelled. No changes made." -ForegroundColor Red
                    Start-Sleep -Seconds 1
                    continue
                }

                $global:PortsForBannerScan = 1..65535
                Write-Host "`n                        All ports (1-65535) set for scan!" -ForegroundColor Green
                Start-Sleep -Seconds 1.5
                continue
            }
            default {
                $portas = $escolha -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^\d+$' } | ForEach-Object { [int]$_ } | Where-Object { $_ -ge 1 -and $_ -le 65535 } | Sort-Object -Unique
                if ($portas.Count -gt 0) {
                    $global:PortsForBannerScan = $portas
                    Write-Host "`n                    Ports set: $($global:PortsForBannerScan -join ', ')" -ForegroundColor Green
                    Start-Sleep -Seconds 1
                    continue
                } else {
                    Write-Host "`n                    Invalid input. Please try again." -ForegroundColor Red
                    Start-Sleep -Seconds 1
                    continue
                }
            }
        }
    }
}

function Set-ScansInteractive {
    foreach ($scan in $global:AllScans) {
        $name = $scan.Name
        if ($global:ScansConfig | Where-Object { $_.Name -eq $name }) {
            $scan.Enabled = 1
        } else {
            $scan.Enabled = 0
        }
    }

    $scans = $global:AllScans.Clone()
    
    while ($true) {
        Clear-Host 
        Logo_Menu
        Write-Host "`n                                                                              === Configure Scans ===" -ForegroundColor Red
        Write-Host "`n`n                                   Configure which scans will be executed in the RunAllScans function (option:13)`n`n" -ForegroundColor Gray

        $width = 180

        # formata índice
        $indexFormat = '{0,2}. {1}'

        # lista formatada
        $entries = for ($i = 0; $i -lt $scans.Count; $i++) {
            $scan = $scans[$i]
            $index = $i + 1
            $entry = $indexFormat -f $index, $scan.Name
            $entry
        }

        $maxEntryLength = ($entries | ForEach-Object { $_.Length } | Measure-Object -Maximum).Maximum
        $statusLength = 3
        $blockWidth = $maxEntryLength + 1 + $statusLength
        $leftPaddingBase = [Math]::Max(0, [Math]::Floor(($width - $blockWidth) / 2))

        for ($i = 0; $i -lt $scans.Count; $i++) {
            $scan = $scans[$i]
            $index = $i + 1
            $entry = $indexFormat -f $index, $scan.Name
            $statusText = if ($scan.Enabled -eq 1) { '[1]' } else { '[0]' }
            $innerPadLength = ($maxEntryLength - $entry.Length) + 1
            if ($innerPadLength -lt 1) { $innerPadLength = 1 }
            $innerPadding = ' ' * $innerPadLength
            $leftPadding = ' ' * $leftPaddingBase

            Write-Host -NoNewline ($leftPadding + $entry + $innerPadding)
            if ($scan.Enabled -eq 1) {
                Write-Host $statusText -ForegroundColor Green
            } else {
                Write-Host $statusText -ForegroundColor Red
            }
        }
        
        Write-Host "`n`n                                                            [Preset's]" -ForegroundColor Red
        Write-Host "`n                                                                       Press " -NoNewline -ForegroundColor DarkRed
        Write-Host "[B]" -NoNewline -ForegroundColor DarkGreen
        Write-Host " - Basic Recon (1,2,3,5,6)" -ForegroundColor Gray
        Write-Host "                                                                       Press " -NoNewline -ForegroundColor DarkRed
        Write-Host "[W]" -NoNewline -ForegroundColor DarkGreen
        Write-Host " - Web Application (1,2,4,5,6,10)" -ForegroundColor Gray
        Write-Host "                                                                       Press " -NoNewline -ForegroundColor DarkRed
        Write-Host "[N]" -NoNewline -ForegroundColor DarkGreen
        Write-Host " - Network & DNS (3,8,9,13)" -ForegroundColor Gray
        Write-Host "                                                                       Press " -NoNewline -ForegroundColor DarkRed
        Write-Host "[C]" -NoNewline -ForegroundColor DarkGreen
        Write-Host " - Content Discovery (10,11,12,14)" -ForegroundColor Gray
        Write-Host "                                                                       Press " -NoNewline -ForegroundColor DarkRed
        Write-Host "[S]" -NoNewline -ForegroundColor DarkGreen
        Write-Host " - Security Audit (2,4,7,8,13)" -ForegroundColor Gray
        Write-Host "                                                                       Press " -NoNewline -ForegroundColor DarkRed
        Write-Host "[T]" -NoNewline -ForegroundColor DarkGreen
        Write-Host " - Stealth Mode (1,2,3,5,6,11,12)" -ForegroundColor Gray
        Write-Host "                                                                       Press " -NoNewline -ForegroundColor DarkRed
        Write-Host "[P]" -NoNewline -ForegroundColor DarkGreen
        Write-Host " - Penetration Test (1,2,3,4,5,6,7,10,11,12,13,14)" -ForegroundColor Gray
        Write-Host "                                                                       Press " -NoNewline -ForegroundColor DarkRed
        Write-Host "[A]" -NoNewline -ForegroundColor DarkGreen
        Write-Host " - Active All (1 to 14)" -ForegroundColor Gray
        Write-Host "`n`n`n                                   - Enter the number corresponding to the function you want to Enable or Disable or Select Preset's`n" -ForegroundColor Yellow
        $choice = Show-InputPrompt -input_name "  Press [Enter] to Save and exit" -PaddingLeft 25 -QuestionColor Green
        
        if ([string]::IsNullOrWhiteSpace($choice)) {
            $global:ScansConfig = $scans | Where-Object { $_.Enabled -eq 1 }
            Write-Host "`n`n`n      Configuration saved!" -ForegroundColor Green
            Start-Sleep -Seconds 1
            return $global:ScansConfig
        }
        
        switch ($choice.ToUpper()) {
            # === PRESETS ===
            'B' {
                # BASIC RECON - Para iniciantes/resultados rápidos
                for ($i = 0; $i -lt $scans.Count; $i++) {
                    $scans[$i].Enabled = 0
                }
                $preset = 1,2,3,5,6
                foreach ($i in $preset) { $scans[$i-1].Enabled = 1 }
                Write-Host "`nBasic Recon enabled (Status, Title, IP, Headers, Technologies)" -ForegroundColor Green
                Start-Sleep -Seconds 1
                continue
            }
            'W' {
                # WEB APPLICATION - Foco em aplicações web
                for ($i = 0; $i -lt $scans.Count; $i++) {
                    $scans[$i].Enabled = 0
                }
                $preset = 1,2,4,5,6,10
                foreach ($i in $preset) { $scans[$i-1].Enabled = 1 }
                Write-Host "`nWeb Application scans enabled" -ForegroundColor Green
                Start-Sleep -Seconds 1
                continue
            }
            'N' {
                # NETWORK & DNS - Infraestrutura de rede
                for ($i = 0; $i -lt $scans.Count; $i++) {
                    $scans[$i].Enabled = 0
                }
                $preset = 3,8,9,13
                foreach ($i in $preset) { $scans[$i-1].Enabled = 1 }
                Write-Host "`nNetwork & DNS scans enabled" -ForegroundColor Green
                Start-Sleep -Seconds 1
                continue
            }
            'C' {
                # CONTENT DISCOVERY - Enumerar conteúdo
                for ($i = 0; $i -lt $scans.Count; $i++) {
                    $scans[$i].Enabled = 0
                }
                $preset = 10,11,12,14
                foreach ($i in $preset) { $scans[$i-1].Enabled = 1 }
                Write-Host "`nContent Discovery scans enabled" -ForegroundColor Green
                Start-Sleep -Seconds 1
                continue
            }
            'S' {
                # SECURITY AUDIT - Verificações de segurança
                for ($i = 0; $i -lt $scans.Count; $i++) {
                    $scans[$i].Enabled = 0
                }
                $preset = 2,4,7,8,13
                foreach ($i in $preset) { $scans[$i-1].Enabled = 1 }
                Write-Host "`nSecurity Audit scans enabled" -ForegroundColor Green
                Start-Sleep -Seconds 1
                continue
            }
            'T' {
                for ($i = 0; $i -lt $scans.Count; $i++) {
                    $scans[$i].Enabled = 0
                }
                $preset = 1,2,3,5,6,11,12
                foreach ($i in $preset) { $scans[$i-1].Enabled = 1 }
                Write-Host "`nStealth Mode enabled (Minimal detection, max information)" -ForegroundColor Green
                Start-Sleep -Seconds 1
                continue
            }
            'P' {
                # PENETRATION TEST - Scan agressivo completo
                for ($i = 0; $i -lt $scans.Count; $i++) {
                    $scans[$i].Enabled = 0
                }
                $preset = 1,2,3,4,5,6,7,10,11,12,13,14
                foreach ($i in $preset) { $scans[$i-1].Enabled = 1 }
                Write-Host "`nPenetration Testing scans enabled" -ForegroundColor Green
                Start-Sleep -Seconds 1
                continue
            }
            'A' {
                # ACTIVE ALL - Tudo mesmo (máximo ruído)
                for ($i = 0; $i -lt $scans.Count; $i++) {
                    $scans[$i].Enabled = 1
                }
                Write-Host "`nAll scans enabled (1 to 14)" -ForegroundColor Green
                Start-Sleep -Seconds 1
                continue
            }

            default {
                if ($choice -match '^\d+$') {
                    $n = [int]$choice
                    if ($n -ge 1 -and $n -le $scans.Count) {
                        $scans[$n-1].Enabled = 1 - $scans[$n-1].Enabled
                        $status = if ($scans[$n-1].Enabled -eq 1) { "ENABLED" } else { "DISABLED" }
                        $color = if ($scans[$n-1].Enabled -eq 1) { "Green" } else { "Red" }
                        Write-Host "`n$($scans[$n-1].Name) -> $status" -ForegroundColor $color
                        Start-Sleep -Milliseconds 600
                    } else {
                        Write-Host "`nNumber out of range (1-$($scans.Count))." -ForegroundColor Red
                        Start-Sleep -Milliseconds 800
                    }
                } else {
                    Write-Host "`n  Invalid choice." -ForegroundColor Red
                    Start-Sleep -Milliseconds 800
                    Continue
                }
            }
        }
    }
}

function Set-FuzzingRecursive {
    while ($true) {
        Clear-Host 
        Logo_Menu
        Write-Host "`n                                                                 === Configure Recursive Fuzzing ===" -ForegroundColor Red
        
        Write-Host "`n`n                                                  [Current Fuzzing Configuration]:" -ForegroundColor Yellow
        Write-Host "`n                                                                          " -NoNewline
        Write-Host "(" -NoNewline -ForegroundColor White
        Write-Host "Configured" -NoNewline -ForegroundColor Cyan
        Write-Host ")" -NoNewline -ForegroundColor White
        Write-Host " Max Depth:            " -NoNewline -ForegroundColor Gray
    
        if ($global:FuzzingMaxDepth -ge 1 -and $global:FuzzingMaxDepth -le 2) {
            Write-Host "$($global:FuzzingMaxDepth)" -ForegroundColor Yellow
        } elseif ($global:FuzzingMaxDepth -ge 3 -and $global:FuzzingMaxDepth -le 4) {
            Write-Host "$($global:FuzzingMaxDepth)" -ForegroundColor Green
        } elseif ($global:FuzzingMaxDepth -ge 5 -and $global:FuzzingMaxDepth -le 6) {
            Write-Host "$($global:FuzzingMaxDepth)" -ForegroundColor DarkGreen
        } elseif ($global:FuzzingMaxDepth -ge 7 -and $global:FuzzingMaxDepth -le 8) {
            Write-Host "$($global:FuzzingMaxDepth)" -ForegroundColor Red
        } elseif ($global:FuzzingMaxDepth -ge 9 -and $global:FuzzingMaxDepth -le 10) {
            Write-Host "$($global:FuzzingMaxDepth)" -ForegroundColor DarkRed
        } else {
            Write-Host "$($global:FuzzingMaxDepth)" -ForegroundColor Gray
        }

        Write-Host "                                                                          " -NoNewline
        Write-Host "(" -NoNewline -ForegroundColor White
        Write-Host "Configured" -NoNewline -ForegroundColor Cyan
        Write-Host ")" -NoNewline -ForegroundColor White
        Write-Host " Timeout (ms):       " -NoNewline -ForegroundColor Gray

        if ($global:FuzzingTimeoutMs -ge 500 -and $global:FuzzingTimeoutMs -le 1000) {
            Write-Host "$($global:FuzzingTimeoutMs)ms" -ForegroundColor DarkRed  # Muito rápido = Alto risco
        } elseif ($global:FuzzingTimeoutMs -ge 1001 -and $global:FuzzingTimeoutMs -le 2000) {
            Write-Host "$($global:FuzzingTimeoutMs)ms" -ForegroundColor Red      # Rápido = Risco moderado
        } elseif ($global:FuzzingTimeoutMs -ge 2001 -and $global:FuzzingTimeoutMs -le 5000) {
            Write-Host "$($global:FuzzingTimeoutMs)ms" -ForegroundColor Yellow   # Moderado = Risco baixo
        } elseif ($global:FuzzingTimeoutMs -ge 5001 -and $global:FuzzingTimeoutMs -le 30000) {
            Write-Host "$($global:FuzzingTimeoutMs)ms" -ForegroundColor Green    # Lento = Baixo risco
        } else {
            Write-Host "$($global:FuzzingTimeoutMs)ms" -ForegroundColor Gray
        }

        Write-Host "                                                                          " -NoNewline
        Write-Host "(" -NoNewline -ForegroundColor White
        Write-Host "Configured" -NoNewline -ForegroundColor Cyan
        Write-Host ")" -NoNewline -ForegroundColor White
        Write-Host " Max Threads:          " -NoNewline -ForegroundColor Gray
        write-Host "$($global:FuzzingMaxThreads)" -ForegroundColor Magenta

        Write-Host "                                                                          " -NoNewline
        Write-Host "(" -NoNewline -ForegroundColor White
        Write-Host "Configured" -NoNewline -ForegroundColor Cyan
        Write-Host ")" -NoNewline -ForegroundColor White
        Write-Host " Aggressive Mode:   " -NoNewline -ForegroundColor Gray
        Write-Host "$(if ($global:FuzzingAggressive) { 'ENABLED' } else { 'DISABLED' })" -ForegroundColor $(if ($global:FuzzingAggressive) { "Green" } else { "Red" }) 

        Write-Host "                                                                          " -NoNewline
        Write-Host "(" -NoNewline -ForegroundColor White
        Write-Host "Configured" -NoNewline -ForegroundColor Cyan
        Write-Host ")" -NoNewline -ForegroundColor White
        Write-Host " Subdomain Fuzzing: " -NoNewline -ForegroundColor Gray
        Write-Host "$(if ($global:FuzzingSubdomain) { 'ENABLED' } else { 'DISABLED' })" -ForegroundColor $(if ($global:FuzzingSubdomain) { "Green" } else { "Red" }) 

        Write-Host "`n`n                                                        [Configuration Options]`n" -ForegroundColor Red
        
        Write-Host "                                                                       Press " -NoNewline -ForegroundColor DarkRed
        Write-Host "[1]" -NoNewline -ForegroundColor DarkGreen
        Write-Host " - Configure Max Depth " -ForegroundColor Gray
        
        Write-Host "                                                                       Press " -NoNewline -ForegroundColor DarkRed
        Write-Host "[2]" -NoNewline -ForegroundColor DarkGreen
        Write-Host " - Configure Timeout " -ForegroundColor Gray
        
        Write-Host "                                                                       Press " -NoNewline -ForegroundColor DarkRed
        Write-Host "[3]" -NoNewline -ForegroundColor DarkGreen
        Write-Host " - Configure Max Threads " -ForegroundColor Gray
        
        Write-Host "                                                                       Press " -NoNewline -ForegroundColor DarkRed
        Write-Host "[4]" -NoNewline -ForegroundColor DarkGreen
        Write-Host " - Toggle Aggressive Mode" -ForegroundColor Gray
        
        Write-Host "                                                                       Press " -NoNewline -ForegroundColor DarkRed
        Write-Host "[5]" -NoNewline -ForegroundColor DarkGreen
        Write-Host " - Toggle Subdomain Fuzzing`n" -ForegroundColor Gray

        if ($global:FuzzingStatusCodes.Count -gt 0) {
            Write-Host "`n                                                      [Selected Status Codes]:" -ForegroundColor Yellow
            foreach ($code in $global:FuzzingStatusCodes) {
                $color = Get-StatusCodeColor -StatusCode $code
                Write-Host "                                                                           $code" -ForegroundColor $color -NoNewline
                Write-Host " - $(Get-StatusCodeDescription -Code $code)" -ForegroundColor Gray
            }
        }
        
        Write-Host "`n`n                                                        [Status Code Presets]`n" -ForegroundColor Red
        
        Write-Host "                                                                       Press " -NoNewline -ForegroundColor DarkRed
        Write-Host "[S]" -NoNewline -ForegroundColor DarkGreen
        Write-Host " - Success Codes Only         (200, 301, 302)" -ForegroundColor Gray
        
        Write-Host "                                                                       Press " -NoNewline -ForegroundColor DarkRed
        Write-Host "[G]" -NoNewline -ForegroundColor DarkGreen
        Write-Host " - Good Codes          (200, 301, 302, 403, 500, 503)" -ForegroundColor Gray

        Write-Host "                                                                       Press " -NoNewline -ForegroundColor DarkRed
        Write-Host "[E]" -NoNewline -ForegroundColor DarkGreen
        Write-Host " - Error Codes Only      (400, 403, 404, 500, 503)" -ForegroundColor Gray
        
        Write-Host "                                                                       Press " -NoNewline -ForegroundColor DarkRed
        Write-Host "[A]" -NoNewline -ForegroundColor DarkGreen
        Write-Host " - All           (200, 301, 302, 400, 403, 404, 500, 503)" -ForegroundColor Gray
        
        Write-Host "                                                                       Press " -NoNewline -ForegroundColor DarkRed
        Write-Host "[N]" -NoNewline -ForegroundColor DarkGreen
        Write-Host " - All Except Errors     (except 400, 403, 404)" -ForegroundColor Gray
        
        Write-Host "                                                                       Press " -NoNewline -ForegroundColor DarkRed
        Write-Host "[C]" -NoNewline -ForegroundColor DarkGreen
        Write-Host " - Clear All Status Codes" -ForegroundColor Gray

        Write-Host "`n`n`n                                                       - Or enter custom status codes separated by ',' (ex: 200,301,404)`n" -ForegroundColor Yellow

        $escolha = Show-InputPrompt -input_name "   Press [Enter] to save and Exit" -PaddingLeft 16 -QuestionColor Green
        
        if ([string]::IsNullOrWhiteSpace($escolha)) {
            Write-Host "`n                    Configuration Saved!" -ForegroundColor Green
            Start-Sleep -Seconds 1
            return
        }
    
        # Opções de configuração
        switch ($escolha.ToUpper()) {
            '1' {
                Write-Host "`n               Current Max Depth: $($global:FuzzingMaxDepth)" -ForegroundColor Yellow
                Write-Host "               Recommended: 2-6 (higher = more comprehensive but slower)" -ForegroundColor Gray
                $newDepth = Show-InputPrompt -input_name "Enter new Max Depth" -PaddingLeft 52 -QuestionColor Green
                if ($newDepth -match '^\d+$' -and [int]$newDepth -ge 1 -and [int]$newDepth -le 10) {
                    $global:FuzzingMaxDepth = [int]$newDepth
                    Write-Host "`n                    Max Depth set to: $global:FuzzingMaxDepth" -ForegroundColor Green
                } else {
                    Write-Host "`n                    Invalid depth. Must be between 1 and 10." -ForegroundColor Red
                }
                Start-Sleep -Seconds 1
                continue
            }
            '2' {
                Write-Host "`n               Current Timeout: $($global:FuzzingTimeoutMs)ms" -ForegroundColor Yellow
                $newTimeout = Show-InputPrompt -input_name "Enter new Timeout (ms) ex: 2000-10000 (higher = more reliable but slower)" -PaddingLeft 38 -QuestionColor Green
                if ($newTimeout -match '^\d+$' -and [int]$newTimeout -ge 500 -and [int]$newTimeout -le 30000) {
                    $global:FuzzingTimeoutMs = [int]$newTimeout
                    Write-Host "`n                    Timeout set to: ${global:FuzzingTimeoutMs}ms" -ForegroundColor Green
                } else {
                    Write-Host "`n                    Invalid timeout. Must be between 500 and 30000." -ForegroundColor Red
                }
                Start-Sleep -Seconds 1
                continue
            }
            '3' {
                Write-Host "`n               Current Max Threads: $($global:FuzzingMaxThreads)" -ForegroundColor Yellow
                Write-Host "               Recommended: 3-10 (higher = faster but more detectable)" -ForegroundColor Gray
                $newThreads = Show-InputPrompt -input_name "Enter new Max Threads" -PaddingLeft 52 -QuestionColor Green
                if ($newThreads -match '^\d+$' -and [int]$newThreads -ge 1 -and [int]$newThreads -le 20) {
                    $global:FuzzingMaxThreads = [int]$newThreads
                    Write-Host "`n                    Max Threads set to: $global:FuzzingMaxThreads" -ForegroundColor Green
                } else {
                    Write-Host "`n                    Invalid thread count. Must be between 1 and 20." -ForegroundColor Red
                }
                Start-Sleep -Seconds 1
                continue
            }
            '4' {
                $global:FuzzingAggressive = -not $global:FuzzingAggressive
                $status = if ($global:FuzzingAggressive) { "ENABLED" } else { "DISABLED" }
                Write-Host "`n                    Aggressive Mode: $status" -ForegroundColor $(if ($global:FuzzingAggressive) { "Green" } else { "Red" })
                Write-Host "                    Note: Aggressive mode increases speed but may trigger WAF/IDS" -ForegroundColor Yellow
                Start-Sleep -Seconds 1
                continue
            }
            '5' {
                $global:FuzzingSubdomain = -not $global:FuzzingSubdomain
                $status = if ($global:FuzzingSubdomain) { "ENABLED" } else { "DISABLED" }
                Write-Host "`n                    Subdomain Fuzzing: $status" -ForegroundColor $(if ($global:FuzzingSubdomain) { "Green" } else { "Red" })
                Write-Host "                    Note: Subdomain fuzzing tests https://[word].domain.com.br patterns" -ForegroundColor Yellow
                Start-Sleep -Seconds 1
                continue
            }
            'S' {
                $global:FuzzingStatusCodes = @(200, 301, 302)
                Write-Host "`n                    Success Codes Only: 200, 301, 302" -ForegroundColor Green
                Start-Sleep -Seconds 1
                continue
            }
            'G' {
                # NOVO PRESET: Good Codes - 200,301,302,403,500,503
                $global:FuzzingStatusCodes = @(200, 301, 302, 403, 500, 503)
                Write-Host "`n                    Good Codes: 200, 301, 302, 403, 500, 503" -ForegroundColor Blue
                Write-Host "                    (Success + Forbidden + Server Errors)" -ForegroundColor Gray
                Start-Sleep -Seconds 1
                continue
            }
            'E' {
                $global:FuzzingStatusCodes = @(400, 403, 404, 500, 503)
                Write-Host "`n                    Error Codes Only: 400, 403, 404, 500, 503" -ForegroundColor Yellow
                Start-Sleep -Seconds 1
                continue
            }
            'A' {
                $global:FuzzingStatusCodes = @(200, 301, 302, 400, 403, 404, 500, 503)
                Write-Host "`n                    All Common Codes: 200, 301, 302, 400, 403, 404, 500, 503" -ForegroundColor Cyan
                Start-Sleep -Seconds 1
                continue
            }
            'N' {
                $global:FuzzingStatusCodes = @(200, 301, 302, 500, 503)
                Write-Host "`n                    All Except Client Errors: 200, 301, 302, 500, 503" -ForegroundColor Magenta
                Write-Host "                    (Excludes 400, 403, 404 - common error pages)" -ForegroundColor Gray
                Start-Sleep -Seconds 1
                continue
            }
            'C' {
                $global:FuzzingStatusCodes = @()
                Write-Host "`n                    All status codes cleared - will show all responses" -ForegroundColor Green
                Start-Sleep -Seconds 1
                continue
            }
            default {
                # Verifica se é uma lista de códigos de status
                $codes = $escolha -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^\d{3}$' } | ForEach-Object { [int]$_ } | Where-Object { $_ -ge 100 -and $_ -le 599 } | Sort-Object -Unique
                if ($codes.Count -gt 0) {
                    $global:FuzzingStatusCodes = $codes
                    Write-Host "`n                    Status Codes set: $($global:FuzzingStatusCodes -join ', ')" -ForegroundColor Green
                    Start-Sleep -Seconds 1
                    continue
                } else {
                    Write-Host "`n                    Invalid input. Please try again." -ForegroundColor Red
                    Start-Sleep -Seconds 1
                    continue
                }
            }
        }
    }
}
# =============================================
# CLASSE DE CONTROLE DE SESSÃO DE FUZZING
# =============================================
class FuzzingSession {
    [hashtable]$GlobalTestedUrls
    [hashtable]$TestedPaths
    [hashtable]$VisitedUrls
    [hashtable]$ContentHashes
    [System.Collections.Generic.List[object]]$AllResults
    [int]$TotalRequests
    [int]$ValidEndpoints  
    [int]$DuplicatesFiltered
    [int]$FilteredByStatus
    [string]$LastDuplicateUrl
    [datetime]$StartTime
    
    FuzzingSession() {
        $this.GlobalTestedUrls = @{}
        $this.TestedPaths = @{}
        $this.VisitedUrls = @{}
        $this.ContentHashes = @{}
        $this.AllResults = [System.Collections.Generic.List[object]]::new()
        $this.TotalRequests = 0
        $this.ValidEndpoints = 0
        $this.DuplicatesFiltered = 0
        $this.FilteredByStatus = 0
        $this.LastDuplicateUrl = "None"
        $this.StartTime = [datetime]::Now
    }
    
    [void] IncrementRequest() { $this.TotalRequests++ }
    [void] IncrementValidEndpoint() { $this.ValidEndpoints++ }
    [void] IncrementDuplicate() { $this.DuplicatesFiltered++ }
    [void] IncrementFiltered() { $this.FilteredByStatus++ }
    
    [hashtable] GetStatistics() {
        $duration = ([datetime]::Now - $this.StartTime).TotalSeconds
        $requestsPerSecond = if ($duration -gt 0) { 
            [math]::Round($this.TotalRequests / $duration, 2) 
        } else { 0 }
        
        $efficiencyRate = if ($this.TotalRequests -gt 0) { 
            [math]::Round(($this.ValidEndpoints / $this.TotalRequests) * 100, 2) 
        } else { 0 }
        
        return @{
            TotalRequests = $this.TotalRequests
            ValidEndpoints = $this.ValidEndpoints
            DuplicatesFiltered = $this.DuplicatesFiltered
            FilteredByStatus = $this.FilteredByStatus
            LastDuplicateUrl = $this.LastDuplicateUrl
            DurationSeconds = [math]::Round($duration, 2)
            RequestsPerSecond = $requestsPerSecond
            EfficiencyRate = $efficiencyRate
        }
    }
}
# =============================================
# SUBFUNÇÕES DE CONFIGURAÇÃO DE FUZZING
# =============================================
function Get-PageSignature {
    param([string]$Url)
    
    $request = $null
    $response = $null
    $stream = $null
    $reader = $null
    $md5 = $null
    
    try {
        Write-Log "Getting page signature for: $Url" "DEBUG"
        
        $request = [System.Net.WebRequest]::Create($Url)
        $request.Timeout = 15000
        $request.Method = "GET"
        
        $request.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        $request.Accept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        
        $request.Headers.Add("Accept-Language", "en-US,en;q=0.5")
        
        Write-Log "Request configured safely for: $Url" "DEBUG"
        
        # Obter resposta
        $response = $request.GetResponse()
        Write-Log "Response received - Status: $($response.StatusCode)" "DEBUG"
        
        # Verificar se é uma resposta válida
        if ($response.StatusCode -ne 200) {
            Write-Log "Non-200 response: $($response.StatusCode)" "WARNING"
            return @{
                Url = $Url
                Title = "Non-200 Response: $($response.StatusCode)"
                ContentLength = 0
                ContentHash = "status_$($response.StatusCode)"
                SampleContent = ""
                StatusCode = [int]$response.StatusCode
                ContentType = $response.ContentType
            }
        }
        
        $stream = $response.GetResponseStream()
        
        # Verificar se a resposta está compactada
        $contentEncoding = $response.Headers["Content-Encoding"]
        if ($contentEncoding -and $contentEncoding -match "gzip|deflate") {
            try {
                if ($contentEncoding -eq "gzip") {
                    $stream = New-Object System.IO.Compression.GZipStream($stream, [System.IO.Compression.CompressionMode]::Decompress)
                    Write-Log "GZIP compression detected and decompressed" "DEBUG"
                } elseif ($contentEncoding -eq "deflate") {
                    $stream = New-Object System.IO.Compression.DeflateStream($stream, [System.IO.Compression.CompressionMode]::Decompress)
                    Write-Log "Deflate compression detected and decompressed" "DEBUG"
                }
            } catch {
                Write-Log "Decompression failed, using raw stream: $($_.Exception.Message)" "WARNING"
                # Continua com o stream original - não é fatal
            }
        }
        
        $reader = New-Object System.IO.StreamReader($stream, [System.Text.Encoding]::UTF8)
        $content = $reader.ReadToEnd()
        
        # Se conteúdo estiver vazio, tentar detectar encoding alternativo
        if ([string]::IsNullOrWhiteSpace($content)) {
            Write-Log "Empty content detected, trying different encoding..." "WARNING"
            try {
                $stream.Position = 0
                $reader = New-Object System.IO.StreamReader($stream, [System.Text.Encoding]::Default)
                $content = $reader.ReadToEnd()
            } catch {
                Write-Log "Alternative encoding also failed: $($_.Exception.Message)" "WARNING"
                $content = ""
            }
        }
        
        # Extrair título
        $title = "No Title"
        if ($content -match '<title[^>]*>(.*?)</title>') { 
            $title = $matches[1].Trim()
            # Limpar título de caracteres problemáticos
            $title = $title -replace '[^\x20-\x7E]', '' -replace '\s+', ' ' -replace '"', '' -replace "'", ""
            if ($title.Length -gt 100) { 
                $title = $title.Substring(0, 100) + "..." 
            }
            Write-Log "Title extracted: '$title'" "DEBUG"
        } else {
            Write-Log "No title tag found in content" "DEBUG"
        }
        
        # Calcular hash do conteúdo
        try {
            $md5 = [System.Security.Cryptography.MD5]::Create()
            $contentBytes = [System.Text.Encoding]::UTF8.GetBytes($content)
            $hashBytes = $md5.ComputeHash($contentBytes)
            $contentHash = [System.BitConverter]::ToString($hashBytes).Replace("-", "").ToLower()
            Write-Log "Content hash calculated: $contentHash" "DEBUG"
        } catch {
            Write-Log "Hash calculation failed: $($_.Exception.Message)" "WARNING"
            $contentHash = "hash_error"
        }
        
        # Amostra de conteúdo segura
        $sampleContent = ""
        if ($content.Length -gt 0) {
            $sampleLength = [math]::Min(300, $content.Length)  # Reduzido para evitar problemas
            $sampleContent = $content.Substring(0, $sampleLength)
            # Limpar amostra de caracteres problemáticos
            $sampleContent = $sampleContent -replace '[^\x20-\x7E]', ' ' -replace '\s+', ' '
            Write-Log "Sample content extracted: $sampleLength chars" "DEBUG"
        }
        
        Write-Log "Page signature SUCCESS - Title: '$title', Size: $($content.Length), Hash: $contentHash" "INFO"
        
        return @{
            Url = $Url
            Title = $title
            ContentLength = $content.Length
            ContentHash = $contentHash
            SampleContent = $sampleContent
            StatusCode = [int]$response.StatusCode
            ContentType = $response.ContentType
        }
        
    } catch [System.Net.WebException] {
        $statusCode = 0
        $errorMsg = $_.Exception.Message
        
        if ($_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
            $errorMsg = "HTTP $statusCode - $($_.Exception.Message)"
        }
        
        Write-Log "WebException in Get-PageSignature for $Url - $errorMsg" "WARNING"
        
        #  SEMPRE RETORNAR UMA ESTRUTURA VÁLIDA - NUNCA $null
        return @{
            Url = $Url
            Title = "Web Error - $errorMsg"
            ContentLength = 0
            ContentHash = "web_error_$statusCode"
            SampleContent = ""
            StatusCode = $statusCode
            ContentType = "unknown"
        }
        
    } catch {
        $errorMsg = $_.Exception.Message
        Write-Log "Unexpected error in Get-PageSignature for $Url : $errorMsg" "ERROR"
        Write-Log "Stack trace: $($_.Exception.StackTrace)" "DEBUG"
        
        #  SEMPRE RETORNAR UMA ESTRUTURA VÁLIDA - NUNCA $null
        return @{
            Url = $Url
            Title = "System Error - $errorMsg"
            ContentLength = 0
            ContentHash = "system_error"
            SampleContent = ""
            StatusCode = 0
            ContentType = "unknown"
        }
        
    } finally {
        #  FECHAR RECURSOS DE FORMA SEGURA
        try { 
            if ($reader) { 
                $reader.Close() 
                $reader.Dispose()
            } 
        } catch { 
            Write-Log "Error closing reader: $($_.Exception.Message)" "DEBUG" 
        }
        
        try { 
            if ($stream) { 
                $stream.Close() 
                $stream.Dispose()
            } 
        } catch { 
            Write-Log "Error closing stream: $($_.Exception.Message)" "DEBUG" 
        }
        
        try { 
            if ($response) { 
                $response.Close() 
            } 
        } catch { 
            Write-Log "Error closing response: $($_.Exception.Message)" "DEBUG" 
        }
        
        try { 
            if ($md5) { 
                $md5.Dispose()
            } 
        } catch { 
            Write-Log "Error disposing MD5: $($_.Exception.Message)" "DEBUG" 
        }
        
        Write-Log "Resources cleaned up for: $Url" "DEBUG"
    }
}

function Get-StatusCodeColor {
    param([int]$StatusCode)
    
    switch ($StatusCode) {
        200 { return "Green" }
        301 { return "Magenta" }
        302 { return "DarkGreen" }
        400 { return "DarkRed" }
        403 { return "Magenta" }
        404 { return "Red" }
        500 { return "Yellow" }
        503 { return "Cyan" }
        default { 
            if ($StatusCode -ge 100 -and $StatusCode -lt 200) { return "Blue" }
            elseif ($StatusCode -ge 200 -and $StatusCode -lt 300) { return "Green" }
            elseif ($StatusCode -ge 300 -and $StatusCode -lt 400) { return "Cyan" }
            elseif ($StatusCode -ge 400 -and $StatusCode -lt 500) { return "Red" }
            elseif ($StatusCode -ge 500) { return "Yellow" }
            else { return "White" }
        }
    }
}

function Get-StatusCodeText {
    param([int]$StatusCode)
    
    $texts = @{
        200 = "200 - OK"
        301 = "301 - MOVED_PERMANENTLY" 
        302 = "302 - FOUND"
        400 = "400 - BAD_REQUEST"
        403 = "403 - FORBIDDEN"
        404 = "404 - NOT_FOUND"
        500 = "500 - INTERNAL_ERROR"
        503 = "503 - UNAVAILABLE"
    }
    
    if ($texts.ContainsKey($StatusCode)) {
        return $texts[$StatusCode]
    } else {
        return "$StatusCode - UNKNOWN"
    }
}
function Get-StatusCodeDescription {
    param([int]$Code)
    $descriptions = @{
        200 = "OK - Successful request"
        301 = "Moved Permanently - Permanent redirect" 
        302 = "Found - Temporary redirect"
        400 = "Bad Request - Client error"
        403 = "Forbidden - Access denied"
        404 = "Not Found - Resource not found"
        500 = "Internal Server Error - Server error"
        503 = "Service Unavailable - Service down"
    }
    
    if ($descriptions.ContainsKey($Code)) {
        return $descriptions[$Code]
    } else {
        return "Unknown status code"
    }
}

function Test-StatusCodeFilter {
    param([int]$StatusCode)
    
    if ($global:FuzzingStatusCodes.Count -eq 0) {
        return $true
    }
    
    return $global:FuzzingStatusCodes -contains $StatusCode
}

function Test-RealEndpoint {
    param($Url, $Content, $ContentLength, $BaseSignature)
    
    # 1. Hash IDÊNTICO = definitivamente duplicado
    $currentHash = [System.BitConverter]::ToString(
        [System.Security.Cryptography.MD5]::Create().ComputeHash(
            [System.Text.Encoding]::UTF8.GetBytes($Content)
        )
    ).Replace("-", "").ToLower()

    if ($currentHash -eq $BaseSignature.ContentHash) {
        Write-Log "CONTEUDO IDENTICO AO BASE: $Url" "DEBUG"
        return $false
    }

    # 2. Páginas de erro CLARAS (mais específicas)
    $clearErrorIndicators = @(
        "404 Not Found", "Page Not Found", "Error 404",
        "The page cannot be found", "This page isn't working",
        "404 - File or directory not found"
    )
    
    $errorCount = 0
    foreach ($indicator in $clearErrorIndicators) {
        if ($Content -imatch $indicator) {
            $errorCount++
        }
    }
    
    # Só rejeita se tiver MÚLTIPLOS indicadores de erro
    if ($errorCount -ge 2) {
        Write-Log "MULTIPLOS INDICADORES DE ERRO: $Url" "DEBUG"
        return $false
    }

    $alwaysValidPatterns = @(
        "wp-admin", "wp-content", "wp-json", "wp-includes",
        "administrator", "admin", "api", "ajax", "rest", "graphql",
        "login", "dashboard", "panel", "console"
    )
    
    foreach ($pattern in $alwaysValidPatterns) {
        if ($Url -imatch $pattern) {
            Write-Log "PADRAO SEMPRE VALIDO DETECTADO: $pattern em $Url" "DEBUG"
            return $true
        }
    }

    # 4. Listagem de diretório = SEMPRE VÁLIDA
    if ($Content -match "Index of /" -or $Content -match "Directory listing for /") {
        Write-Log "LISTAGEM DE DIRETORIO: $Url" "DEBUG"
        return $true
    }

    # 5. Título DIFERENTE = conteúdo diferente
    $currentTitle = if ($Content -match '<title[^>]*>(.*?)</title>') { 
        $matches[1].Trim() 
    } else { 
        $null 
    }
    
    $baseTitle = $BaseSignature.Title
    
    if ($currentTitle -and $currentTitle -ne $baseTitle -and $currentTitle -ne "No Title") {
        Write-Log "TITULO DIFERENTE: '$currentTitle' vs '$baseTitle' em $Url" "DEBUG"
        return $true
    }

    # 6. Conteúdo razoável sem erros óbvios (MAIS PERMISSIVO)
    if ($ContentLength -gt 200 -and $Content -notmatch '404|Not.Found|Error.404') {
        Write-Log "CONTEUDO RAZOAVEL SEM ERROS: $Url ($ContentLength bytes)" "DEBUG"
        return $true
    }

    # 7. URLs sem extensão + conteúdo mínimo (MAIS PERMISSIVO)
    $lastPart = $Url.Split('/')[-1]
    $fileExtensions = @('.jpg', '.jpeg', '.png', '.gif', '.css', '.js', '.pdf', '.zip', '.txt', '.xml', '.json', '.ico')
    $hasExtension = $false
    foreach ($ext in $fileExtensions) {
        if ($lastPart.ToLower().EndsWith($ext)) {
            $hasExtension = $true
            break
        }
    }
    
    # MAIS PERMISSIVO: qualquer URL sem extensão e com algum conteúdo
    if (-not $hasExtension -and $ContentLength -gt 100) {
        Write-Log "URL SEM EXTENSAO COM CONTEUDO: $Url ($ContentLength bytes)" "DEBUG"
        return $true
    }

    Write-Log "ENDPOINT NAO CLASSIFICADO COMO VALIDO: $Url" "DEBUG"
    return $false
}

# =============================================
# FUNÇÕES DE SUBDOMAIN FUZZING
# =============================================

function Test-SingleSubdomain {
    param($testUrl, $timeout, $parentWord, $allResults, $contentHashes, $session)
    
    try {
        $request = [System.Net.WebRequest]::Create($testUrl)
        $request.Timeout = $timeout
        $request.Method = "GET"
        $request.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        
        $response = $request.GetResponse()
        $statusCode = [int]$response.StatusCode
        $contentLength = $response.ContentLength
        
        $stream = $response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($stream)
        $fullContent = $reader.ReadToEnd()
        $reader.Close()
        $stream.Close()
        $response.Close()

        # Calcula hash do conteúdo
        $contentHash = [System.BitConverter]::ToString(
            [System.Security.Cryptography.MD5]::Create().ComputeHash(
                [System.Text.Encoding]::UTF8.GetBytes($fullContent)
            )
        ).Replace("-", "").ToLower()

        $isValidSubdomain = $statusCode -lt 400 -and $contentLength -gt 50  # Reduzido para 50 bytes

        $title = if ($fullContent -match '<title[^>]*>(.*?)</title>') { 
            $matches[1].Trim() 
        } else { $null }
        
        $result = [PSCustomObject]@{
            URL = $testUrl
            StatusCode = $statusCode
            ContentLength = $contentLength
            Word = $parentWord
            Depth = 0
            IsValid = $isValidSubdomain
            Title = $title
            ContentHash = $contentHash
            Timestamp = Get-Date
            Type = "Subdomain"
        }
        
        $allResults.Add($result) | Out-Null
        
        if ($isValidSubdomain) {
            $session.IncrementValidEndpoint()
            Write-Log "SUBDOMINIO VALIDO - STATUS $statusCode : $testUrl" "INFO"
            
            $statusColor = Get-StatusCodeColor -StatusCode $statusCode
            $statusText = Get-StatusCodeText -StatusCode $statusCode
            
            Write-Host "[SUBDOMAIN $statusText] $testUrl" -ForegroundColor $statusColor
            if ($title) {
                Write-Host "       Title: $title" -ForegroundColor Magenta
            }
            if ($contentLength -gt 0) {
                Write-Host "       Size: $contentLength bytes" -ForegroundColor Gray
            }
            
            return $true
        } else {
            $statusColor = Get-StatusCodeColor -StatusCode $statusCode
            $statusText = Get-StatusCodeText -StatusCode $statusCode
            
            Write-Host "[SUBDOMAIN $statusText] $testUrl" -ForegroundColor $statusColor
            if ($contentLength -gt 0) {
                Write-Host "       Size: $contentLength bytes" -ForegroundColor DarkGray
            }
            return $false
        }
        
    } catch [System.Net.WebException] {
        $webException = $_.Exception
        if ($webException.Response) {
            $statusCode = [int]$webException.Response.StatusCode
            $statusColor = Get-StatusCodeColor -StatusCode $statusCode
            $statusText = Get-StatusCodeText -StatusCode $statusCode
            
            Write-Host "[SUBDOMAIN $statusText] $testUrl" -ForegroundColor $statusColor
            
            $result = [PSCustomObject]@{
                URL = $testUrl
                StatusCode = $statusCode
                ContentLength = 0
                Word = $parentWord
                Depth = 0
                IsValid = $false
                Title = $null
                ContentHash = "error_$statusCode"
                Timestamp = Get-Date
                Type = "Subdomain"
            }
            $allResults.Add($result) | Out-Null
        } else {
            # Write-Host "[SUBDOMAIN TIMEOUT/ERROR] $testUrl" -ForegroundColor DarkYellow # gestão de errros
        }
        return $false
    } catch {
        Write-Host "[SUBDOMAIN ERROR] $testUrl - $($_.Exception.Message)" -ForegroundColor DarkRed
        return $false
    } finally {
        $session.IncrementRequest()
    }
}

function Invoke-SubdomainFuzzing {
    param(
        $baseDomain, 
        $wordList, 
        $allResults, 
        $contentHashes, 
        $TimeoutMsRef, 
        $session
    )
    
    Write-Log "INICIANDO SUBDOMAIN FUZZING" "INFO"
    Write-Host "   Pattern: https://[word].$baseDomain" -ForegroundColor Gray

    
    # Configuração otimizada para subdomínios
    $originalTimeout = $TimeoutMsRef.Value
    $localTimeout = $global:FuzzingTimeoutMs
    $originalStatusCodes = $global:FuzzingStatusCodes.Clone()
    $global:FuzzingStatusCodes = @()  # Mostrar todos os status codes para subdomínios
    
    $validSubdomains = @()
    $testedCount = 0
    $processedSubdomains = @{}
    
    try {
        foreach ($word in $wordList) {
            $subdomain = "$word.$baseDomain".ToLower()
            $testUrl = "https://$subdomain"
            $testedCount++
            
            # Progresso
            $percentComplete = [math]::Round(($testedCount / $wordList.Count) * 100, 1)
            Write-Progress -Id 10 -Activity "SUBDOMAIN FUZZING" -Status "Testing: $subdomain" -PercentComplete $percentComplete -CurrentOperation "Subdomains found: $($validSubdomains.Count)"

            # Verificar se já processou este subdomínio
            if (-not $processedSubdomains.ContainsKey($subdomain)) {
                $processedSubdomains[$subdomain] = $true
                
                # Testa o subdomínio
                $isValid = Test-SubdomainEndpoint -testUrl $testUrl -parentWord $word -timeout $localTimeout -allResults $allResults -contentHashes $contentHashes -session $session
                
                if ($isValid) {
                    $validSubdomains += $testUrl
                    Write-Log "Valid subdomain found: $testUrl" "INFO"
                }
            }
            
            # Delay entre requests
            Start-Sleep -Milliseconds (Get-Random -Minimum 50 -Maximum 100)
        }
    }
    finally {
        $TimeoutMsRef.Value = $originalTimeout
        $global:FuzzingStatusCodes = $originalStatusCodes
        Write-Progress -Id 10 -Activity "Completed" -Completed
    }
    
    $foundSubdomains = @()
    foreach ($result in $allResults) {
        if ($result.Type -eq "Subdomain" -and $result.IsValid -eq $true) {
            $foundSubdomains += $result.URL
        }
    }
    
    Write-Log "Subdomain fuzzing completed - Found: $($foundSubdomains.Count) valid subdomains" "INFO"
    
    #return $foundSubdomains
}

function Test-SubdomainEndpoint {
    param($testUrl, $parentWord, $timeout, $allResults, $contentHashes, $session)
    
    try {
        # TENTA HTTP PRIMEIRO (muitos subdomínios não têm HTTPS)
        $httpUrl = $testUrl.Replace("https://", "http://")
        
        # Testa HTTP primeiro
        $httpResult = Test-SingleSubdomain -testUrl $httpUrl -timeout $timeout -parentWord $parentWord -allResults $allResults -contentHashes $contentHashes -session $session
        if ($httpResult -eq $true) {
            return $true
        }
        
        # Se HTTP falhou, testa HTTPS
        $httpsResult = Test-SingleSubdomain -testUrl $testUrl -timeout $timeout -parentWord $parentWord -allResults $allResults -contentHashes $contentHashes -session $session
        if ($httpsResult -eq $true) {
            return $true
        }
        
        return $false
        
    } catch {
        Write-Log "ERRO teste subdominio $testUrl : $($_.Exception.Message)" "DEBUG"
        return $false
    }
}

# =============================================
# FUNÇÕES DE RECURSÃO INTELIGENTE
# =============================================
function Test-Endpoint {
    param($testUrl, $currentDepth, $parentWord, $allResults, $visitedUrls, $contentHashes, $baseSignature, $TimeoutMs, $session)
    
    # VERIFICAÇÃO GLOBAL DE URLS
    $normalizedUrl = $testUrl.ToLower().TrimEnd('/')
    if ($session.GlobalTestedUrls.ContainsKey($normalizedUrl)) {
        $session.IncrementDuplicate()
        $session.LastDuplicateUrl = $testUrl
        return $false
    }
    $session.GlobalTestedUrls[$normalizedUrl] = $true
    
    try {
        $request = [System.Net.WebRequest]::Create($testUrl)
        $request.Timeout = $TimeoutMs
        $request.Method = "GET"
        $request.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        
        $response = $request.GetResponse()
        $statusCode = [int]$response.StatusCode
        $contentLength = $response.ContentLength
        $contentStream = $response.GetResponseStream()
        
        $reader = New-Object System.IO.StreamReader($contentStream)
        $fullContent = $reader.ReadToEnd()
        $reader.Close()
        $response.Close()

        $contentHash = [System.BitConverter]::ToString(
            [System.Security.Cryptography.MD5]::Create().ComputeHash(
                [System.Text.Encoding]::UTF8.GetBytes($fullContent)
            )
        ).Replace("-", "").ToLower()

        # Verificação de conteúdo duplicado
        if ($statusCode -eq 200 -and $contentHashes.ContainsKey($contentHash)) {
            $session.IncrementDuplicate()
            $session.LastDuplicateUrl = $testUrl
            return $false
        }
        
        # Cache de hashes
        if ($statusCode -eq 200 -and $contentLength -gt 100) {
            $contentHashes[$contentHash] = $true
        }

        $isValidEndpoint = Test-RealEndpoint -Url $testUrl -Content $fullContent -ContentLength $contentLength -BaseSignature $baseSignature
        $shouldShow = Test-StatusCodeFilter -StatusCode $statusCode
        
        if ($isValidEndpoint) {
            $title = if ($fullContent -match '<title[^>]*>(.*?)</title>') { 
                $matches[1].Trim() 
            } else { $null }
            
            $result = [PSCustomObject]@{
                URL = $testUrl
                StatusCode = $statusCode
                ContentLength = $contentLength
                Word = $parentWord
                Depth = $currentDepth
                IsValid = $true
                Title = $title
                ContentHash = $contentHash
                Timestamp = Get-Date
                Type = "Path"
            }
            
            $allResults.Add($result)
            $session.IncrementValidEndpoint()
            
            if ($shouldShow) {
                $statusColor = Get-StatusCodeColor -StatusCode $statusCode
                $statusText = Get-StatusCodeText -StatusCode $statusCode
                Write-Host "[PATH $statusText Depth $currentDepth] $testUrl" -ForegroundColor $statusColor
                if ($title) {
                    Write-Host "       Title: $title" -ForegroundColor Magenta
                }
            }
            
            return $true
        } else {
            if ($shouldShow) {
                $statusColor = Get-StatusCodeColor -StatusCode $statusCode
                $statusText = Get-StatusCodeText -StatusCode $statusCode
                Write-Host "[PATH $statusText] $testUrl" -ForegroundColor $statusColor
            }
            return $false
        }
        
    } catch [System.Net.WebException] {
        $webException = $_.Exception
        if ($webException.Response) {
            $statusCode = [int]$webException.Response.StatusCode
            $shouldShow = Test-StatusCodeFilter -StatusCode $statusCode
            
            if ($shouldShow) {
                $statusColor = Get-StatusCodeColor -StatusCode $statusCode
                $statusText = Get-StatusCodeText -StatusCode $statusCode
                Write-Host "[$statusText] $testUrl" -ForegroundColor $statusColor
            } else {
                $session.IncrementFiltered()
            }
        } else {
            if ($global:FuzzingStatusCodes.Count -eq 0) {
                Write-Host "[TIMEOUT] $testUrl" -ForegroundColor DarkYellow
            } else {
                $session.IncrementFiltered()
            }
        }
        return $false
    } catch {
        if ($global:FuzzingStatusCodes.Count -eq 0) {
            Write-Host "[ERROR] $testUrl - $($_.Exception.Message)" -ForegroundColor DarkRed
        } else {
            $session.IncrementFiltered()
        }
        return $false
    } finally {
        $session.IncrementRequest()
    }
}

function Invoke-SmartRecursion {
    param($basePath, $wordList, $currentDepth, $maxDepth, $allResults, $visitedUrls, $contentHashes, $baseSignature, $TimeoutMs, $session)
    
    if ($currentDepth -gt $maxDepth) { 
        Write-Log "Profundidade maxima ($maxDepth) atingida para: $basePath" "INFO"
        return 
    }
    
    Write-Log "Iniciando recursao nivel $currentDepth em: $basePath" "INFO"
    
    $testedCount = 0
    $validPathsThisLevel = @()
    
    # EXTENSÕES DE ARQUIVO COMUNS
    $fileExtensions = @('.jpg', '.jpeg', '.png', '.gif', '.css', '.js', '.pdf', '.zip', '.txt', '.xml', '.json', '.ico', '.php', '.html', '.asp', '.aspx')
    
    foreach ($word in $wordList) {
        $isFile = $false
        $fileExtension = $null
        
        foreach ($ext in $fileExtensions) {
            if ($word.ToLower().EndsWith($ext)) {
                $isFile = $true
                $fileExtension = $ext
                break
            }
        }
        
        # CONSTRUÇÃO DA URL
        $testUrl = if ($basePath.EndsWith('/')) {
            "$basePath$word"
        } else {
            "$basePath/$word"
        }
        
        # VALIDAÇÃO DA URL
        try {
            $null = [System.Uri]$testUrl
        } catch {
            Write-Log "URL inválida: $testUrl" "DEBUG"
            continue
        }
        
        # PROGRESSO DETALHADO
        $testedCount++
        $percentComplete = [math]::Round(($testedCount / $wordList.Count) * 100, 1)
        $stats = $session.GetStatistics()
        
        $elapsedMinutes = [math]::Floor($stats.DurationSeconds / 60)
        $elapsedSeconds = [math]::Round($stats.DurationSeconds % 60)
        $elapsedFormatted = "{0:00}:{1:00}" -f $elapsedMinutes, $elapsedSeconds
        
        # BARRA DE PROGRESSO
        Write-Progress -Id 1 -Activity "RECURSIVE FUZZING - Depth $currentDepth" -Status "Directory: $basePath" -PercentComplete $percentComplete -CurrentOperation "Testing: $word"
        
        Write-Progress -Id 2 -Activity "STATISTICS" -Status "Progress: $testedCount/$($wordList.Count) words | $percentComplete% Complete | Valid: $($stats.ValidEndpoints) endpoints" -ParentId 1
        
        Write-Progress -Id 3 -Activity "TIMING" -Status "Elapsed: $elapsedFormatted | Speed: $($stats.RequestsPerSecond) req/s" -ParentId 1
        
        Write-Progress -Id 4 -Activity "REQUESTS" -Status "Total: $($stats.TotalRequests) requests | Filtered: $($stats.DuplicatesFiltered) duplicates" -ParentId 1
        
        if ($stats.LastDuplicateUrl -and $stats.LastDuplicateUrl -ne "None") {
            Write-Progress -Id 5 -Activity "LAST DUPLICATE FILTERED" -Status "$($stats.LastDuplicateUrl)" -ParentId 1
        }
        
        $isValid = Test-Endpoint -testUrl $testUrl -currentDepth $currentDepth -parentWord $word -allResults $allResults -visitedUrls $visitedUrls -contentHashes $contentHashes -baseSignature $baseSignature -TimeoutMs $TimeoutMs -session $session
        
        if ($isValid) {
            $validPathsThisLevel += @{
                Word = $word
                Url = $testUrl
                IsFile = $isFile
                FileExtension = $fileExtension
            }
            
            if ($isFile -and $fileExtension) {
                Write-Host "       [FILE] $testUrl" -ForegroundColor Cyan
            }
        }
        
        # DELAY ENTRE REQUESTS
        Start-Sleep -Milliseconds (Get-Random -Minimum 50 -Maximum 150)
    }
    
    # LIMPA AS BARRAS DE PROGRESSO
    Write-Progress -Id 1 -Activity "Completed" -Completed
    Write-Progress -Id 2 -Activity "Completed" -Completed
    Write-Progress -Id 3 -Activity "Completed" -Completed
    Write-Progress -Id 4 -Activity "Completed" -Completed
    Write-Progress -Id 5 -Activity "Completed" -Completed
    
    Write-Log "Recursao nivel $currentDepth completada - $testedCount URLs testadas, $($validPathsThisLevel.Count) paths validos encontrados" "INFO"
    
    if ($currentDepth -lt $maxDepth -and $validPathsThisLevel.Count -gt 0) {
        Write-Log "Iniciando recursao para $($validPathsThisLevel.Count) paths validos no nivel $currentDepth" "INFO"
        Write-Host "`n[RECURSION] Found $($validPathsThisLevel.Count) valid paths at depth $currentDepth" -ForegroundColor Yellow
        
        foreach ($validItem in $validPathsThisLevel) {
            $validWord = $validItem.Word
            $validUrl = $validItem.Url
            $isFile = $validItem.IsFile
            $fileExtension = $validItem.FileExtension
            
            if ($isFile) {
                Write-Host "       [SKIP] File detected, no recursion: $validWord" -ForegroundColor DarkGray
                Write-Host "       [FILE] $validUrl" -ForegroundColor Cyan
                continue
            }
            
            Write-Log "Recursando para proximo nivel a partir de: $validWord -> $validUrl" "INFO"
            Write-Host "       -> Recursing to depth $(($currentDepth + 1)) from: $validWord" -ForegroundColor Yellow
            
            Invoke-SmartRecursion -basePath $validUrl -wordList $wordList -currentDepth ($currentDepth + 1) -maxDepth $maxDepth -allResults $allResults -visitedUrls $visitedUrls -contentHashes $contentHashes -baseSignature $baseSignature -TimeoutMs $TimeoutMs -session $session
        }
    } else {
        if ($currentDepth -ge $maxDepth) {
            Write-Log "Profundidade maxima atingida: $maxDepth" "INFO"
        } else {
            Write-Log "Nenhum path valido para recursao no nivel $currentDepth" "INFO"
        }
    }
}

# =============================================
# Fuzzing Functions
# =============================================

function Start-FuzzingRecursive {
    param(
        [string]$url,
        [string]$wordlist,
        [int]$MaxDepth = $global:FuzzingMaxDepth,
        [int]$TimeoutMs = $global:FuzzingTimeoutMs,
        [switch]$Aggressive = $global:FuzzingAggressive,
        [int]$MaxThreads = $global:FuzzingMaxThreads,
        [switch]$SubdomainFuzzing = $global:FuzzingSubdomain
    )

    $session = [FuzzingSession]::new()
    
    try {
        Write-Log "=== INICIANDO FUZZING RECURSIVO AVANcADO ===" "INFO"
        Write-Log "Alvo: $url" "INFO"
        Write-Log "Wordlist: $wordlist" "INFO"
        Write-Log "Profundidade maxima: $MaxDepth" "INFO"
        Write-Log "Timeout: ${TimeoutMs}ms" "INFO"
        
        Write-Host "`n[ADVANCED RECURSIVE FUZZING]" -ForegroundColor Magenta
        Write-Host "   Target: $url" -ForegroundColor White
        Write-Host "   Wordlist: $wordlist" -ForegroundColor White
        
        # MOSTRA CONFIGURAÇÃO ATUAL DE STATUS CODES
        Write-Host "   Status Codes: " -NoNewline -ForegroundColor White
        if ($global:FuzzingStatusCodes.Count -eq 0) {
            Write-Host "ALL (Showing all status codes)" -ForegroundColor Cyan
        } else {
            Write-Host "$($global:FuzzingStatusCodes.Count) codes configured" -ForegroundColor Yellow
        }
        
        if (-not (Test-Path $wordlist)) {
            Write-Log "Wordlist nao encontrada: $wordlist" "ERROR"
            Write-Host "[ERROR] Wordlist not found: $wordlist" -ForegroundColor Red
            return @()
        }

        $words = [System.IO.File]::ReadAllLines($wordlist) | Where-Object { 
            -not [string]::IsNullOrEmpty($_) -and $_.Length -gt 2 
        }
        
        if ($words.Count -eq 0) {
            Write-Log "Nenhuma palavra valida na wordlist: $wordlist" "ERROR"
            Write-Host "[ERROR] No valid words in wordlist" -ForegroundColor Red
            return @()
        }

        Write-Log "Wordlist carregada com $($words.Count) palavras validas" "INFO"

        # CONFIGURAÇÕES INTELIGENTES
        try {
            $baseUri = [System.Uri]$url
            $baseUrl = $baseUri.GetLeftPart([System.UriPartial]::Path)
            $baseHost = $baseUri.Host
        } catch {
            Write-Log "URL invalida: $url - $($_.Exception.Message)" "ERROR"
            Write-Host "[ERROR] Invalid URL: $url" -ForegroundColor Red
            Write-Host "       Details: $($_.Exception.Message)" -ForegroundColor Gray
            return @()
        }
        
        # Garante que a base URL termina com /
        if (-not $baseUrl.EndsWith('/')) {
            $baseUrl += '/'
        }
        
        Write-Log "URL base configurada: $baseUrl" "INFO"
        Write-Log "Host: $baseHost" "INFO"
        
        Write-Host "`n[CONFIGURATION STATUS]" -ForegroundColor Cyan
        
        Write-Host "  " -NoNewline
        Write-Host "(" -NoNewline -ForegroundColor White
        Write-Host "Status" -NoNewline -ForegroundColor Magenta
        Write-Host ")" -NoNewline -ForegroundColor White
        Write-Host " Words: " -NoNewline -ForegroundColor Gray
        Write-Host "$($words.Count)" -ForegroundColor DarkRed

        Write-Host "  " -NoNewline
        Write-Host "(" -NoNewline -ForegroundColor White
        Write-Host "Config" -NoNewline -ForegroundColor Magenta
        Write-Host ")" -NoNewline -ForegroundColor White
        Write-Host " Max Depth: " -NoNewline -ForegroundColor Gray

        if ($MaxDepth -ge 1 -and $MaxDepth -le 2) {
            Write-Host "$($MaxDepth)" -ForegroundColor Yellow
        } elseif ($MaxDepth -ge 3 -and $MaxDepth -le 4) {
            Write-Host "$($MaxDepth)" -ForegroundColor Green
        } elseif ($MaxDepth -ge 5 -and $MaxDepth -le 6) {
            Write-Host "$($MaxDepth)" -ForegroundColor DarkGreen
        } elseif ($MaxDepth -ge 7 -and $MaxDepth -le 8) {
            Write-Host "$($MaxDepth)" -ForegroundColor Red
        } elseif ($MaxDepth -ge 9 -and $MaxDepth -le 10) {
            Write-Host "$($MaxDepth)" -ForegroundColor DarkRed
        } else {
            Write-Host "$($MaxDepth)" -ForegroundColor Gray
        }

        Write-Host "  " -NoNewline
        Write-Host "(" -NoNewline -ForegroundColor White
        Write-Host "Config" -NoNewline -ForegroundColor Magenta
        Write-Host ")" -NoNewline -ForegroundColor White
        Write-Host " Timeout (ms): " -NoNewline -ForegroundColor Gray
        
        if ($global:FuzzingTimeoutMs -ge 500 -and $global:FuzzingTimeoutMs -le 1000) {
            Write-Host "$($global:FuzzingTimeoutMs)" -ForegroundColor DarkRed  # Muito rápido = Alto risco
        } elseif ($global:FuzzingTimeoutMs -ge 1001 -and $global:FuzzingTimeoutMs -le 2000) {
            Write-Host "$($global:FuzzingTimeoutMs)" -ForegroundColor Red      # Rápido = Risco moderado
        } elseif ($global:FuzzingTimeoutMs -ge 2001 -and $global:FuzzingTimeoutMs -le 5000) {
            Write-Host "$($global:FuzzingTimeoutMs)" -ForegroundColor Yellow   # Moderado = Risco baixo
        } elseif ($global:FuzzingTimeoutMs -ge 5001 -and $global:FuzzingTimeoutMs -le 30000) {
            Write-Host "$($global:FuzzingTimeoutMs)" -ForegroundColor Green    # Lento = Baixo risco
        } else {
            Write-Host "$($global:FuzzingTimeoutMs)" -ForegroundColor Gray
        }

        Write-Host "  " -NoNewline
        Write-Host "(" -NoNewline -ForegroundColor White
        Write-Host "Config" -NoNewline -ForegroundColor Magenta
        Write-Host ")" -NoNewline -ForegroundColor White
        Write-Host " Max Threads: " -NoNewline -ForegroundColor Gray
        Write-Host "$($MaxThreads)" -ForegroundColor Yellow

        Write-Host "  " -NoNewline
        Write-Host "(" -NoNewline -ForegroundColor White
        Write-Host "Status" -NoNewline -ForegroundColor Magenta
        Write-Host ")" -NoNewline -ForegroundColor White
        Write-Host " Aggressive Mode: " -NoNewline -ForegroundColor Gray
        Write-Host "$(if ($Aggressive) { 'ENABLED' } else { 'DISABLED' })" -ForegroundColor $(if ($Aggressive) { "Green" } else { "Red" })

        Write-Host "  " -NoNewline
        Write-Host "(" -NoNewline -ForegroundColor White
        Write-Host "Status" -NoNewline -ForegroundColor Magenta
        Write-Host ")" -NoNewline -ForegroundColor White
        Write-Host " Subdomain Fuzzing: " -NoNewline -ForegroundColor Gray
        Write-Host "$(if ($SubdomainFuzzing) { 'ENABLED' } else { 'DISABLED' })" -ForegroundColor $(if ($SubdomainFuzzing) { "Green" } else { "Red" })

        # SISTEMA AVANÇADO DE DETECÇÃO DE BASE - MAIS TOLERANTE
        Write-Log "Analisando pagina base..." "INFO"
        Write-Host "`n[ANALYSIS] Analyzing base page..." -ForegroundColor Green
        
        $baseSignature = Get-PageSignature -Url $url
        
        if (-not $baseSignature -or $baseSignature.StatusCode -ne 200) {
            Write-Log "Pagina base com problemas - Status: $($baseSignature.StatusCode)" "WARNING"
            Write-Host "[WARNING] Base page analysis had issues" -ForegroundColor Yellow
            
            if ($baseSignature) {
                Write-Host "  Status: $($baseSignature.StatusCode)" -ForegroundColor Gray
                Write-Host "  Error: $($baseSignature.Title)" -ForegroundColor Gray
            } else {
                Write-Host "  Could not retrieve base page signature" -ForegroundColor Gray
            }
            
            Write-Host "  Continuing with fallback signature..." -ForegroundColor Yellow
            
            # Criar assinatura fallback robusta
            $baseSignature = @{
                Url = $url
                Title = "Fallback - Base Page Unavailable"
                ContentLength = 0
                ContentHash = "fallback_$(Get-Date -Format 'HHmmss')"
                SampleContent = ""
                StatusCode = 0
                ContentType = "unknown"
            }
            
            Write-Host "  Using fallback base signature" -ForegroundColor Gray
        } else {
            Write-Log "Pagina base analisada - Titulo: '$($baseSignature.Title)', Tamanho: $($baseSignature.ContentLength) chars" "INFO"
            Write-Host "  Base Page: $($baseSignature.Title)" -ForegroundColor Gray
            Write-Host "  Size: $($baseSignature.ContentLength) chars" -ForegroundColor Gray
            Write-Host "  Hash: $($baseSignature.ContentHash)" -ForegroundColor Gray
        }

        # INICIA FUZZING DE SUBDOMÍNIOS (SE HABILITADO)
        if ($SubdomainFuzzing) {
            Write-Host "`n[SUBDOMAIN FUZZING] Starting subdomain discovery..." -ForegroundColor Cyan
            try {
                Invoke-SubdomainFuzzing -baseDomain $baseHost -wordList $words -allResults $session.AllResults -contentHashes $session.ContentHashes -TimeoutMsRef ([ref]$TimeoutMs) -session $session
                
                $foundSubdomains = $session.AllResults | Where-Object { 
                    $_.Type -eq "Subdomain" -and $_.IsValid -eq $true
                }
                
                if ($foundSubdomains.Count -gt 0) {
                    Write-Host "`n[SUBDOMAIN RESULTS] Found $($foundSubdomains.Count) valid subdomains:" -ForegroundColor Green
                    
                    # SEU CÓDIGO DE REPORTING ATUAL JÁ É EXCELENTE - MANTENHA!
                    Write-Host "   Subdomains found:" -ForegroundColor Gray
                    foreach ($sub in $foundSubdomains) {
                        Write-Host "     - $($sub.URL)" -ForegroundColor Yellow
                        
                        # Adicionar informações extras se disponíveis
                        if ($sub.Title -and $sub.Title -ne "No Title") {
                            Write-Host "         Title: $($sub.Title)" -ForegroundColor Magenta
                        }
                        if ($sub.ContentLength -gt 0) {
                            Write-Host "         Size: $($sub.ContentLength) bytes" -ForegroundColor Gray
                        }
                        if ($sub.StatusCode -ne 200) {
                            $statusColor = Get-StatusCodeColor -StatusCode $sub.StatusCode
                            $statusText = Get-StatusCodeText -StatusCode $sub.StatusCode
                            Write-Host "         Status: $statusText" -ForegroundColor $statusColor
                        }
                    }
                    
                    # Estatísticas dos subdomínios
                    $uniqueStatusCodes = $foundSubdomains.StatusCode | Sort-Object -Unique
                    Write-Host "`n   Summary:" -ForegroundColor Cyan
                    Write-Host "     Total valid subdomains: $($foundSubdomains.Count)" -ForegroundColor White
                    Write-Host "     Status codes found: $($uniqueStatusCodes -join ', ')" -ForegroundColor White
                    
                } else {
                    Write-Host "`n[SUBDOMAIN RESULTS] No valid subdomains found" -ForegroundColor Yellow
                    Write-Host "   All subdomains timed out or returned errors" -ForegroundColor Gray
                    
                    # Mostrar estatísticas mesmo quando não encontrar subdomínios válidos
                    $allSubdomains = $session.AllResults | Where-Object { $_.Type -eq "Subdomain" }
                    if ($allSubdomains.Count -gt 0) {
                        $statusCount = $allSubdomains | Group-Object StatusCode | ForEach-Object {
                            "$($_.Name): $($_.Count)"
                        }
                        Write-Host "   Responses received: $($statusCount -join ', ')" -ForegroundColor DarkGray
                    }
                }
                
            } catch {
                Write-Log "Erro no subdomain fuzzing: $($_.Exception.Message)" "ERROR"
                Write-Host "[ERROR] Subdomain fuzzing failed: $($_.Exception.Message)" -ForegroundColor Red
                Write-Host "   Continuing with main fuzzing..." -ForegroundColor Yellow
            }
        }

        # INICIA FUZZING PRINCIPAL - MESMO COM BASE SIGNATURE PROBLEMÁTICA
        Write-Log "INICIANDO SCAN RECURSIVO PRINCIPAL" "INFO"
        Write-Host "`n[FUZZING] Starting smart recursive scan..." -ForegroundColor Magenta
        
        if ($global:FuzzingStatusCodes.Count -gt 0) {
            Write-Host "          Showing only: " -NoNewline -ForegroundColor Gray
            foreach ($code in $global:FuzzingStatusCodes) {
                $color = Get-StatusCodeColor -StatusCode $code
                $text = Get-StatusCodeText -StatusCode $code
                Write-Host "$text " -NoNewline -ForegroundColor $color
            }
            Write-Host ""
        }
        Write-Host "                   (Duplicates and filtered status codes are shown in dark gray)`n" -ForegroundColor Gray
        
        $basePath = $baseUrl
        
        Write-Host "   Base Path: $basePath" -ForegroundColor Gray
        Write-Host "   Starting recursion with $($words.Count) words, depth: $MaxDepth" -ForegroundColor Gray
        
        try {
            Invoke-SmartRecursion -basePath $basePath -wordList $words -currentDepth 1 -maxDepth $MaxDepth -allResults $session.AllResults -visitedUrls $session.VisitedUrls -contentHashes $session.ContentHashes -baseSignature $baseSignature -TimeoutMs $TimeoutMs -session $session
        } catch {
            Write-Log "Erro no recursive fuzzing: $($_.Exception.Message)" "ERROR"
            Write-Host "[ERROR] Recursive fuzzing failed: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "   Partial results will be shown..." -ForegroundColor Yellow
        }

        $stats = $session.GetStatistics()
        
        Write-Log "SCAN CONCLUIDO - Total de requests: $($stats.TotalRequests)" "INFO"
        Write-Log "SCAN CONCLUIDO - Endpoints validos: $($stats.ValidEndpoints)" "INFO"
        Write-Log "SCAN CONCLUIDO - Duplicatas filtradas: $($stats.DuplicatesFiltered)" "INFO"
        Write-Log "SCAN CONCLUIDO - Filtrados por status: $($stats.FilteredByStatus)" "INFO"
        Write-Log "SCAN CONCLUIDO - Eficiencia: $($stats.EfficiencyRate)%" "INFO"

        Write-Host "`n[SCAN COMPLETE]" -ForegroundColor Green
        Write-Host "   Total Requests: $($stats.TotalRequests)" -ForegroundColor White
        Write-Host "   Valid Endpoints: $($stats.ValidEndpoints)" -ForegroundColor Cyan
        Write-Host "   Duplicates Filtered: $($stats.DuplicatesFiltered)" -ForegroundColor DarkYellow
        Write-Host "   Filtered by Status: $($stats.FilteredByStatus)" -ForegroundColor Yellow
        Write-Host "   Duration: $([math]::Round($stats.DurationSeconds, 1))s" -ForegroundColor White
        Write-Host "   Speed: $([math]::Round($stats.RequestsPerSecond, 1)) req/s" -ForegroundColor White
        Write-Host "   Efficiency: $([math]::Round($stats.EfficiencyRate, 1))%" -ForegroundColor $(if ($stats.EfficiencyRate -gt 5) { "Green" } elseif ($stats.EfficiencyRate -gt 1) { "Yellow" } else { "Red" })

        # FILTRA RESULTADOS FINAIS PELA CONFIGURAÇÃO DE STATUS CODES
        if ($global:FuzzingStatusCodes.Count -gt 0) {
            $finalResults = $session.AllResults | Where-Object { $global:FuzzingStatusCodes -contains $_.StatusCode } | Sort-Object Depth, StatusCode | Select-Object -Unique
        } else {
            $finalResults = $session.AllResults | Sort-Object Depth, StatusCode | Select-Object -Unique
        }
        
        if ($finalResults.Count -gt 0) {
            Write-Log "RELATORIO FINAL: $($finalResults.Count) endpoints validos encontrados (apos filtro)" "INFO"
            Write-Host "`n[VALID ENDPOINTS FOUND]:" -ForegroundColor Green
            
            # Agrupa por tipo para melhor organização
            $subdomainResults = $finalResults | Where-Object { $_.Type -eq "Subdomain" -and $_.IsValid -eq $true }
            $pathResults = $finalResults | Where-Object { $_.Type -eq "Path" -and $_.IsValid -eq $true }
            
            if ($subdomainResults.Count -gt 0) {
                Write-Host "`n  [SUBDOMAINS] ($($subdomainResults.Count)):" -ForegroundColor Cyan
                foreach ($result in $subdomainResults) {
                    $statusColor = Get-StatusCodeColor -StatusCode $result.StatusCode
                    $statusText = Get-StatusCodeText -StatusCode $result.StatusCode
                    
                    Write-Host "    [$statusText] " -NoNewline -ForegroundColor $statusColor
                    Write-Host "$($result.URL)" -ForegroundColor White
                    if ($result.Title -and $result.Title -ne "No Title") {
                        Write-Host "         Title: $($result.Title)" -ForegroundColor Magenta
                    }
                    if ($result.ContentLength -gt 0) {
                        Write-Host "         Size: $($result.ContentLength) bytes" -ForegroundColor Gray
                    }
                }
            }
            
            if ($pathResults.Count -gt 0) {
                Write-Host "`n  [PATHS] ($($pathResults.Count)):" -ForegroundColor Cyan
                foreach ($result in $pathResults) {
                    $statusColor = Get-StatusCodeColor -StatusCode $result.StatusCode
                    $statusText = Get-StatusCodeText -StatusCode $result.StatusCode
                    
                    Write-Host "    [$statusText] " -NoNewline -ForegroundColor $statusColor
                    Write-Host "Depth $($result.Depth) - $($result.URL)" -ForegroundColor White
                    if ($result.Title -and $result.Title -ne "No Title") {
                        Write-Host "         Title: $($result.Title)" -ForegroundColor Magenta
                    }
                    if ($result.ContentLength -gt 0) {
                        Write-Host "         Size: $($result.ContentLength) bytes" -ForegroundColor Gray
                    }
                }
            }
            
            # Salva resultados em arquivo
            $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
            $resultsFile = "fuzzing_results_${timestamp}.csv"
            
            try {
                $finalResults | Export-Csv -Path $resultsFile -NoTypeInformation -Encoding UTF8
                Write-Log "Resultados salvos em: $resultsFile" "INFO"
                Write-Host "`n   Results saved to: $resultsFile" -ForegroundColor Gray
            } catch {
                Write-Log "Erro ao salvar resultados: $($_.Exception.Message)" "ERROR"
                Write-Host "   [WARNING] Could not save results to file" -ForegroundColor Yellow
            }
            
            return $finalResults
        } else {
            Write-Log "Nenhum endpoint valido encontrado apos filtro" "INFO"
            Write-Host "`n[RESULTS] No real endpoints found (after status code filtering)" -ForegroundColor Yellow
            Write-Host "   Try adjusting timeout, status codes, or using a different wordlist" -ForegroundColor Gray
            return @()
        }

    } catch {
        Write-Log "ERRO FATAL em Start-FuzzingRecursive: $($_.Exception.Message)" "ERROR"
        Write-Log "Stack trace: $($_.Exception.StackTrace)" "DEBUG"
        Write-Host "[FATAL ERROR] $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "   Check the logs for more details" -ForegroundColor Gray
        return @()
    } finally {
        Write-Log "=== FUZZING RECURSIVO FINALIZADO ===" "INFO"
        Write-Host "`n[FINAL] Fuzzing session completed" -ForegroundColor DarkGreen
    }
}

# =============================================
# FUNÇÕES DE EXECUÇÃO E MENU
# =============================================

function RunAllScans {
    param ([string]$url)
    
    clear-host
    Logo_Menu
    Write-Host "`n                                                              === Starting all checks for URL: $url ===`n" -ForegroundColor Red
    Write-Log "Starting RunAllScans for: $url"
    
    # Uses the GLOBAL configuration saved
    $scansToRun = $global:ScansConfig
    
    if ($scansToRun.Count -eq 0) {
        Write-Host "No scans enabled! Please configure the scans first." -ForegroundColor Red
        Write-Host "`nPress Enter to continue..." -ForegroundColor Gray
        $null = Read-Host
        return
    }
    
    # Prepara a lista de scans para exibição (todos os scans com status)
    $scansForDisplay = $global:AllScans.Clone()
    foreach ($scan in $scansForDisplay) {
        # Marca como habilitado se estiver na configuração
        $scan.Enabled = if ($scansToRun.Name -contains $scan.Name) { 1 } else { 0 }
    }
    
    $width = 180

    # formata o índice para que números de 1 digito e 2 digitos fiquem alinhados
    $indexFormat = '{0,2}. {1}'

    # calcula a linha "entry" mais longa (sem o status)
    $entries = for ($i = 0; $i -lt $scansForDisplay.Count; $i++) {
        $scan = $scansForDisplay[$i]
        $index = $i + 1
        $entry = $indexFormat -f $index, $scan.Name
        $entry
    }

    $maxEntryLength = ($entries | ForEach-Object { $_.Length } | Measure-Object -Maximum).Maximum
    $statusLength = 3
    $blockWidth = $maxEntryLength + 1 + $statusLength
    $leftPaddingBase = [Math]::Max(0, [Math]::Floor(($width - $blockWidth) / 2))

    # EXIBE O MENU DOS SCANS (igual ao Set-ScansInteractive)
    Write-Host "`n`n                                                                                 Scan Selected's:`n" -ForegroundColor DarkRed
    
    for ($i = 0; $i -lt $scansForDisplay.Count; $i++) {
        $scan = $scansForDisplay[$i]
        $index = $i + 1
        $entry = $indexFormat -f $index, $scan.Name
        $statusText = if ($scan.Enabled -eq 1) { '[1]' } else { '[0]' }
        $innerPadLength = ($maxEntryLength - $entry.Length) + 1
        if ($innerPadLength -lt 1) { $innerPadLength = 1 }
        $innerPadding = ' ' * $innerPadLength
        $leftPadding = ' ' * $leftPaddingBase

        Write-Host -NoNewline ($leftPadding + $entry + $innerPadding)
        if ($scan.Enabled -eq 1) {
            Write-Host $statusText -ForegroundColor Green
        } else {
            Write-Host $statusText -ForegroundColor Red
        }
    }
    
    Write-Host "`n`n               Auto Fuzzing Mode: $(if ($global:AutoFuzzingMode -eq 1) { 'ENABLED' } else { 'DISABLED' })" -ForegroundColor $(if ($global:AutoFuzzingMode -eq 1) { "Green" } else { "Red" })
    
    Write-Host "`n               tip: You can configure the scans in the configuration Sub-Menu - Option [0] ." -ForegroundColor Yellow      
    Write-Host ""
    
    Start-Sleep -Seconds 3

    $counter = 0
    $fuzzingResult = $null
    $scanHTMLExecuted = $false
    
    foreach ($scan in $scansToRun) {
        $counter++
        Write-Host "`n`n=== $counter. $($scan.Name) ===" -ForegroundColor Gray
        
        if ($scan.Name -eq "Words for Fuzzing") {
            try {
                Write-Host "Executing Words for Fuzzing (this will be used for Auto Fuzzing if enabled)..." -ForegroundColor Cyan
                $fuzzingResult = & $scan.Function $url
                $scanHTMLExecuted = $true
                
                if ($fuzzingResult -and $fuzzingResult.SavedFilePath) {
                    # Write-Host "`nWordlist available at: $($fuzzingResult.SavedFilePath)" -ForegroundColor Green
                    # Write-Host "Total words extracted: $($fuzzingResult.TotalWords)" -ForegroundColor White
                    Write-Log "Words for Fuzzing completed. Total words: $($fuzzingResult.TotalWords), File: $($fuzzingResult.SavedFilePath)" "INFO"
                } else {
                    Write-Host "Wordlist NOT saved but Auto Fuzzing will use temporary file if needed" -ForegroundColor Yellow
                    Write-Host "Total words extracted: $($fuzzingResult.TotalWords)" -ForegroundColor White
                }
                
            } catch {
                Write-Host "Error while executing Words for Fuzzing: $($_.Exception.Message)" -ForegroundColor Red
                Write-Log "Error in Words for Fuzzing: $($_.Exception.Message)" "ERROR"
            }
        } else {
            # Execução normal para outros scans
            try {
                & $scan.Function $url
            } catch {
                Write-Host "Error while executing scan: $($_.Exception.Message)" -ForegroundColor Red
                Write-Log "Error in $($scan.Name): $($_.Exception.Message)" "ERROR"
            }
        }
            
        Start-Sleep -Milliseconds 300
    }
    
    Write-Host "`n`n        === CHECKING AUTO FUZZING MODE ===`n" -ForegroundColor Magenta
    
    if ($global:AutoFuzzingMode -eq 1) {
        Write-Host "Auto Fuzzing Mode: ENABLED" -ForegroundColor Green
        
        if ($scanHTMLExecuted -and $fuzzingResult -and $fuzzingResult.TotalWords -gt 0) {
            Write-Host "Words for Fuzzing: EXECUTED`n" -ForegroundColor Green
            #Write-Host "Total words: $($fuzzingResult.TotalWords)" -ForegroundColor White

            if ($fuzzingResult.SavedFilePath -and (Test-Path $fuzzingResult.SavedFilePath)) {
                Write-Host "Wordlist file: FOUND ($($fuzzingResult.SavedFilePath))" -ForegroundColor Green
                $wordlistPath = $fuzzingResult.SavedFilePath
            } else {
                Write-Host "Wordlist file: NOT SAVED, creating temporary file..." -ForegroundColor Yellow
                
                $tempDir = "Fuzz_files"
                if (-not (Test-Path $tempDir)) {
                    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
                }
                
                $tempWordlist = Join-Path $tempDir "temp_autofuzz_$(Get-Date -Format 'HHmmss').txt"
                $fuzzingResult.Words | Out-File -FilePath $tempWordlist -Encoding UTF8
                $wordlistPath = $tempWordlist
                
                Write-Host "Temporary wordlist created: $tempWordlist" -ForegroundColor Green
            }

            Write-Host "`n          === STARTING AUTO FUZZING ===`n" -ForegroundColor Magenta
            Write-Host "Launching recursive fuzzing with generated wordlist..." -ForegroundColor Yellow
            
            Start-Sleep -Seconds 2
            
            # Executa o fuzzing recursivo
            Start-FuzzingRecursive -url $url -wordlist $wordlistPath
            
            if ($wordlistPath -like "*temp_autofuzz_*" -and (Test-Path $wordlistPath)) {
                Remove-Item $wordlistPath -Force
                Write-Host "Temporary wordlist cleaned up: $wordlistPath" -ForegroundColor Gray
            }
            
        } else {
            Write-Host "Words for Fuzzing: NOT EXECUTED OR FAILED  Active in Submenu (0 , 3 , 14)." -ForegroundColor Red
            Write-Host "Auto Fuzzing skipped - make sure 'Words for Fuzzing' scan is enabled and words were extracted." -ForegroundColor Yellow
        }
    } else {
        Write-Host "Auto Fuzzing Mode: DISABLED, Active in Submenu (0 , 4)." -ForegroundColor Red
        Write-Host "No automatic fuzzing will be performed." -ForegroundColor Gray
    }
    
    Write-Host "`n                                                                               === All checks completed ===`n" -ForegroundColor DarkGreen
    Write-Log "RunAllScans completed for: $url"
    Write-Host "`nPress Enter to continue..." -ForegroundColor Gray
    $null = Read-Host
}

function Help {
    Clear-Host
    Logo_Menu
    Write-Host "`n                                                                          ==== HELP - PowerDiNSpec v2.3.0 ====`n" -ForegroundColor Red

    Write-Host "`n  POWERDINSPEC - Advanced PowerShell Reconnaissance Toolkit" -ForegroundColor Yellow
    Write-Host "`n  PowerDiNSpec is a comprehensive PowerShell-based reconnaissance toolkit for" -ForegroundColor White
    Write-Host "  websites and DNS infrastructure. Designed for security professionals, researchers," -ForegroundColor White
    Write-Host "  and penetration testers conducting authorized security assessments." -ForegroundColor White
    
    Write-Host "`n  OVERVIEW" -ForegroundColor Cyan
    Write-Host "    PowerDiNSpec automates multiple reconnaissance techniques against web targets," -ForegroundColor White
    Write-Host "    providing essential information gathering capabilities for security assessments." -ForegroundColor White
    Write-Host "    Each scan is designed to be non-invasive but may trigger security monitoring." -ForegroundColor White

    Write-Host "`n  CORE FEATURES" -ForegroundColor Cyan   
    
    Write-Host "`n    WEB RECONNAISSANCE" -ForegroundColor Magenta
    Write-Host "    [1] HTTP Status Code Analysis" -ForegroundColor Green
    Write-Host "        Retrieves and analyzes HTTP response codes with color-coded categorization" -ForegroundColor White
    Write-Host "        and identifies redirect patterns, client/server errors." -ForegroundColor Gray
    
    Write-Host "    [2] Page Title Extraction" -ForegroundColor Green
    Write-Host "        Extracts and analyzes HTML page titles with length analysis for quick" -ForegroundColor White
    Write-Host "        content identification and target verification." -ForegroundColor Gray
    
    Write-Host "    [4] HTTP Methods Discovery" -ForegroundColor Green
    Write-Host "        Enumerates allowed HTTP methods (GET, POST, PUT, DELETE, OPTIONS) with" -ForegroundColor White
    Write-Host "        risk assessment for dangerous methods like PUT and DELETE." -ForegroundColor Gray
    
    Write-Host "    [5] Server Headers Analysis" -ForegroundColor Green
    Write-Host "        Captures and analyzes HTTP response headers including Server, X-Powered-By," -ForegroundColor White
    Write-Host "        and framework-specific headers for comprehensive technology fingerprinting." -ForegroundColor Gray
    
    Write-Host "    [6] Technology Detection" -ForegroundColor Green
    Write-Host "        Advanced fingerprinting of web technologies, frameworks (React, jQuery)," -ForegroundColor White
    Write-Host "        CMS platforms (WordPress, Drupal, Joomla), and server software." -ForegroundColor Gray
    
    Write-Host "    [7] Security Headers Analysis" -ForegroundColor Green
    Write-Host "        Comprehensive security headers audit with scoring system:" -ForegroundColor White
    Write-Host "        - Content-Security-Policy, Strict-Transport-Security" -ForegroundColor Gray
    Write-Host "        - X-Frame-Options, X-Content-Type-Options, Referrer-Policy" -ForegroundColor Gray
    Write-Host "        - Security scoring and vulnerability identification" -ForegroundColor Gray
    
    Write-Host "    [10] HTML Link Discovery" -ForegroundColor Green
    Write-Host "        Extracts all HTTP/HTTPS links from page content to map internal and" -ForegroundColor White
    Write-Host "        external resources, identifying potential attack surface expansion." -ForegroundColor Gray
    
    Write-Host "    [11] Robots.txt Analysis" -ForegroundColor Green
    Write-Host "        Comprehensive robots.txt analysis with sensitive path detection," -ForegroundColor White
    Write-Host "        user-agent targeting, and disallowed directory identification." -ForegroundColor Gray
    
    Write-Host "    [12] Sitemap Discovery" -ForegroundColor Green
    Write-Host "        XML sitemap analysis with URL categorization (images, PDFs, admin," -ForegroundColor White
    Write-Host "        API endpoints) and interesting path identification." -ForegroundColor Gray

    Write-Host "`n    DNS & NETWORK RECONNAISSANCE" -ForegroundColor Magenta
    Write-Host "    [3] DNS IP Resolution" -ForegroundColor Green
    Write-Host "        Performs comprehensive DNS lookups for both IPv4 (A) and IPv6 (AAAA)" -ForegroundColor White
    Write-Host "        records, revealing the target's complete IP infrastructure." -ForegroundColor Gray
    
    Write-Host "    [8] DNS Zone Transfer Test" -ForegroundColor Green
    Write-Host "        Tests DNS servers for zone transfer vulnerabilities that could" -ForegroundColor White
    Write-Host "        expose all DNS records of the domain in misconfigured environments." -ForegroundColor Gray
    
    Write-Host "    [9] Comprehensive DNS Records" -ForegroundColor Green
    Write-Host "        Extensive DNS reconnaissance including all record types:" -ForegroundColor White
    Write-Host "        - MX Records  - Mail server infrastructure" -ForegroundColor Gray
    Write-Host "        - NS Records  - Name server architecture" -ForegroundColor Gray
    Write-Host "        - SOA Records - Zone authority and administrative info" -ForegroundColor Gray
    Write-Host "        - CNAME Records - Canonical name mappings and aliases" -ForegroundColor Gray
    Write-Host "        - TXT Records - SPF, DKIM, DMARC, verification records" -ForegroundColor Gray
    Write-Host "        - PTR Records - Reverse DNS lookups for discovered IPs" -ForegroundColor Gray
    
    Write-Host "    [13] Port Banner Grabbing" -ForegroundColor Green
    Write-Host "        Advanced service detection on multiple ports with intelligent presets:" -ForegroundColor White
    Write-Host "        - Common Services: 21,22,80,443,3306,3389,5432,8080" -ForegroundColor Gray
    Write-Host "        - Web Services: 80,443,8080,8443,8888,9090" -ForegroundColor Gray
    Write-Host "        - Database Ports: 1433,1521,3306,5432,27017,6379" -ForegroundColor Gray
    Write-Host "        - Email Services: 25,110,143,465,587,993,995" -ForegroundColor Gray
    Write-Host "        - Custom port ranges and full 1-65535 scanning supported" -ForegroundColor Gray

    Write-Host "`n    ADVANCED FUZZING & DISCOVERY" -ForegroundColor Magenta
    Write-Host "    [14] Wordlist Generation for Fuzzing" -ForegroundColor Green
    Write-Host "        Extracts unique words from HTML content to create customized, target-specific" -ForegroundColor White
    Write-Host "        wordlists for directory brute-forcing and content discovery." -ForegroundColor Gray
    
    Write-Host "    [15] Recursive Directory Fuzzing" -ForegroundColor Green
    Write-Host "        Advanced recursive directory discovery with intelligent features:" -ForegroundColor White
    Write-Host "        - Configurable depth levels (1-10)" -ForegroundColor Gray
    Write-Host "        - Hash-based duplicate content filtering" -ForegroundColor Gray
    Write-Host "        - Real-time progress tracking and statistics" -ForegroundColor Gray
    Write-Host "        - Smart false-positive detection" -ForegroundColor Gray
    Write-Host "        - Status code filtering and customization" -ForegroundColor Gray
    
    Write-Host "    [16] Run All Scans" -ForegroundColor Green
    Write-Host "        Executes comprehensive sequential assessment using configured scans" -ForegroundColor White
    Write-Host "        with real-time progress display and automated fuzzing pipeline." -ForegroundColor Gray

    Write-Host "`n  NEW FEATURES IN v2.2.5" -ForegroundColor Cyan
    Write-Host "    Auto Fuzzing Mode" -ForegroundColor White
    Write-Host "        Automatic recursive fuzzing pipeline after word extraction" -ForegroundColor Gray
    
    Write-Host "    Enhanced Port Discovery" -ForegroundColor White
    Write-Host "        Intelligent port detection from HTML content and auto-testing" -ForegroundColor Gray
    
    Write-Host "    Advanced Progress Tracking" -ForegroundColor White
    Write-Host "        Real-time progress bars, speed metrics, and request statistics" -ForegroundColor Gray
    
    Write-Host "    Smart Filtering System" -ForegroundColor White
    Write-Host "        Hash-based duplicate detection and false-positive reduction" -ForegroundColor Gray
    
    Write-Host "    Granular Configuration" -ForegroundColor White
    Write-Host "        Customizable timeouts, threads, depth, and status code filters" -ForegroundColor Gray

    Write-Host "`n  CONFIGURATION PRESETS" -ForegroundColor Cyan
    Write-Host "    Quick setup with optimized scan profiles for different scenarios:" -ForegroundColor White
    
    Write-Host "    Basic Recon" -ForegroundColor Green
    Write-Host "        Essential information gathering (Status, Title, IP, Headers, Technologies)" -ForegroundColor Gray
    
    Write-Host "    Web Application" -ForegroundColor Blue
    Write-Host "        Focus on web app security (Status, Methods, Headers, Links, Technologies)" -ForegroundColor Gray
    
    Write-Host "    Network & DNS" -ForegroundColor Yellow
    Write-Host "        Infrastructure reconnaissance (IP, Zone Transfer, DNS Records, Ports)" -ForegroundColor Gray
    
    Write-Host "    Content Discovery" -ForegroundColor Magenta
    Write-Host "        Directory and file enumeration (Links, Robots, Sitemap, Words)" -ForegroundColor Gray
    
    Write-Host "    Security Audit" -ForegroundColor Red
    Write-Host "        Comprehensive security checks (Headers, Methods, Security, Zone Transfer)" -ForegroundColor Gray
    
    Write-Host "    Stealth Mode" -ForegroundColor DarkGray
    Write-Host "        Minimal detection, maximum information gathering" -ForegroundColor Gray
    
    Write-Host "    Penetration Test" -ForegroundColor Cyan
    Write-Host "        Full aggressive assessment with all scans enabled" -ForegroundColor Gray

    Write-Host "`n  OUTPUT & LOGGING SYSTEM" -ForegroundColor Cyan
    Write-Host "    Structured output with comprehensive logging capabilities:" -ForegroundColor White
    
    Write-Host "    Console Output" -ForegroundColor White
    Write-Host "        - Color-coded results based on status codes and severity" -ForegroundColor Gray
    Write-Host "        - Real-time progress indicators and statistics" -ForegroundColor Gray
    Write-Host "        - Formatted tables and hierarchical information display" -ForegroundColor Gray
    
    Write-Host "    File System Organization" -ForegroundColor White
    Write-Host "        - Logs_PowerDns/ - Timestamped scan logs and activity records" -ForegroundColor Gray
    Write-Host "        - Fuzz_files/ - Generated wordlists for fuzzing operations" -ForegroundColor Gray
    Write-Host "        - CSV exports - Fuzzing results and discovered endpoints" -ForegroundColor Gray
    
    Write-Host "    Analytics & Metrics" -ForegroundColor White
    Write-Host "        - Request speed and success rates" -ForegroundColor Gray
    Write-Host "        - Duplicate filtering statistics" -ForegroundColor Gray
    Write-Host "        - Scan duration and performance metrics" -ForegroundColor Gray

    Write-Host "`n  PERFORMANCE OPTIMIZATIONS" -ForegroundColor Cyan
    Write-Host "    Engineered for efficiency and speed in large-scale assessments:" -ForegroundColor White
    
    Write-Host "    Parallel Processing" -ForegroundColor White
    Write-Host "        Configurable multi-threading for faster scanning" -ForegroundColor Gray
    
    Write-Host "    Intelligent Caching" -ForegroundColor White
    Write-Host "        Hash-based content deduplication and visited URL tracking" -ForegroundColor Gray
    
    Write-Host "    Adaptive Timeouts" -ForegroundColor White
    Write-Host "        Configurable timeouts and delays for different network conditions" -ForegroundColor Gray
    
    Write-Host "    Memory Management" -ForegroundColor White
    Write-Host "        Efficient processing of large wordlists and result sets" -ForegroundColor Gray
    
    Write-Host "    Progressive Display" -ForegroundColor White
    Write-Host "        Real-time results without blocking operation" -ForegroundColor Gray

    Write-Host "`n  SECURITY, ETHICS AND LEGAL NOTICE" -ForegroundColor Red
    Write-Host "    [CRITICAL] USE ONLY WITH EXPLICIT AUTHORIZATION" -ForegroundColor Yellow
    Write-Host "`n    PowerDiNSpec is designed for legitimate security purposes:" -ForegroundColor White
    Write-Host "    Authorized penetration testing with written permission" -ForegroundColor Green
    Write-Host "    Security research in controlled lab environments" -ForegroundColor Green
    Write-Host "    Educational purposes and cybersecurity training" -ForegroundColor Green
    Write-Host "    Bug bounty programs within explicitly defined scope" -ForegroundColor Green
    Write-Host "    Internal security assessments on owned infrastructure" -ForegroundColor Green

    Write-Host "`n    STRICTLY PROHIBITED ACTIVITIES:" -ForegroundColor Red
    Write-Host "    Scanning systems without explicit written permission" -ForegroundColor Gray
    Write-Host "    Testing outside of authorized scope boundaries" -ForegroundColor Gray
    Write-Host "    Malicious or unauthorized intrusion attempts" -ForegroundColor Gray
    Write-Host "    Network disruption or denial of service attacks" -ForegroundColor Gray
    Write-Host "    Privacy violations or unauthorized data access" -ForegroundColor Gray

    Write-Host "`n    LEGAL RESPONSIBILITY:" -ForegroundColor Yellow
    Write-Host "    You are solely responsible for ensuring proper authorization and" -ForegroundColor White
    Write-Host "    compliance with all applicable laws, regulations, and organizational" -ForegroundColor White
    Write-Host "    policies. Unauthorized use may result in legal consequences." -ForegroundColor White

    Write-Host "`n  INSTALLATION & USAGE" -ForegroundColor Cyan
    Write-Host "    Requirements:" -ForegroundColor White
    Write-Host "    - Windows PowerShell 5.1 or newer" -ForegroundColor Gray
    Write-Host "    - Internet connectivity for target access" -ForegroundColor Gray
    Write-Host "    - Appropriate execution policy settings" -ForegroundColor Gray
    Write-Host "    - Administrative privileges for some scans" -ForegroundColor Gray
    
    Write-Host "`n    Quick Start:" -ForegroundColor White
    Write-Host "    1. Configure scans (Option 0 -> Configure Scans)" -ForegroundColor Gray
    Write-Host "    2. Set port ranges (Option 0 -> Configure Ports)" -ForegroundColor Gray
    Write-Host "    3. Enable Auto Fuzzing if desired (Option 0 -> Auto Fuzzing)" -ForegroundColor Gray
    Write-Host "    4. Configure fuzzing parameters (Option 0 -> Fuzzing Recursive)" -ForegroundColor Gray
    Write-Host "    5. Run individual scans or complete assessment" -ForegroundColor Gray
    Write-Host "    6. Review logs in Logs_PowerDns/ directory" -ForegroundColor Gray
    Write-Host "    7. Check Fuzz_files/ for generated wordlists" -ForegroundColor Gray

    Write-Host "`n  TIPS & BEST PRACTICES" -ForegroundColor Cyan
    Write-Host "    - Start with Basic Recon preset for initial assessment" -ForegroundColor White
    Write-Host "    - Use Stealth Mode for sensitive environments" -ForegroundColor White
    Write-Host "    - Enable Auto Fuzzing for comprehensive directory discovery" -ForegroundColor White
    Write-Host "    - Monitor scan progress and adjust timeouts as needed" -ForegroundColor White
    Write-Host "    - Review logs for detailed scan information and troubleshooting" -ForegroundColor White
    Write-Host "    - Customize port ranges based on target environment" -ForegroundColor White
    Write-Host "    - Use status code filtering to reduce noise in fuzzing results" -ForegroundColor White
    Write-Host "    - Configure appropriate thread counts for your network bandwidth" -ForegroundColor White

    Write-Host "`n  CREDITS" -ForegroundColor Cyan
    Write-Host "    - Author: Luan Calazans (2025)" -ForegroundColor White
    Write-Host "    - PowerShell-based toolkit design and implementation: Luan Calazans" -ForegroundColor White
    Write-Host "    - Menu ASCII fonts and artwork assistance: WriteAscii project" -ForegroundColor White
    Write-Host "      Font and artwork source: https://github.com/EliteLoser/WriteAscii/blob/master/letters.xml" -ForegroundColor White
    Write-Host "    - Community contributions and testing" -ForegroundColor White

    Write-Host "`n  LICENSE" -ForegroundColor Cyan
    Write-Host "    GNU Affero General Public License v3.0" -ForegroundColor White
    Write-Host "    This program is free software: you can redistribute it and/or modify" -ForegroundColor Gray
    Write-Host "    it under the terms of the GNU AGPLv3. See LICENSE file for details." -ForegroundColor Gray

    Write-Host "`n  REPOSITORY & SUPPORT" -ForegroundColor Cyan
    Write-Host "    GitHub: https://github.com/Luanqmata/PowerDiNSpec" -ForegroundColor White
    Write-Host "    Issues and contributions welcome via GitHub repository." -ForegroundColor Gray
    Write-Host "    Documentation: Included in help system and repository wiki" -ForegroundColor Gray

    Write-Host "`n  VERSION INFORMATION" -ForegroundColor Cyan
    Write-Host "    Current Version: 2.2.5" -ForegroundColor White
    Write-Host "    Release Date: 2025" -ForegroundColor White
    Write-Host "    Compatibility: Windows PowerShell 5.1+" -ForegroundColor White

    Write-Host "`n  FINAL REMINDER" -ForegroundColor Red
    Write-Host "    USE RESPONSIBLY - GET AUTHORIZATION - RESPECT PRIVACY - FOLLOW ETHICS" -ForegroundColor Yellow
    Write-Host "    This tool is for defensive security purposes only." -ForegroundColor White
    Write-Host "    Your actions are your responsibility - always obtain proper authorization." -ForegroundColor White

    Write-Host "`n  Press Enter to return to the submenu..." -ForegroundColor DarkGray
    $null = Read-Host
}

function PowerDiNSpec {
    $logFile = "scan_log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    # === Menu Principal ===
    while ($true) {
        Clear-Host
        Logo_Menu   
        Write-Host ""

        $menus = @(
            "Help & Configuration",
            "Get HTTP Status Code",
            "Get the Page <title>", 
            "Get IP Address from DNS",
            "Discover Allowed HTTP Methods",
            "Capture Server Headers",
            "Detect Technologies in Use",
            "Security Headers Analysis",
            "DNS Zone Transfer Test",
            "Check DNS Records",
            "List Links Found in HTML", 
            "Check the robots.txt File",
            "Check if Site has a Sitemap",
            "Capture Port's Banner's",
            "Get All Words from the Site",
            "Fuzzing Recursive ",
            "Run All Scans (1 to 14)",
            "Exit"
        )

        for ($i=0; $i -lt $menus.Count; $i++) {
            $num = $i 
            $spacing = " " * 74

            if ($i -eq 0) {
                # Apenas a opção 0 (Help & Configuration) em amarelo
                Write-Host -NoNewline "$spacing["
                Write-Host -NoNewline (" {0} " -f $num) -ForegroundColor Green
                Write-Host "]   " -NoNewline
                Write-Host "$($menus[$i])" -ForegroundColor Yellow
            }
            else {
                # Demais opções (número ciano, texto vermelho)
                Write-Host -NoNewline "$spacing["
                Write-Host -NoNewline (" {0} " -f $num) -ForegroundColor Cyan
                Write-Host "]   " -NoNewline
                Write-Host "$($menus[$i])" -ForegroundColor Red
            }

            Write-Host ""
        }

        Write-Host "`n`n`n                                                                                                                          Log is being saved to: $logFile `n" -ForegroundColor Yellow

        $option = Show-InputPrompt -input_name "Choose an option (1-14)" -PaddingLeft 26

        switch ($option) {
            0 {
                while ($true) {
                    Clear-Host
                    Write-Host "`n"
                    Logo_Menu
                    Write-Host "`n`n`n"
                    $submenu = @(
                        "Back Menu",
                        "Help", 
                        "Configure: Cap'port Banner - Option [13]",
                        "Configure: RunAllScans - Option [16]",
                        "Disable : Auto Fuzzing Mode - Option [16]",
                        "Configure: Fuzzing Recursive - Option [15]"
                    )

                    for ($i = 0; $i -lt $submenu.Count; $i++) {
                    $spacing = " " * 57
                    Write-Host -NoNewline "$spacing["
                    Write-Host -NoNewline (" {0} " -f $i) -ForegroundColor Green
                    Write-Host "]   " -NoNewline
                    
                    if ($i -eq 4) {
                        if ($global:AutoFuzzingMode -eq 1) {
                            Write-Host -NoNewline "( Enable )" -ForegroundColor Green
                            Write-Host " Auto Fuzzing Mode - Option [16]" -ForegroundColor Magenta
                        } else {
                            Write-Host -NoNewline "( Disable )" -ForegroundColor Red
                            Write-Host " Auto Fuzzing Mode - Option [16]" -ForegroundColor Magenta
                        }
                    } else {
                        Write-Host "$($submenu[$i])" -ForegroundColor Yellow
                    }
                    
                    Write-Host ""
                }
                    Write-host "`n`n`n"
                    $option_costumization = Show-InputPrompt -input_name "Choose an option (0-5)" -PaddingLeft 35

                    $choice = 0 
                    if (-not [int]::TryParse($option_costumization, [ref]$choice)) {
                        Write-Host "`n`n`n               Invalid option. Choose a number between 0 and 4." -ForegroundColor Red
                        Write-Host "`n               Press Enter to continue..." -ForegroundColor Gray
                        $null = Read-Host
                        continue
                    }

                    switch ($choice) {
                        0 { break }
                        1 { Help; continue }
                        2 { 
                            Clear-Host
                            Logo_Menu
                            Write-Host ""
                            Write-Host "`n==== Configure Ports for Banner Scan ====`n" -ForegroundColor Yellow
                            Write-Host "Default ports: 21, 22, 80, 443, 8080" -ForegroundColor Gray
                            Set-PortsForBanner
                        }
                        3 {
                            Clear-Host
                            Logo_Menu
                            Write-Host "`n==== Configure RunAllScan's ====`n" -ForegroundColor Yellow
                            Write-Host "Configure which scans will be executed when using 'Run All Scans'`n" -ForegroundColor Gray
                            $global:ScansConfig = Set-ScansInteractive
                            if ($global:ScansConfig.Count -eq 0) {
                                Write-Host "  No scans enabled!" -ForegroundColor Red
                            } else {
                                foreach ($scan in $global:ScansConfig) {
                                    Write-Log "$($scan.Name) [1] " -ForegroundColor Green
                                }
                            }
                            continue
                        }
                        4 {
                            $global:AutoFuzzingMode = 1 - $global:AutoFuzzingMode
                            
                            if ($global:AutoFuzzingMode -eq 1) {
                                Write-Host "`n Auto Fuzzing Mode ENABLED" -ForegroundColor Green
                                Write-Host "   After word extraction, recursive fuzzing will run automatically" -ForegroundColor White
                            } else {
                                Write-Host "`n Auto Fuzzing Mode DISABLED" -ForegroundColor Red
                                Write-Host "   Only word extraction will be performed" -ForegroundColor White
                            }
                            
                            Write-Log "Auto Fuzzing Mode toggled to: $global:AutoFuzzingMode"

                        }5 { 
                            Clear-Host
                            Logo_Menu
                            Write-Host "`n==== Configure Recursive Fuzzing ====`n" -ForegroundColor Yellow
                            Write-Host "Configure fuzzing parameters for recursive directory discovery`n" -ForegroundColor Gray
                            Set-FuzzingRecursive
                            continue
                        }
                        default {
                            Write-Host "`n`n               Invalid option. Choose a number between 0 and 5." -ForegroundColor Red
                            Write-Host "`n               Press Enter to continue..." -ForegroundColor Gray
                            $null = Read-Host
                            continue
                        }
                    }
                    if ($choice -eq 0) { break }
                }
            }
            1 {
                Clear-Host
                Logo_Menu
                Write-Host ""
                $url = Show-InputPrompt -input_name "Enter the website URL (ex: http://scanme.nmap.org)" -PaddingLeft 19
                if (Test-ValidUrl $url) {
                    ScanStatusCode -url $url
                } else {
                    Write-Host "`n               Invalid URL. Use http:// or https://" -ForegroundColor Red
                }
                Write-Host "`nPress Enter to continue..." -ForegroundColor Gray
                $null = Read-Host
            }
            2 {
                Clear-Host
                Logo_Menu
                Write-Host ""
                $url = Show-InputPrompt -input_name "Enter the website URL (ex: http://scanme.nmap.org)" -PaddingLeft 19
                if (Test-ValidUrl $url) {
                    ScanTitle -url $url
                } else {
                    Write-Host "`n               Invalid URL. Use http:// or https://" -ForegroundColor Red
                }
                Write-Host "`nPress Enter to continue..." -ForegroundColor Gray
                $null = Read-Host
            }
            3 {   
                Clear-Host
                Logo_Menu
                Write-Host ""
                $url = Show-InputPrompt -input_name "Enter the website URL (ex: http://scanme.nmap.org)" -PaddingLeft 19
                if (Test-ValidUrl $url) {
                    Get-ip-from-url -url $url
                } else {
                    Write-Host "`n               Invalid URL. Use http:// or https://" -ForegroundColor Red 
                }
                Write-Host "`nPress Enter to continue..." -ForegroundColor Gray
                $null = Read-Host
            }
            4 {
                Clear-Host
                Logo_Menu
                Write-Host ""
                $url = Show-InputPrompt -input_name "Enter the website URL (ex: http://scanme.nmap.org)" -PaddingLeft 19
                if (Test-ValidUrl $url) {
                    ScanOptions -url $url
                } else {
                    Write-Host "`n               Invalid URL. Use http:// or https://" -ForegroundColor Red
                }
                Write-Host "`nPress Enter to continue..." -ForegroundColor Gray
                $null = Read-Host
            }
            5 {
                Clear-Host
                Logo_Menu
                Write-Host ""
                $url = Show-InputPrompt -input_name "Enter the website URL (ex: http://scanme.nmap.org)" -PaddingLeft 19
                if (Test-ValidUrl $url) {
                    ScanHeaders -url $url
                } else {
                    Write-Host "`n               Invalid URL. Use http:// or https://" -ForegroundColor Red
                }
                Write-Host "`nPress Enter to continue..." -ForegroundColor Gray
                $null = Read-Host
            }
            6 {
                Clear-Host
                Logo_Menu
                Write-Host ""
                $url = Show-InputPrompt -input_name "Enter the website URL (ex: http://scanme.nmap.org)" -PaddingLeft 19
                if (Test-ValidUrl $url) {
                    ScanTech -url $url
                } else {
                    Write-Host "`n               Invalid URL. Use http:// or https://" -ForegroundColor Red
                }
                Write-Host "`nPress Enter to continue..." -ForegroundColor Gray
                $null = Read-Host
            }
            7 {
                Clear-Host
                Logo_Menu
                Write-Host ""
                $url = Show-InputPrompt -input_name "Enter the website URL (ex: http://scanme.nmap.org)" -PaddingLeft 19
                if (Test-ValidUrl $url) {
                    Test-SecurityHeaders -url $url
                } else {
                    Write-Host "`n               Invalid URL. Use http:// or https://" -ForegroundColor Red
                }
                Write-Host "`nPress Enter to continue..." -ForegroundColor Gray
                $null = Read-Host
            }
            8 {
                Clear-Host
                Logo_Menu
                Write-Host ""
                $url = Show-InputPrompt -input_name "Enter the website URL (ex: http://scanme.nmap.org)" -PaddingLeft 19
                if (Test-ValidUrl $url) {
                    Test-DNSZoneTransfer -url $url
                } else {
                    Write-Host "`n               Invalid URL. Use http:// or https://" -ForegroundColor Red
                }
                Write-Host "`nPress Enter to continue..." -ForegroundColor Gray
                $null = Read-Host
            }
            9 {
                Clear-Host
                Logo_Menu
                Write-Host ""
                $url = Show-InputPrompt -input_name "Enter the website URL (ex: http://scanme.nmap.org)" -PaddingLeft 19
                if (Test-ValidUrl $url) {
                    Get-DNSRecords -url $url
                } else {
                    Write-Host "`n               Invalid URL. Use http:// or https://" -ForegroundColor Red
                }
                Write-Host "`nPress Enter to continue..." -ForegroundColor Gray
                $null = Read-Host
            }
            10 {
                Clear-Host
                Logo_Menu
                Write-Host ""
                $url = Show-InputPrompt -input_name "Enter the website URL (ex: http://scanme.nmap.org)" -PaddingLeft 19
                if (Test-ValidUrl $url) {
                    ScanLinks -url $url
                } else {
                    Write-Host "`n               Invalid URL. Use http:// or https://" -ForegroundColor Red
                }
                Write-Host "`nPress Enter to continue..." -ForegroundColor Gray
                $null = Read-Host
            }
            11 {
                Clear-Host
                Logo_Menu
                Write-Host ""
                $url = Show-InputPrompt -input_name "Enter the website URL (ex: http://scanme.nmap.org)" -PaddingLeft 19
                if (Test-ValidUrl $url) {
                    ScanRobotsTxt -url $url
                } else {
                    Write-Host "`n               Invalid URL. Use http:// or https://" -ForegroundColor Red
                }
                Write-Host "`nPress Enter to continue..." -ForegroundColor Gray
                $null = Read-Host
            }
            12 {
                Clear-Host
                Logo_Menu
                Write-Host ""
                $url = Show-InputPrompt -input_name "Enter the website URL (ex: http://scanme.nmap.org)" -PaddingLeft 19
                if (Test-ValidUrl $url) {
                    ScanSitemap -url $url
                } else {
                    Write-Host "`n               Invalid URL. Use http:// or https://" -ForegroundColor Red
                }
                Write-Host "`nPress Enter to continue..." -ForegroundColor Gray
                $null = Read-Host
            }
            13 {
                Clear-Host
                Logo_Menu
                Write-Host ""
                $url = Show-InputPrompt -input_name "Enter the website URL (ex: http://scanme.nmap.org)" -PaddingLeft 19
                if (Test-ValidUrl $url) {
                    Get-PortBanner -url $url
                } else {
                    Write-Host "`n               Invalid URL. Use http:// or https://" -ForegroundColor Red
                }
                Write-Host "`nPress Enter to continue..." -ForegroundColor Gray
                $null = Read-Host
            }
            14 {
                Clear-Host
                Logo_Menu
                Write-Host ""
                $url = Show-InputPrompt -input_name "Enter the website URL (ex: http://scanme.nmap.org)" -PaddingLeft 19
                if (Test-ValidUrl $url) {
                    ScanHTML -url $url
                } else {
                    Write-Host "`n               Invalid URL. Use http:// or https://" -ForegroundColor Red 
                }
                Write-Host "`nPress Enter to continue..." -ForegroundColor Gray
                $null = Read-Host
            }
            15 {
                Clear-Host
                Logo_Menu
                Write-Host ""
                $url = Show-InputPrompt -input_name "Enter the website URL (ex: http://scanme.nmap.org)" -PaddingLeft 19
                if (Test-ValidUrl $url) {
                    # Primeiro 16 as palavras
                    $resultadoScan = ScanHTML -url $url
                    
                    if ($resultadoScan.SavedFilePath -and (Test-Path $resultadoScan.SavedFilePath)) {
                        Write-Host "`nStarting recursive fuzzing automatically..." -ForegroundColor Yellow
                        Start-Sleep -Seconds 2
                        Start-FuzzingRecursive -url $url -wordlist $resultadoScan.SavedFilePath
                    } else {
                        Write-Host "`nFuzzing cancelled - no wordlist file was saved." -ForegroundColor Yellow
                    }
                } else {
                    Write-Host "`n               Invalid URL. Use http:// or https://" -ForegroundColor Red
                }
                Write-Host "`nPress Enter to continue..." -ForegroundColor Gray
                $null = Read-Host
            }
            16 {
                Clear-Host
                Logo_Menu
                Write-Host ""
                $url = Show-InputPrompt -input_name "Enter the website URL (ex: http://scanme.nmap.org)" -PaddingLeft 19
                if (Test-ValidUrl $url) {
                    RunAllScans -url $url
                } else {
                    Write-Host "`n               Invalid URL. Use http:// or https://" -ForegroundColor Red
                    Write-Host "`n               Press Enter to continue..." -ForegroundColor Gray
                    $null = Read-Host
                }
            }
            17 {
                Clear-Host
                Logo_Menu
                Write-Host ""
                Write-Host "             Exiting . . ." -ForegroundColor Red
                Write-Host ""
                Write-Host "             THANK YOU FOR USING PowerDiNSpec" -ForegroundColor Green
                Write-Host "             OBRIGADO POR USAR PowerDiNSpec" -ForegroundColor White
                Write-Host ""
                Write-Host "             Powered by PowerShell - Luan Calazans - 2025" -ForegroundColor DarkGray
                Write-Host ""
                Write-Host "             Visit: https://github.com/Luanqmata/PowerDiNSpec" -ForegroundColor DarkGray
                Write-Host ""
                Write-Log "`n`nExiting PowerDiNSpec ...`n`n" "INFO"
                Start-Sleep -Seconds 1.5
                return
            }
            
            default {
                Write-Host "`n`n               Invalid option. Choose a number between 0 and 16." -ForegroundColor Red
                Write-Host "`n               Press Enter to continue..." -ForegroundColor Gray
                $null = Read-Host
            }
        }
    }
}
# =============================================
# EXECUÇÃO PRINCIPAL
# =============================================
PowerDiNSpec
