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
                                                        //               | |                (_)        |_|                           (_)           2.2.5v

                                         
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
# FUNÇÕES AUXILIARES / Port banner grab
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
    
    $logDir = "Logs_PowerDns"
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }
    
    $logFilePath = Join-Path $logDir $logFile
    
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
        Handle-WebError -ErrorObject $_
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
        Handle-WebError -ErrorObject $_
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
        Handle-WebError -ErrorObject $_
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
        Handle-WebError -ErrorObject $_
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
        Handle-WebError -ErrorObject $_
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
        Handle-WebError -ErrorObject $_
    }
}
function ScanRobotsTxt {
    param ([string]$url)
    try {
        Write-Host "`n Looking for robots.txt..." -ForegroundColor Yellow
        Write-Log "Starting ScanRobotsTxt for: $url"
        
        $robotsUrl = "$url/robots.txt"
        $response = Invoke-WebRequestSafe -Uri $robotsUrl
        
        $content = $response.Content.Trim()
        $lines = $content -split "`n" | Where-Object { $_.Trim() -ne '' }

        
        if ($lines.Count -gt 0) {

            $userAgents = $lines | Where-Object { $_ -match '^User-agent:' } | ForEach-Object { $_.Replace('User-agent:', '').Trim() }
            $disallowed = $lines | Where-Object { $_ -match '^Disallow:' } | ForEach-Object { $_.Replace('Disallow:', '').Trim() }
            $allowed = $lines | Where-Object { $_ -match '^Allow:' } | ForEach-Object { $_.Replace('Allow:', '').Trim() }
            $sitemaps = $lines | Where-Object { $_ -match '^Sitemap:' } | ForEach-Object { $_.Replace('Sitemap:', '').Trim() }
            $crawlDelays = $lines | Where-Object { $_ -match '^Crawl-delay:' } | ForEach-Object { $_.Replace('Crawl-delay:', '').Trim() }

            if ($userAgents.Count -gt 0) {
                Write-Host "`nUSER AGENTS TARGETED ($($userAgents.Count)):" -ForegroundColor Cyan
                $userAgents | ForEach-Object {
                    Write-Host "  - $_" -ForegroundColor White
                }
            }

            if ($disallowed.Count -gt 0) {
                Write-Host "`nDISALLOWED PATHS ($($disallowed.Count)):" -ForegroundColor Red
                $disallowed | ForEach-Object {
                    if ([string]::IsNullOrWhiteSpace($_)) {
                        Write-Host "  - (Empty - allows all)" -ForegroundColor Green
                    } else {
                        Write-Host "  - $_" -ForegroundColor Yellow
                    }
                }

                $sensitivePaths = $disallowed | Where-Object { 
                    $_ -match '(admin|login|config|setup|debug|backup|sql|database|\.env|\.git|wp-|phpmyadmin|cpanel)' 
                }
                if ($sensitivePaths.Count -gt 0) {
                    Write-Host "`nSENSITIVE PATHS FOUND:" -ForegroundColor Red
                    $sensitivePaths | ForEach-Object {
                        Write-Host "  [!] $_" -ForegroundColor Red
                    }
                }
            } else {
                Write-Host "`nDISALLOWED PATHS: None found" -ForegroundColor Green
            }

            if ($allowed.Count -gt 0) {
                Write-Host "`nALLOWED PATHS ($($allowed.Count)):" -ForegroundColor Green
                $allowed | ForEach-Object {
                    Write-Host "  - $_" -ForegroundColor White
                }
            }
            
            if ($sitemaps.Count -gt 0) {
                Write-Host "`nSITEMAP REFERENCES ($($sitemaps.Count)):" -ForegroundColor Magenta
                $sitemaps | ForEach-Object {
                    Write-Host "  - $_" -ForegroundColor White
                }
            }
            
            if ($crawlDelays.Count -gt 0) {
                Write-Host "`nCRAWL DELAYS:" -ForegroundColor Yellow
                $crawlDelays | ForEach-Object {
                    Write-Host "  - $_ seconds" -ForegroundColor White
                }
            }

            Write-Host "`nCOMPLETE RAW CONTENT:" -ForegroundColor DarkRed
            Write-Host $content -ForegroundColor Gray
            
            $contentLength = $content.Length
            Write-Host "`nFILE INFORMATION:" -ForegroundColor Yellow
            Write-Host "  Content Length: $contentLength characters" -ForegroundColor White
            Write-Host "  Approx. Size: $([math]::Round($contentLength / 1024, 2)) KB" -ForegroundColor White
            Write-Host "  Lines: $($lines.Count)" -ForegroundColor White
        } else {
            Write-Host "  robots.txt found but appears to be empty or malformed." -ForegroundColor Yellow
            Write-Host "  Raw content:" -ForegroundColor Cyan
            Write-Host $content -ForegroundColor Gray
        }
        
        Write-Log "Robots.txt comprehensive analysis completed: $($lines.Count) lines, $contentLength characters"
        
    } catch {
        Write-Host "`n  robots.txt not found or inaccessible." -ForegroundColor Red
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
        $lines = $content -split "`n" | Where-Object { $_.Trim() -ne '' }

        $content = $response.Content.Trim()
        
        if ($content -match '<urlset') {
            Write-Host "`n  STANDARD SITEMAP DETECTED (XML FORMAT)" -ForegroundColor Gray
            $lines = $content -split "`n" | Where-Object { $_.Trim() -ne '' }
            $urls = @()
            
            $locMatches = [regex]::Matches($content, '<loc>\s*([^<]+)\s*</loc>', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            $urls += $locMatches | ForEach-Object { $_.Groups[1].Value.Trim() }
            
            $urlMatches = [regex]::Matches($content, '<url>\s*<loc>([^<]+)</loc>', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            $urls += $urlMatches | ForEach-Object { $_.Groups[1].Value.Trim() }
            
            $urls = $urls | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique
            
            Write-Host "`nTOTAL URLs EXTRACTED: $($urls.Count)" -ForegroundColor Green
            
            if ($urls.Count -gt 0) {
                Write-Host "`nALL URLs FOUND:" -ForegroundColor Red
                $urls | ForEach-Object {
                    Write-Host "  - $_" -ForegroundColor White
                }
                
                $categories = @{
                    "Images" = $urls | Where-Object { $_ -match '\.(jpg|jpeg|png|gif|bmp|svg|webp)(\?|$)' }
                    "PDFs" = $urls | Where-Object { $_ -match '\.pdf(\?|$)' }
                    "Documents" = $urls | Where-Object { $_ -match '\.(doc|docx|xls|xlsx|ppt|pptx)(\?|$)' }
                    "Admin" = $urls | Where-Object { $_ -match '(admin|login|dashboard|panel|wp-admin)' }
                    "API" = $urls | Where-Object { $_ -match '(api|json|xml|rest)' }
                }
                
                Write-Host "`nURL CATEGORIES:" -ForegroundColor Magenta
                foreach ($category in $categories.Keys) {
                    $count = $categories[$category].Count
                    if ($count -gt 0) {
                        Write-Host "  $category`: $count URLs" -ForegroundColor White
                    }
                }
                
                $interestingUrls = $urls | Where-Object { 
                    $_ -match '(admin|login|config|setup|debug|backup|test|dev|staging)' 
                }
                if ($interestingUrls.Count -gt 0) {
                    Write-Host "`nINTERESTING/ADMIN URLs:" -ForegroundColor Red
                    $interestingUrls | ForEach-Object {
                        Write-Host "  [!] $_" -ForegroundColor Red
                    }
                }
            }
            
        } elseif ($content -match '^http' -or $content -match 'sitemap') {
            Write-Host "`n  SITEMAP INDEX DETECTED" -ForegroundColor Gray
            $lines = $content -split "`n" | Where-Object { $_.Trim() -ne '' }
            $sitemapRefs = $content -split "`n" | Where-Object { 
                $_ -match '^http' -or $_ -match 'sitemap' -or $_ -match '\.xml'
            } | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
            
            Write-Host "`nSITEMAP REFERENCES FOUND: $($sitemapRefs.Count)" -ForegroundColor Green
            
            if ($sitemapRefs.Count -gt 0) {
                Write-Host "`nALL SITEMAP REFERENCES:" -ForegroundColor Yellow
                $sitemapRefs | ForEach-Object {
                    Write-Host "  - $_" -ForegroundColor White
                }
            }
            
        } else {
            Write-Host "`nUNKNOWN SITEMAP FORMAT" -ForegroundColor Yellow
        }
        
        Write-Host "`nCOMPLETE RAW CONTENT:" -ForegroundColor DarkRed
        Write-Host $content -ForegroundColor Gray

        $contentLength = $content.Length
        Write-Host "`nFILE INFORMATION:" -ForegroundColor Yellow
        Write-Host "  Content Length: $contentLength characters" -ForegroundColor White
        Write-Host "  Approx. Size: $([math]::Round($contentLength / 1024, 2)) KB" -ForegroundColor White
        Write-Host "  Lines: $($lines.Count)" -ForegroundColor White
        Write-Log "Sitemap.xml comprehensive analysis completed: $contentLength characters"
        
    } catch {
        Write-Host "`n  sitemap.xml not found or inaccessible." -ForegroundColor Red
        Write-Log "Sitemap.xml not found: $($_.Exception.Message)" "WARNING"
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

function Configure-PortsForBanner {
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

function Configure-ScansInteractive {
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
        $input = Show-InputPrompt -input_name "  Press [Enter] to Save and exit" -PaddingLeft 25 -QuestionColor Green
        
        if ([string]::IsNullOrWhiteSpace($input)) {
            $global:ScansConfig = $scans | Where-Object { $_.Enabled -eq 1 }
            Write-Host "`n`n`n      Configuration saved!" -ForegroundColor Green
            Start-Sleep -Seconds 1
            return $global:ScansConfig
        }
        
        switch ($input.ToUpper()) {
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
                # 🕵️‍♂️ STEALTH MODE - Novo preset furtivo
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
                if ($input -match '^\d+$') {
                    $n = [int]$input
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
                    Write-Host "`n  Invalid input." -ForegroundColor Red
                    Start-Sleep -Milliseconds 800
                    Continue
                }
            }
        }
    }
}
# =============================================
# Fuzzing Functions
# =============================================
function ScanHTML {
    param ([string]$url)
    try {
        Write-Host "`n Obtaining words from the HTML source code..." -ForegroundColor Yellow
        Write-Log "Starting ScanHTML for: $url"
        Start-Sleep -Seconds 2

        $response = Invoke-WebRequestSafe -Uri $url
        $htmlContent = $response.Content

        # Extract words with improved regex - SEM FILTROS COMPLEXOS
        $palavras = ($htmlContent -split '[^\p{L}0-9_\-]+') |
                    Where-Object { $_.Length -gt 2 } |  # Apenas remove palavras muito curtas
                    Select-Object -Unique |
                    Sort-Object

        # Remove apenas palavras extremamente comuns se necessário
        $commonWords = @('div', 'span', 'html', 'head', 'body', 'script', 'style', 'css')
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
        Handle-WebError -ErrorObject $_
        return @{
            Words = @()
            SavedFilePath = $null
            TotalWords = 0
        }
    }
}
function Start-FuzzingRecursive {
    param(
        [string]$url,
        [string]$wordlist,
        [int]$MaxDepth = 4,
        [int]$TimeoutMs = 3000,
        [switch]$Aggressive = $false,
        [int]$MaxThreads = 5
    )
    
    try {
        Write-Host "`n[ADVANCED RECURSIVE FUZZING]" -ForegroundColor Magenta
        Write-Host "   Target: $url" -ForegroundColor White
        Write-Host "   Wordlist: $wordlist" -ForegroundColor White
        
        if (-not (Test-Path $wordlist)) {
            Write-Host "[ERROR] Wordlist not found: $wordlist" -ForegroundColor Red
            return @()
        }

        $words = [System.IO.File]::ReadAllLines($wordlist) | Where-Object { 
            -not [string]::IsNullOrEmpty($_) -and $_.Length -gt 2 
        }
        
        if ($words.Count -eq 0) {
            Write-Host "[ERROR] No valid words in wordlist" -ForegroundColor Red
            return @()
        }

        # CONFIGURAÇÕES INTELIGENTES
        $baseUri = [System.Uri]$url
        $baseUrl = $baseUri.GetLeftPart([System.UriPartial]::Path)
        $baseHost = $baseUri.Host
        
        # Garante que a base URL termina com /
        if (-not $baseUrl.EndsWith('/')) {
            $baseUrl += '/'
        }
        
        Write-Host "`n[CONFIG]" -ForegroundColor Cyan
        Write-Host "  Words: $($words.Count)" -ForegroundColor Gray
        Write-Host "  Max Depth: $MaxDepth" -ForegroundColor Gray
        Write-Host "  Timeout: ${TimeoutMs}ms" -ForegroundColor Gray

        # SISTEMA AVANÇADO DE DETECÇÃO DE BASE
        Write-Host "`n[ANALYSIS] Analyzing base page..." -ForegroundColor Cyan
        $baseSignature = Get-PageSignature -Url $url
        
        if (-not $baseSignature) {
            Write-Host "[WARNING] Could not analyze base page" -ForegroundColor Yellow
            return @()
        }

        Write-Host "  Base Page: $($baseSignature.Title)" -ForegroundColor Gray
        Write-Host "  Size: $($baseSignature.ContentLength) chars" -ForegroundColor Gray
        Write-Host "  Hash: $($baseSignature.ContentHash)" -ForegroundColor Gray

        # RESULTADOS E CONTROLE DE DUPLICATAS
        $allResults = [System.Collections.ArrayList]::new()
        $visitedUrls = @{}  # Hash table para URLs já visitadas
        $contentHashes = @{} # Hash table para conteúdos já vistos
        $script:totalRequests = 0
        $script:validEndpoints = 0
        $script:duplicatesFiltered = 0
        $script:lastDuplicateUrl = "None"
        $startTime = Get-Date

        # FUNÇÃO DE TESTE OTIMIZADA
        function Test-Endpoint {
            param($testUrl, $currentDepth, $parentWord)
            
            # Verifica se URL já foi visitada
            if ($visitedUrls.ContainsKey($testUrl)) {
                $script:duplicatesFiltered++
                $script:lastDuplicateUrl = $testUrl
                return $false
            }
            $visitedUrls[$testUrl] = $true
            
            try {
                # VALIDAÇÃO DA URL ANTES DO REQUEST
                if (-not $testUrl.StartsWith('http')) {
                    return $false
                }
                
                $request = [System.Net.WebRequest]::Create($testUrl)
                $request.Timeout = $TimeoutMs
                $request.Method = "GET"
                $request.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                
                $response = $request.GetResponse()
                $statusCode = [int]$response.StatusCode
                $contentLength = $response.ContentLength
                $contentStream = $response.GetResponseStream()
                
                # Lê o conteúdo completo para análise
                $reader = New-Object System.IO.StreamReader($contentStream)
                $fullContent = $reader.ReadToEnd()
                $reader.Close()
                $contentStream.Close()
                $response.Close()

                # Calcula hash do conteúdo
                $contentHash = [System.BitConverter]::ToString(
                    [System.Security.Cryptography.MD5]::Create().ComputeHash(
                        [System.Text.Encoding]::UTF8.GetBytes($fullContent)
                    )
                ).Replace("-", "").ToLower()

                # Verifica se já vimos este conteúdo antes (SILENCIOSAMENTE)
                if ($contentHashes.ContainsKey($contentHash)) {
                    $script:duplicatesFiltered++
                    $script:lastDuplicateUrl = $testUrl
                    return $false
                }
                $contentHashes[$contentHash] = $true

                # DETECÇÃO AVANÇADA DE FALSOS POSITIVOS
                $isValidEndpoint = Test-RealEndpoint -Url $testUrl -Content $fullContent -ContentLength $contentLength -BaseSignature $baseSignature

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
                    }
                    
                    $allResults.Add($result) | Out-Null
                    $script:validEndpoints++
                    
                    Write-Host "[REAL $statusCode] Depth $currentDepth - $testUrl" -ForegroundColor Green
                    if ($title) {
                        Write-Host "       Title: $title" -ForegroundColor Magenta
                    }
                    if ($contentLength -gt 0) {
                        Write-Host "            Size: $contentLength bytes" -ForegroundColor Gray
                    }
                    
                    return $true
                } else {
                    # Mostra apenas FALSE quando for realmente diferente (não duplicado)
                    if (-not $contentHashes.ContainsKey($contentHash)) {
                        Write-Host "[FALSE $statusCode] $testUrl" -ForegroundColor Gray
                        if ($contentLength -gt 0) {
                            Write-Host "       Size: $contentLength bytes" -ForegroundColor DarkGray
                        }
                    }
                    return $false
                }
                
            } catch [System.Net.WebException] {
                # Ignora 404, timeout, etc silenciosamente
                return $false
            } catch {
                return $false
            } finally {
                $script:totalRequests++
            }
        }

        # RECURSÃO INTELIGENTE COM CONTROLE DE DUPLICATAS
        function Invoke-SmartRecursion {
            param($basePath, $wordList, $currentDepth, $maxDepth)
            
            if ($currentDepth -gt $maxDepth) { return }
            
            $testedCount = 0
            $validPathsThisLevel = @()
            
            foreach ($word in $wordList) {
                # CONSTRUÇÃO SEGURA DA URL
                $testUrl = if ($basePath.EndsWith('/')) {
                    "$basePath$word"
                } else {
                    "$basePath/$word"
                }
                
                # VALIDAÇÃO DA URL
                try {
                    $uri = [System.Uri]$testUrl
                } catch {
                    continue
                }
                
                # PALAVRAS QUE NUNCA DEVEM RECURSAR
                $noRecursionWords = @('non9')
                $isNoRecursion = $noRecursionWords -contains $word.ToLower()
                
                # PROGRESSO DETALHADO - MOSTRA TUDO EM TEMPO REAL
                $testedCount++
                $percentComplete = [math]::Round(($testedCount / $wordList.Count) * 100, 1)
                $elapsedTime = (Get-Date) - $startTime
                $elapsedFormatted = "{0:D2}:{1:D2}" -f $elapsedTime.Minutes, $elapsedTime.Seconds
                
                # BARRA DE PROGRESSO COMPLETA
                Write-Progress -Id 1 -Activity "RECURSIVE FUZZING - Depth $currentDepth" -Status "Directory: $basePath" -PercentComplete $percentComplete -CurrentOperation "Testing: $word"
                
                Write-Progress -Id 2 -Activity "STATISTICS" -Status "Progress: $testedCount/$($wordList.Count) words | $percentComplete% Complete | Valid: $($script:validEndpoints) endpoints" -ParentId 1
                
                Write-Progress -Id 3 -Activity "TIMING" -Status "Elapsed: $elapsedFormatted | Speed: $([math]::Round($script:totalRequests / [math]::Max($elapsedTime.TotalSeconds, 1), 2)) req/s" -ParentId 1
                
                Write-Progress -Id 4 -Activity "REQUESTS" -Status "Total: $($script:totalRequests) requests | Filtered: $($script:duplicatesFiltered) duplicates" -ParentId 1
                
                # NOVA BARRA: ÚLTIMO DUPLICADO FILTRADO
                Write-Progress -Id 5 -Activity "LAST DUPLICATE FILTERED" -Status "$($script:lastDuplicateUrl)" -ParentId 1
                
                # TESTE DO ENDPOINT
                $isValid = Test-Endpoint -testUrl $testUrl -currentDepth $currentDepth -parentWord $word
                
                if ($isValid) {
                    $validPathsThisLevel += $word
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
            
            # RECURSÃO APENAS PARA PATHS VÁLIDOS
            if ($currentDepth -lt $maxDepth -and $validPathsThisLevel.Count -gt 0) {
                Write-Host "`n[RECURSION] Found $($validPathsThisLevel.Count) valid paths at depth $currentDepth" -ForegroundColor Yellow
                
                foreach ($validWord in $validPathsThisLevel) {
                    # Não recursa em palavras que sabemos que não devem recursar
                    if ($noRecursionWords -contains $validWord.ToLower()) {
                        Write-Host "       [SKIP] No recursion for: $validWord" -ForegroundColor DarkGray
                        continue
                    }
                    
                    # Não recursa em arquivos com extensão
                    if ($validWord -match '\.[a-z]{2,4}$') {
                        Write-Host "       [SKIP] File extension, no recursion: $validWord" -ForegroundColor DarkGray
                        continue
                    }
                    
                    $nextUrl = if ($basePath.EndsWith('/')) {
                        "$basePath$validWord"
                    } else {
                        "$basePath/$validWord"
                    }
                    
                    Write-Host "       -> Recursing to depth $(($currentDepth + 1)) from: $validWord" -ForegroundColor Yellow
                    Invoke-SmartRecursion -basePath $nextUrl -wordList $wordList -currentDepth ($currentDepth + 1) -maxDepth $maxDepth
                }
            }
        }

        # INICIA FUZZING PRINCIPAL
        Write-Host "`n[FUZZING] Starting smart recursive scan..." -ForegroundColor Magenta
        Write-Host "          (Duplicates and generic pages are filtered silently)`n" -ForegroundColor Gray
        
        Invoke-SmartRecursion -basePath $baseUrl -wordList $words -currentDepth 1 -maxDepth $MaxDepth

        # RELATÓRIO FINAL
        $endTime = Get-Date
        $duration = $endTime - $startTime
        $requestsPerSecond = [math]::Round($script:totalRequests / [math]::Max($duration.TotalSeconds, 1), 2)

        Write-Host "`n[SCAN COMPLETE]" -ForegroundColor Green
        Write-Host "   Total Requests: $($script:totalRequests)" -ForegroundColor White
        Write-Host "   Valid Endpoints: $($script:validEndpoints)" -ForegroundColor Cyan
        Write-Host "   Duplicates Filtered: $($script:duplicatesFiltered)" -ForegroundColor DarkYellow
        Write-Host "   Duration: $([math]::Round($duration.TotalSeconds, 2))s" -ForegroundColor White
        Write-Host "   Speed: $requestsPerSecond req/s" -ForegroundColor White

        $finalResults = $allResults | Sort-Object Depth, StatusCode | Select-Object -Unique
        
        if ($finalResults.Count -gt 0) {
            Write-Host "`n[VALID ENDPOINTS FOUND]:" -ForegroundColor Green
            $finalResults | Format-Table URL, StatusCode, ContentLength, Depth, Title -AutoSize
            
            # Salva resultados em arquivo
            $resultsFile = "fuzzing_results_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
            $finalResults | Export-Csv -Path $resultsFile -NoTypeInformation
            Write-Host "   Results saved to: $resultsFile" -ForegroundColor Gray
            
            return $finalResults
        } else {
            Write-Host "`n[RESULTS] No real endpoints found" -ForegroundColor Yellow
            return @()
        }

    } catch {
        Write-Host "[FATAL ERROR] $($_.Exception.Message)" -ForegroundColor Red
        return @()
    }
}
# FUNÇÕES AUXILIARES PARA DETECÇÃO PRECISA
function Get-PageSignature {
    param([string]$Url)
    
    try {
        $request = [System.Net.WebRequest]::Create($Url)
        $request.Timeout = 10000
        $response = $request.GetResponse()
        $stream = $response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($stream)
        $content = $reader.ReadToEnd()
        $reader.Close()
        $response.Close()

        $title = if ($content -match '<title[^>]*>(.*?)</title>') { $matches[1].Trim() } else { "No Title" }
        $contentHash = [System.BitConverter]::ToString(
            [System.Security.Cryptography.MD5]::Create().ComputeHash(
                [System.Text.Encoding]::UTF8.GetBytes($content)
            )
        ).Replace("-", "").ToLower()

        return @{
            Url = $Url
            Title = $title
            ContentLength = $content.Length
            ContentHash = $contentHash
            SampleContent = $content.Substring(0, [math]::Min(1000, $content.Length))
        }
    } catch {
        return $null
    }
}

function Test-RealEndpoint {
    param($Url, $Content, $ContentLength, $BaseSignature)
    
    # VERIFICAÇÕES CONSECUTIVAS PARA FALSOS POSITIVOS
    
    # 1. Comparação de Hash (mais precisa)
    $currentHash = [System.BitConverter]::ToString(
        [System.Security.Cryptography.MD5]::Create().ComputeHash(
            [System.Text.Encoding]::UTF8.GetBytes($Content)
        )
    ).Replace("-", "").ToLower()

    if ($currentHash -eq $BaseSignature.ContentHash) {
        return $false # Conteúdo idêntico ao base
    }

    # 2. Verificação de páginas de erro
    $errorPatterns = @(
        "404", "Not Found", "Page Not Found", "Error", "Invalid", "Cannot GET",
        "Route not found", "The resource cannot be found", "Object not found",
        "404 Not Found", "404 Error", "Page Not Found"
    )

    foreach ($pattern in $errorPatterns) {
        if ($Content -imatch $pattern) {
            return $false
        }
    }

    # 3. Verificação de tamanho (páginas muito pequenas geralmente são erros)
    if ($ContentLength -lt 100 -and $BaseSignature.ContentLength -gt 1000) {
        return $false
    }

    # 4. Verificação de conteúdo vazio/básico
    if ($Content -match '^\s*$' -or $Content -match '^<\?xml') {
        return $false
    }

    # 5. Verificação de redirect para página principal
    if ($Content -match 'window\.location|http-equiv\s*=\s*["'']refresh["'']') {
        if ($Content -match $BaseSignature.Url) {
            return $false
        }
    }

    # 6. Verificação de páginas de archive/listagem genérica do WordPress
    $wpGenericPatterns = @(
        "archive", "category", "tag", "author", "date", "search",
        "is_404", "page-not-found", "error-404",
        "Nothing found", "No posts found"
    )

    foreach ($pattern in $wpGenericPatterns) {
        if ($Content -imatch $pattern -and $ContentLength -lt 1500) {
            return $false
        }
    }

    # Se passou por todas as verificações, é provavelmente um endpoint válido
    return $true
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

    # EXIBE O MENU DOS SCANS (igual ao Configure-ScansInteractive)
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
            Write-Host "Words for Fuzzing: EXECUTED" -ForegroundColor Green
            Write-Host "Total words: $($fuzzingResult.TotalWords)" -ForegroundColor White

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

            Write-Host "`n           === STARTING AUTO FUZZING ===`n" -ForegroundColor Magenta
            Write-Host "Launching recursive fuzzing with generated wordlist..." -ForegroundColor Cyan
            
            Start-Sleep -Seconds 2
            
            # Executa o fuzzing recursivo
            Start-FuzzingRecursive -url $url -wordlist $wordlistPath
            
            if ($wordlistPath -like "*temp_autofuzz_*" -and (Test-Path $wordlistPath)) {
                Remove-Item $wordlistPath -Force
                Write-Host "Temporary wordlist cleaned up: $wordlistPath" -ForegroundColor Gray
            }
            
        } else {
            Write-Host "Words for Fuzzing: NOT EXECUTED OR FAILED" -ForegroundColor Red
            Write-Host "Auto Fuzzing skipped - make sure 'Words for Fuzzing' scan is enabled and words were extracted." -ForegroundColor Yellow
        }
    } else {
        Write-Host "Auto Fuzzing Mode: DISABLED" -ForegroundColor Yellow
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
    Write-Host "`n                                                                          ==== HELP - PowerDiNSpec v2.2.5 ====`n" -ForegroundColor Red

    Write-Host "`n  POWERDINSPEC - PowerShell DNS Recon Tool" -ForegroundColor Yellow
    Write-Host "`n  PowerDiNSpec is a comprehensive PowerShell-based reconnaissance toolkit for" -ForegroundColor White
    Write-Host "  websites and DNS infrastructure. Designed for security professionals, researchers," -ForegroundColor White
    Write-Host "  and penetration testers conducting authorized security assessments." -ForegroundColor White
    Write-Host "`n  OVERVIEW" -ForegroundColor Cyan
    Write-Host "    PowerDiNSpec automates multiple reconnaissance techniques against web targets," -ForegroundColor White
    Write-Host "    providing essential information gathering capabilities for security assessments." -ForegroundColor White
    Write-Host "    Each scan is designed to be non-invasive but may trigger security monitoring." -ForegroundColor White
    Write-Host "`n  CORE FEATURES" -ForegroundColor Cyan   
    Write-Host "`n    [1] HTTP Status Code Analysis" -ForegroundColor Green
    Write-Host "        Retrieves and analyzes HTTP response codes to understand server behavior" -ForegroundColor White
    Write-Host "        and identify potential issues or redirect patterns." -ForegroundColor Gray
    Write-Host "`n    [2] Page Title Extraction" -ForegroundColor Green
    Write-Host "        Extracts and displays the HTML page title for quick content identification" -ForegroundColor White
    Write-Host "        and target verification." -ForegroundColor Gray
    Write-Host "`n    [3] DNS IP Resolution" -ForegroundColor Green
    Write-Host "        Performs comprehensive DNS lookups for both IPv4 (A) and IPv6 (AAAA)" -ForegroundColor White
    Write-Host "        records, revealing the target's IP infrastructure." -ForegroundColor Gray
    Write-Host "`n    [4] HTTP Methods Discovery" -ForegroundColor Green
    Write-Host "        Enumerates allowed HTTP methods (GET, POST, PUT, DELETE, OPTIONS, etc.)" -ForegroundColor White
    Write-Host "        to identify potential attack vectors and server configuration." -ForegroundColor Gray
    Write-Host "`n    [5] Server Headers Analysis" -ForegroundColor Green
    Write-Host "        Captures and analyzes HTTP response headers including Server, X-Powered-By," -ForegroundColor White
    Write-Host "        and other security-related headers for technology fingerprinting." -ForegroundColor Gray
    Write-Host "`n    [6] Technology Detection" -ForegroundColor Green
    Write-Host "        Identifies web technologies, frameworks, and server software through" -ForegroundColor White
    Write-Host "        header analysis and response patterns." -ForegroundColor Gray
    Write-Host "`n    [7] Security Headers Analysis" -ForegroundColor Green
    Write-Host "        Comprehensive security headers audit including:" -ForegroundColor White
    Write-Host "        - Content-Security-Policy, Strict-Transport-Security" -ForegroundColor Gray
    Write-Host "        - X-Frame-Options, X-Content-Type-Options" -ForegroundColor Gray
    Write-Host "        - Security scoring and recommendations" -ForegroundColor Gray
    Write-Host "`n    [8] DNS Zone Transfer Test" -ForegroundColor Green
    Write-Host "        Tests DNS servers for zone transfer vulnerabilities that could" -ForegroundColor White
    Write-Host "        expose all DNS records of the domain." -ForegroundColor Gray
    Write-Host "`n    [9] Comprehensive DNS Records" -ForegroundColor Green
    Write-Host "        Extensive DNS reconnaissance including:" -ForegroundColor White
    Write-Host "        - MX Records  - Mail server information" -ForegroundColor Gray
    Write-Host "        - NS Records  - Name servers" -ForegroundColor Gray
    Write-Host "        - SOA Records - Zone authority information" -ForegroundColor Gray
    Write-Host "        - CNAME Records - Canonical name mappings" -ForegroundColor Gray
    Write-Host "        - TXT Records - SPF, DKIM, verification records" -ForegroundColor Gray
    Write-Host "        - PTR Records - Reverse DNS lookups" -ForegroundColor Gray
    Write-Host "`n    [10] HTML Link Discovery" -ForegroundColor Green
    Write-Host "        Extracts all HTTP/HTTPS links from page content to map internal and" -ForegroundColor White
    Write-Host "        external resources and identify potential attack surface." -ForegroundColor Gray
    Write-Host "`n    [11] Robots.txt Analysis" -ForegroundColor Green
    Write-Host "        Retrieves and analyzes robots.txt files to discover hidden directories," -ForegroundColor White
    Write-Host "        disallowed paths, and potential sensitive areas." -ForegroundColor Gray
    Write-Host "`n    [12] Sitemap Discovery" -ForegroundColor Green
    Write-Host "        Checks for sitemap.xml files to understand site structure and" -ForegroundColor White
    Write-Host "        discover additional content paths." -ForegroundColor Gray
    Write-Host "`n    [13] Port Banner Grabbing" -ForegroundColor Green
    Write-Host "        Advanced service detection on multiple ports with configurable presets:" -ForegroundColor White
    Write-Host "        - Common Services (21,22,80,443, etc.)" -ForegroundColor Gray
    Write-Host "        - Web Services (80,443,8080,8443, etc.)" -ForegroundColor Gray
    Write-Host "        - Database Ports (1433,1521,3306,5432, etc.)" -ForegroundColor Gray
    Write-Host "        - Email Services (25,110,143,465, etc.)" -ForegroundColor Gray
    Write-Host "        - Custom port ranges supported" -ForegroundColor Gray
    Write-Host "`n    [14] Wordlist Generation for Fuzzing" -ForegroundColor Green
    Write-Host "        Extracts unique words from HTML content to create customized wordlists" -ForegroundColor White
    Write-Host "        for directory brute-forcing, fuzzing, and content discovery." -ForegroundColor Gray
    Write-Host "`n    [15] Fuzzing Recursive" -ForegroundColor Green
    Write-Host "        Advanced recursive directory fuzzing with features:" -ForegroundColor White
    Write-Host "        - Infinite depth recursion on found directories" -ForegroundColor Gray
    Write-Host "        - Real-time progress tracking" -ForegroundColor Gray
    Write-Host "        - Automatic port discovery from HTML content" -ForegroundColor Gray
    Write-Host "        - Multi-level directory discovery" -ForegroundColor Gray
    Write-Host "`n    [16] Run All Scans" -ForegroundColor Green
    Write-Host "        Executes a comprehensive sequential assessment using all enabled scans" -ForegroundColor White
    Write-Host "        with configurable options and real-time progress display." -ForegroundColor Gray

    Write-Host "`n  NEW FEATURES IN v2.2.5" -ForegroundColor Magenta
    Write-Host "    - Auto Fuzzing Mode: Automatic recursive fuzzing after word extraction" -ForegroundColor White
    Write-Host "    - Port Discovery: Automatically detects and tests ports from HTML content" -ForegroundColor White
    Write-Host "    - Enhanced Wordlist Generation: Improved filtering and optimization" -ForegroundColor White
    Write-Host "    - Recursive Fuzzing: Infinite depth directory discovery" -ForegroundColor White
    Write-Host "    - Real-time Progress: Visual progress bars for long-running scans" -ForegroundColor White
    Write-Host "    - Auto-save Functionality: Automatic wordlist saving for fuzzing" -ForegroundColor White

    Write-Host "`n  AUTO FUZZING MODE" -ForegroundColor Cyan
    Write-Host "    When enabled, automatically launches recursive fuzzing after word extraction:" -ForegroundColor White
    Write-Host "    - Extracts words from HTML content" -ForegroundColor Gray
    Write-Host "    - Automatically saves wordlist (even if user declines)" -ForegroundColor Gray
    Write-Host "    - Launches recursive fuzzing with discovered words" -ForegroundColor Gray
    Write-Host "    - Tests discovered ports automatically" -ForegroundColor Gray
    Write-Host "    - Provides real-time progress and results" -ForegroundColor Gray

    Write-Host "`n  PORT DISCOVERY INTELLIGENCE" -ForegroundColor Cyan
    Write-Host "    Advanced port detection from HTML content:" -ForegroundColor White
    Write-Host "    - Scans HTML for potential port numbers" -ForegroundColor Gray
    Write-Host "    - Tests common web ports automatically" -ForegroundColor Gray
    Write-Host "    - Auto-fuzzing on discovered live ports" -ForegroundColor Gray
    Write-Host "    - Real-time port status reporting" -ForegroundColor Gray

    Write-Host "`n  CONFIGURATION FEATURES" -ForegroundColor Cyan
    Write-Host "    - Customizable scan selection and prioritization" -ForegroundColor White
    Write-Host "    - Configurable port ranges for banner grabbing" -ForegroundColor White
    Write-Host "    - Preset configurations for different assessment types" -ForegroundColor White
    Write-Host "    - Interactive configuration menus" -ForegroundColor White
    Write-Host "    - Auto Fuzzing Mode toggle" -ForegroundColor White
    Write-Host "    - Real-time configuration preview" -ForegroundColor White

    Write-Host "`n  PRESET CONFIGURATIONS" -ForegroundColor Cyan
    Write-Host "    Quick setup with optimized scan profiles:" -ForegroundColor White
    Write-Host "    - Basic Recon: Essential information gathering" -ForegroundColor Gray
    Write-Host "    - Web Application: Focus on web app security" -ForegroundColor Gray
    Write-Host "    - Network & DNS: Infrastructure reconnaissance" -ForegroundColor Gray
    Write-Host "    - Content Discovery: Directory and file enumeration" -ForegroundColor Gray
    Write-Host "    - Security Audit: Comprehensive security checks" -ForegroundColor Gray
    Write-Host "    - Stealth Mode: Minimal detection, maximum info" -ForegroundColor Gray
    Write-Host "    - Penetration Test: Full aggressive assessment" -ForegroundColor Gray

    Write-Host "`n  OUTPUT & LOGGING" -ForegroundColor Cyan
    Write-Host "    - Structured console output with color coding" -ForegroundColor White
    Write-Host "    - Comprehensive log files with timestamps" -ForegroundColor White
    Write-Host "    - Automatic directory organization:" -ForegroundColor White
    Write-Host "      - Logs_PowerDns/ - Scan logs and activity records" -ForegroundColor Gray
    Write-Host "      - Fuzz_files/    - Generated wordlists for fuzzing" -ForegroundColor Gray
    Write-Host "    - Real-time progress indicators" -ForegroundColor White
    Write-Host "    - Detailed scan summaries and statistics" -ForegroundColor White

    Write-Host "`n  PERFORMANCE OPTIMIZATIONS" -ForegroundColor Cyan
    Write-Host "    - Parallel request processing" -ForegroundColor White
    Write-Host "    - Configurable timeouts and delays" -ForegroundColor White
    Write-Host "    - Intelligent wordlist optimization" -ForegroundColor White
    Write-Host "    - Memory-efficient processing" -ForegroundColor White
    Write-Host "    - Progressive result display" -ForegroundColor White

    Write-Host "`n  SECURITY, ETHICS AND LEGAL NOTICE" -ForegroundColor Yellow
    Write-Host "    [IMPORTANT] USE ONLY WITH EXPLICIT AUTHORIZATION" -ForegroundColor Red
    Write-Host "" -ForegroundColor White
    Write-Host "    PowerDiNSpec is designed for:" -ForegroundColor White
    Write-Host "    - Authorized penetration testing" -ForegroundColor Gray
    Write-Host "    - Security research and education" -ForegroundColor Gray
    Write-Host "    - Internal security assessments" -ForegroundColor Gray
    Write-Host "    - Bug bounty programs with explicit scope" -ForegroundColor Gray
    Write-Host "" -ForegroundColor White
    Write-Host "    STRICTLY PROHIBITED:" -ForegroundColor Red
    Write-Host "    - Scanning systems without explicit written permission" -ForegroundColor Gray
    Write-Host "    - Testing outside of authorized scope" -ForegroundColor Gray
    Write-Host "    - Malicious or unauthorized activities" -ForegroundColor Gray
    Write-Host "    - Network disruption or denial of service" -ForegroundColor Gray
    Write-Host "" -ForegroundColor White
    Write-Host "    You are solely responsible for ensuring proper authorization and" -ForegroundColor White
    Write-Host "    compliance with all applicable laws and regulations." -ForegroundColor White

    Write-Host "`n  INSTALLATION & USAGE" -ForegroundColor Cyan
    Write-Host "    Requirements:" -ForegroundColor White
    Write-Host "    - Windows PowerShell 5.1 or newer" -ForegroundColor Gray
    Write-Host "    - Internet connectivity for target access" -ForegroundColor Gray
    Write-Host "    - Appropriate execution policy settings" -ForegroundColor Gray
    Write-Host "    - Administrative privileges for some scans" -ForegroundColor Gray
    Write-Host "" -ForegroundColor White
    Write-Host "    Quick Start:" -ForegroundColor White
    Write-Host "    1. Configure scans (Option 0 -> Configure Scans)" -ForegroundColor Gray
    Write-Host "    2. Set port ranges (Option 0 -> Configure Ports)" -ForegroundColor Gray
    Write-Host "    3. Enable Auto Fuzzing if desired (Option 0 -> Auto Fuzzing)" -ForegroundColor Gray
    Write-Host "    4. Run individual scans or complete assessment" -ForegroundColor Gray
    Write-Host "    5. Review logs in Logs_PowerDns/ directory" -ForegroundColor Gray
    Write-Host "    6. Check Fuzz_files/ for generated wordlists" -ForegroundColor Gray

    Write-Host "`n  TIPS & BEST PRACTICES" -ForegroundColor Cyan
    Write-Host "    - Start with Basic Recon preset for initial assessment" -ForegroundColor White
    Write-Host "    - Use Stealth Mode for sensitive environments" -ForegroundColor White
    Write-Host "    - Enable Auto Fuzzing for comprehensive directory discovery" -ForegroundColor White
    Write-Host "    - Monitor scan progress and adjust timeouts as needed" -ForegroundColor White
    Write-Host "    - Review logs for detailed scan information" -ForegroundColor White
    Write-Host "    - Customize port ranges based on target environment" -ForegroundColor White

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
    Write-Host "    Current Version: 2.2.0" -ForegroundColor White
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
    $headers = @{
        "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.0.0 Safari/537.36"
    }

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
                        "Configure: RunAllScans - Option [15]",
                        "Disable : Auto Fuzzing Mode - Option [16]"
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
                    $option_costumization = Show-InputPrompt -input_name "Choose an option (0-4)" -PaddingLeft 35

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
                            Configure-PortsForBanner
                        }
                        3 {
                            Clear-Host
                            Logo_Menu
                            Write-Host "`n==== Configure RunAllScan's ====`n" -ForegroundColor Yellow
                            Write-Host "Configure which scans will be executed when using 'Run All Scans'`n" -ForegroundColor Gray
                            $global:ScansConfig = Configure-ScansInteractive
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

                        }
                        default {
                            Write-Host "`n`n               Invalid option. Choose a number between 0 and 4." -ForegroundColor Red
                            Write-Host "`n               Press Enter to continue..." -ForegroundColor Gray
                            $null = Read-Host
                            continue
                        }
                    } # ← Fecha o switch principal do submenu
                    
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
                        Write-Host "`nStarting recursive fuzzing automatically..." -ForegroundColor Cyan
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
