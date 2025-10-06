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
                                                        //               | |                (_)        |_|                           (_)           2.1.9v

                                         
"@ -split "`n"

    foreach ($line in $ascii) {
        Write-Host $line -ForegroundColor Red
    }
}

$global:PortsForBannerScan = @(21,22,80,443,8080)

$global:AllScans = @(
    @{ Name = "HTTP Status Code";       Enabled = 1; Function = { param($url) ScanStatusCode -url $url } },
    @{ Name = "Page Title";             Enabled = 1; Function = { param($url) ScanTitle -url $url } },
    @{ Name = "IP Address from DNS";    Enabled = 1; Function = { param($url) Get-ip-from-url -url $url } },
    @{ Name = "Allowed HTTP Methods";   Enabled = 1; Function = { param($url) ScanOptions -url $url } },
    @{ Name = "Server Headers";         Enabled = 1; Function = { param($url) ScanHeaders -url $url } },
    @{ Name = "Technologies in Use";    Enabled = 1; Function = { param($url) ScanTech -url $url } },
    @{ Name = "Security Headers Check"; Enabled = 1; Function = { param($url) Test-SecurityHeaders -url $url } },
    @{ Name = "Links in HTML";          Enabled = 1; Function = { param($url) ScanLinks -url $url } },
    @{ Name = "Robots.txt";             Enabled = 1; Function = { param($url) ScanRobotsTxt -url $url } },
    @{ Name = "Sitemap.xml";            Enabled = 1; Function = { param($url) ScanSitemap -url $url } },
    @{ Name = "Searching Record's";     Enabled = 1; Function = { param($url) Get-DNSRecords -url $url } },
    @{ Name = "Port Banner Grabbing";   Enabled = 1; Function = { param($url) Get-PortBanner -url $url } },
    @{ Name = "Words for Fuzzing";      Enabled = 1; Function = { param($url) ScanHTML -url $url } }
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

function PowerDiNSpec {
    $headers = @{
        "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.0.0 Safari/537.36"
    }

    $logFile = "scan_log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    
    # === funcoes de configuração do SUB-MENU ===
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
            Write-Host "[W]" -NoNewline -ForegroundColor DarkGreen
            Write-Host " - Web Checks (1,3,5,6)" -ForegroundColor Gray
            Write-Host "                                                                       Press " -NoNewline -ForegroundColor DarkRed
            Write-Host "[D]" -NoNewline -ForegroundColor DarkGreen
            Write-Host " - DNS & Network (4,8)" -ForegroundColor Gray
            Write-Host "                                                                       Press " -NoNewline -ForegroundColor DarkRed
            Write-Host "[C]" -NoNewline -ForegroundColor DarkGreen
            Write-Host " - Crawling & Discovery (9,10,11,12)" -ForegroundColor Gray
            Write-Host "                                                                       Press " -NoNewline -ForegroundColor DarkRed
            Write-Host "[S]" -NoNewline -ForegroundColor DarkGreen
            Write-Host " - Security & Infra (2,7,12)" -ForegroundColor Gray
            Write-Host "                                                                       Press " -NoNewline -ForegroundColor DarkRed
            Write-Host "[A]" -NoNewline -ForegroundColor DarkGreen
            Write-Host " - Active All (1 to 12)" -ForegroundColor Gray
            Write-Host "`n`n`n                                   - Enter the number corresponding to the function you want to Enable or Disable or Select Preset's`n" -ForegroundColor Yellow
            $input = Show-InputPrompt -input_name "  Press [Enter] to Save and exit" -PaddingLeft 25 -QuestionColor Green
            
            if ([string]::IsNullOrWhiteSpace($input)) {
                $global:ScansConfig = $scans | Where-Object { $_.Enabled -eq 1 }
                Write-Host "`n`n`n      Configuration saved!" -ForegroundColor Green
                Start-Sleep -Seconds 1
                return $global:ScansConfig
            }
            
            switch ($input.ToUpper()) {
                # === Atalhos para grupos ===
                'W' {
                    # Desliga todos
                    for ($i = 0; $i -lt $scans.Count; $i++) {
                        $scans[$i].Enabled = 0
                    }
                    # Liga só os do preset
                    $preset = 1,3,5,6
                    foreach ($i in $preset) { $scans[$i-1].Enabled = 1 }
                    Write-Host "`nWeb checks enabled (HTTP, Title, Methods, Headers)" -ForegroundColor Green
                    Start-Sleep -Seconds 1
                    continue
                }
                'D' {
                    for ($i = 0; $i -lt $scans.Count; $i++) {
                        $scans[$i].Enabled = 0
                    }
                    $preset = 4,8
                    foreach ($i in $preset) { $scans[$i-1].Enabled = 1 }
                    Write-Host "`nDNS & Network scans enabled" -ForegroundColor Green
                    Start-Sleep -Seconds 1
                    continue
                }
                'C' {
                    for ($i = 0; $i -lt $scans.Count; $i++) {
                        $scans[$i].Enabled = 0
                    }
                    $preset = 9,10,11,12
                    foreach ($i in $preset) { $scans[$i-1].Enabled = 1 }
                    Write-Host "`nCrawling & Discovery scans enabled" -ForegroundColor Green
                    Start-Sleep -Seconds 1
                    continue
                }
                'S' {
                    for ($i = 0; $i -lt $scans.Count; $i++) {
                        $scans[$i].Enabled = 0
                    }
                    $preset = 2,7,12
                    foreach ($i in $preset) { $scans[$i-1].Enabled = 1 }
                    Write-Host "`nSecurity & Infra scans enabled" -ForegroundColor Green
                    Start-Sleep -Seconds 1
                    continue
                }
                'A' {
                    # Aqui liga tudo mesmo
                    for ($i = 0; $i -lt $scans.Count; $i++) {
                        $scans[$i].Enabled = 1
                    }
                    Write-Host "`nAll scans enabled (1 to 12)" -ForegroundColor Green
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
    
    # === Funcoes Auxyiliares de Scan === 
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

    # === Funcoes de Scan ===
    function ScanStatusCode {
        param ([String]$url)
        try {
            Write-Host "`n Obtaining HTTP status code..." -ForegroundColor Yellow
            Write-Log "Starting ScanStatusCode for: $url"
            $response = Invoke-WebRequestSafe -Uri $url
            Write-Host "`nStatus Code:" -ForegroundColor Green
            $response.StatusCode
            Write-Log "Status Code: $($response.StatusCode)"
        } catch {
            Handle-WebError -ErrorObject $_
        }
    }
    
    function ScanTitle {
        param ([string]$url)
        try {
            Write-Host "`n Obtaining page title..." -ForegroundColor Yellow
            Write-Log "Starting ScanTitle for: $url"
            
            $response = Invoke-WebRequestSafe -Uri $url
            if ($response -and $response.ParsedHtml -and $response.ParsedHtml.title) {
                Write-Host "`nPage title:" -ForegroundColor Green
                $response.ParsedHtml.title
                Write-Log "Page title: $($response.ParsedHtml.title)"
            } else {
                Write-Host "`nNo title found." -ForegroundColor Red
            }
        } catch {
            Handle-WebError -ErrorObject $_
        }
    }
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

    function ScanOptions {
        param ([string]$url)
        try {
            Write-Host "`n Checking supported HTTP methods..." -ForegroundColor Yellow
            Write-Log "Starting ScanOptions for: $url"

            $response = Invoke-WebRequestSafe -Uri $url -Method Options
            Write-Host "`n Methods allowed by the server:" -ForegroundColor Green
            if ($response.Headers.Allow) {
                $response.Headers.Allow
                Write-Log "Allowed methods: $($response.Headers.Allow)"
            } else {
                Write-Host "No Allow header found in the response." -ForegroundColor Red
            }
        } catch {
            Handle-WebError -ErrorObject $_
        }
    }

    function ScanHeaders {
        param ([string]$url)
        try {
            Write-Host "`n Scanning Headers..." -ForegroundColor Yellow
            Write-Log "Starting ScanHeaders for: $url"

            $response = Invoke-WebRequestSafe -Uri $url -Method Head
            Write-Host "`n The server is running:" -ForegroundColor Green
            if ($response.Headers.Server) {
                $response.Headers.Server
                Write-Log "Server header: $($response.Headers.Server)"
            } else {
                Write-Host "Server header not found." -ForegroundColor Red
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
                'Strict-Transport-Security',
                'Content-Security-Policy', 
                'X-Frame-Options',
                'X-Content-Type-Options',
                'X-XSS-Protection',
                'Referrer-Policy',
                'Permissions-Policy',
                'X-Permitted-Cross-Domain-Policies'
            )
            
            $response = Invoke-WebRequest -Uri $url -Method Head -TimeoutSec 10 -Headers $headers
            
            Write-Host "`nSecurity Headers Analysis:" -ForegroundColor Green
            
            $foundHeaders = 0
            foreach ($header in $securityHeaders) {
                if ($response.Headers[$header]) {
                    Write-Host "  $header : $($response.Headers[$header])" -ForegroundColor Green
                    Write-Log "Security Header found: $header = $($response.Headers[$header])"
                    $foundHeaders++
                } else {
                    Write-Host "  $header : Missing" -ForegroundColor Red
                    Write-Log "Security Header missing: $header" "WARNING"
                }
            }
            
            Write-Host "`n  Summary: $foundHeaders/$($securityHeaders.Count) security headers present" -ForegroundColor $(if ($foundHeaders -ge 5) { "Green" } else { "Yellow" })
            Write-Log "Security Headers check completed: $foundHeaders headers found"
            
        }
        catch {
            Write-Host "  Failed to check security headers: $($_.Exception.Message)" -ForegroundColor Red
            Write-Log "Security Headers check failed: $($_.Exception.Message)" "ERROR"
        }
    }
    function ScanTech {
        param ([string]$url)
        try {
            Write-Host "`n Detecting technologies in use..." -ForegroundColor Yellow
            Write-Log "Starting ScanTech for: $url"

            $response = Invoke-WebRequestSafe -Uri $url
            $techDetected = $false

            if ($response.Headers["x-powered-by"]) {
                Write-Host "`nTechnology detected (X-Powered-By):" -ForegroundColor Green
                $response.Headers["x-powered-by"]
                Write-Log "Technology detected (X-Powered-By): $($response.Headers['x-powered-by'])"
                $techDetected = $true
            }

            if ($response.Headers["server"]) {
                Write-Host "`nServer detected:" -ForegroundColor Green
                $response.Headers["server"]
                Write-Log "Server detected: $($response.Headers['server'])"
                $techDetected = $true
            }

            if (-not $techDetected) {
                Write-Host "No technologies detected in the headers." -ForegroundColor Red
            }
        } catch {
            Handle-WebError -ErrorObject $_
        }
    }

    function Get-DNSRecords {
        param([string]$url)

        $domain = ($url -replace '^https?://', '') -replace '/.*$', ''

        Write-Host "`n Checking DNS records..." -ForegroundColor Yellow
        Write-Log "Starting DNS records check for: $domain" "INFO"

        try {
            Write-Log "Looking for MX records for: $domain" "INFO"
            $mx = Resolve-DnsName -Name $domain -Type MX -ErrorAction Stop
            if ($mx) { 
                Write-host "`n Records found:" -ForegroundColor Green
                Write-Host "   MX Records:" -ForegroundColor Yellow
                $mx | ForEach-Object { 
                    Write-Host "   $($_.NameExchange) (Pref: $($_.Preference))"
                }
                Write-Log "MX records found for: $domain" "INFO"
            }
        }
        catch {
            Write-Host "     No MX records found" -ForegroundColor Red
            Write-Log "No MX records found for: $domain" "WARNING"
        }

        try {
            Write-Log "Looking for NS records for: $domain" "INFO"
            $ns = Resolve-DnsName -Name $domain -Type NS -ErrorAction Stop
            if ($ns) {
                Write-Host "`n   NS Records:" -ForegroundColor Magenta
                $ns | ForEach-Object { 
                    Write-Host "   $($_.NameHost)"
                }
                Write-Log "NS records found for: $domain" "INFO"
            }
        }
        catch {
            Write-Host "     No NS records found" -ForegroundColor Red
            Write-Log "No NS records found for: $domain" "WARNING"
        }

        try {
            Write-Log "Looking for SOA records for: $domain" "INFO"
            $soa = Resolve-DnsName -Name $domain -Type SOA -ErrorAction Stop
            if ($soa) {
                Write-Host "`n   SOA Record:" -ForegroundColor DarkYellow
                $soa | ForEach-Object { 
                    Write-Host "     Primary Server: $($_.PrimaryServer)"
                    Write-Host "     Admin: $($_.NameAdministrator)"
                    Write-Host "     Serial: $($_.SerialNumber)"
                }
                Write-Log "SOA record found for: $domain" "INFO"
            }
        }
        catch {
            Write-Host "     No SOA record found" -ForegroundColor Red
            Write-Log "No SOA record found for: $domain" "WARNING"
        }

        try {
            Write-Log "Looking for CNAME records for: $domain" "INFO"
            $cname = Resolve-DnsName -Name $domain -Type CNAME -ErrorAction Stop
            if ($cname) {
                Write-Host "`n   CNAME Record:" -ForegroundColor DarkGreen
                $cname | ForEach-Object { 
                    Write-Host "     $($_.NameAlias) -> $($_.NameHost)"
                }
                Write-Log "CNAME records found for: $domain" "INFO"
            }
        }
        catch {
            Write-Host "     No CNAME records found" -ForegroundColor Red
            Write-Log "No CNAME records found for: $domain" "WARNING"
        }

        try {
            Write-Log "Looking for TXT records for: $domain" "INFO"
            $txt = Resolve-DnsName -Name $domain -Type TXT -ErrorAction Stop
            if ($txt) {
                Write-Host "`n   TXT Records:" -ForegroundColor DarkCyan
                $txt | ForEach-Object { 
                    Write-Host "     $($_.Strings -join '; ')"
                }
                Write-Log "TXT records found for: $domain" "INFO"
            }
        }
        catch {
            Write-Host "     No TXT records found" -ForegroundColor Red
            Write-Log "No TXT records found for: $domain" "WARNING"
        }

        Write-Log "Starting reverse lookup (PTR) for: $domain" "INFO"
        $ips = @()

        try {
            $a = Resolve-DnsName -Name $domain -Type A -ErrorAction SilentlyContinue
            if ($a) { 
                $ips += $a.IPAddress
                Write-Log "A records found for: $domain" "INFO"
            }
        }
        catch {
            Write-Log "Failed to get A records for: $domain" "WARNING"
        }

        try {
            $aaaa = Resolve-DnsName -Name $domain -Type AAAA -ErrorAction SilentlyContinue
            if ($aaaa) { 
                $ips += $aaaa.IPAddress
                Write-Log "AAAA records found for: $domain" "INFO"
            }
        }
        catch {
            Write-Log "Failed to get AAAA records for: $domain" "WARNING"
        }

        if ($ips.Count -gt 0) {
            Write-Host "`n   Reverse Lookup (PTR):" -ForegroundColor Cyan
            Write-Log "Starting PTR lookups for $($ips.Count) IP addresses" "INFO"
            
            foreach ($ip in $ips) {
                try {
                    $hostEntry = [System.Net.Dns]::GetHostEntry($ip)
                    Write-Host "     $ip -> $($hostEntry.HostName)"
                    Write-Log "PTR found for $ip : $($hostEntry.HostName)" "INFO"
                }
                catch {
                    Write-Host "     $ip -> PTR not found" -ForegroundColor DarkYellow
                    Write-Log "PTR not found for: $ip" "WARNING"
                }
            }
        }
        else {
            Write-Host "`n   No IP addresses found for reverse lookup." -ForegroundColor DarkYellow
            Write-Log "No A or AAAA records found for reverse lookup: $domain" "INFO"
        }

        Write-Log "DNS records check completed for: $domain" "INFO"
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
            Write-Host "`n Content robots.txt:" -ForegroundColor Green
            Write-Host $response.Content
            Write-Log "Robots.txt found and successfully read"
        } catch {
            Write-Host "`nRobots.txt not found or access error." -ForegroundColor Red
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
            Write-Host "`n Sitemap found:" -ForegroundColor Green
            Write-Host $response.Content.Substring(0, [Math]::Min($response.Content.Length, 500))
            Write-Log "Sitemap.xml found and successfully read"
        } catch {
            Write-Host "`nSitemap.xml not found or access error." -ForegroundColor Red
            Write-Log "Sitemap.xml not found: $($_.Exception.Message)" "WARNING"
        }
    }

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
                    Write-Host "    Testing web service on port $Port..." -ForegroundColor Cyan
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
        Write-Host "`n Port scanning completed!`n" -ForegroundColor Green
    }
    function ScanHTML {
        param ([string]$url)
        try {
            Write-Host "`n Obtaining words from the HTML source code..." -ForegroundColor Yellow
            Write-Log "Starting ScanHTML for: $url"
            Start-Sleep -Seconds 2

            $response = Invoke-WebRequestSafe -Uri $url
            $htmlContent = $response.Content

            # Extract words with improved regex
            $palavras = ($htmlContent -split '[^\p{L}0-9_\-]+') |
                        Where-Object { $_.Length -gt 2 -and -not $_.StartsWith('#') -and -not $_.StartsWith('//') } |
                        Select-Object -Unique |
                        Sort-Object

            $commonWords = @('n0n9')
            $palavras = $palavras | Where-Object { $commonWords -notcontains $_.ToLower() }

            Write-Host "`nTotal unique words found: $($palavras.Count)" -ForegroundColor Gray
            Write-Log "Found $($palavras.Count) unique words for fuzzing"

            if ($palavras.Count -gt 0) {
                Write-Host "`nExample of found words (first 10):" -ForegroundColor Yellow
                $palavras | Select-Object -First 10 | ForEach-Object {
                    Write-Host "   $_" -ForegroundColor White
                }

                $save = Read-Host "`nDo you want to save the words to a file for fuzzing? (Y/N)"

                if ($save -eq 'Y' -or $save -eq 'y') {
                    $fuzzingDir = "Fuzz_files"
                    if (-not (Test-Path $fuzzingDir)) {
                        New-Item -ItemType Directory -Path $fuzzingDir -Force | Out-Null
                        Write-Host "`nCreated directory: $fuzzingDir" -ForegroundColor Green
                    }

                    $filePath = Read-Host "`nEnter the file name (default: words_fuzzing.txt)"

                    if ([string]::IsNullOrEmpty($filePath)) {
                        $filePath = "fuzz_words_formated.txt"
                    }
                    
                    $fullPath = Join-Path $fuzzingDir $filePath
                    $palavras | Out-File -FilePath $fullPath -Encoding UTF8
                    
                    Write-Host "`nWords saved to: $fullPath" -ForegroundColor Green
                    Write-Host "Full path: $((Get-Item $fullPath).FullName)" -ForegroundColor Gray
                    Write-Log "Words saved to: $fullPath"
                }
            } else {
                Write-Host "`nNo relevant words were found in the HTML." -ForegroundColor Red
            }

            return $palavras

        } catch {
            Handle-WebError -ErrorObject $_
            return @()
        }
    }
    
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
        Write-Host "`n`n                                                                                 Scan Selecionados:`n" -ForegroundColor DarkRed
        
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
        Start-Sleep -Seconds 1.5
        Write-Host "`n`n               tip: You can configure the scans in the configuration Sub-Menu - Option [0] ." -ForegroundColor Yellow      
        Write-Host ""
        
        #Sleep de 2 segundos
        Start-Sleep -Seconds 3

        $counter = 0
        foreach ($scan in $scansToRun) {
            $counter++
            Write-Host "`n`n=== $counter. $($scan.Name) ===" -ForegroundColor Gray
            try {
                # Execute the scan function, passing the URL as parameter
                & $scan.Function $url
            } catch {
                Write-Host "Error while executing scan: $($_.Exception.Message)" -ForegroundColor Red
            }
            Start-Sleep -Milliseconds 300
        }
        
        Write-Host "`n                                                                               === All checks completed ===`n" -ForegroundColor DarkGreen
        Write-Log "RunAllScans completed for: $url"
        Write-Host "`nPress Enter to continue..." -ForegroundColor Gray
        $null = Read-Host
    }

    function Help {
        Clear-Host
        Logo_Menu
        Write-Host "`n                                                                          ==== HELP - PowerDiNSpec v2.1.9 ====`n" -ForegroundColor Red

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
        Write-Host "`n    [7] Comprehensive DNS Records" -ForegroundColor Green
        Write-Host "        Extensive DNS reconnaissance including:" -ForegroundColor White
        Write-Host "        - MX Records  - Mail server information" -ForegroundColor Gray
        Write-Host "        - NS Records  - Name servers" -ForegroundColor Gray
        Write-Host "        - SOA Records - Zone authority information" -ForegroundColor Gray
        Write-Host "        - CNAME Records - Canonical name mappings" -ForegroundColor Gray
        Write-Host "        - TXT Records - SPF, DKIM, verification records" -ForegroundColor Gray
        Write-Host "        - PTR Records - Reverse DNS lookups" -ForegroundColor Gray
        Write-Host "`n    [8] HTML Link Discovery" -ForegroundColor Green
        Write-Host "        Extracts all HTTP/HTTPS links from page content to map internal and" -ForegroundColor White
        Write-Host "        external resources and identify potential attack surface." -ForegroundColor Gray
        Write-Host "`n    [9] Robots.txt Analysis" -ForegroundColor Green
        Write-Host "        Retrieves and analyzes robots.txt files to discover hidden directories," -ForegroundColor White
        Write-Host "        disallowed paths, and potential sensitive areas." -ForegroundColor Gray
        Write-Host "`n    [10] Sitemap Discovery" -ForegroundColor Green
        Write-Host "        Checks for sitemap.xml files to understand site structure and" -ForegroundColor White
        Write-Host "        discover additional content paths." -ForegroundColor Gray
        Write-Host "`n    [11] Port Banner Grabbing" -ForegroundColor Green
        Write-Host "        Advanced service detection on multiple ports with configurable presets:" -ForegroundColor White
        Write-Host "        - Common Services (21,22,80,443, etc.)" -ForegroundColor Gray
        Write-Host "        - Web Services (80,443,8080,8443, etc.)" -ForegroundColor Gray
        Write-Host "        - Database Ports (1433,1521,3306,5432, etc.)" -ForegroundColor Gray
        Write-Host "        - Email Services (25,110,143,465, etc.)" -ForegroundColor Gray
        Write-Host "        - Custom port ranges supported" -ForegroundColor Gray
        Write-Host "`n    [12] Wordlist Generation for Fuzzing" -ForegroundColor Green
        Write-Host "        Extracts unique words from HTML content to create customized wordlists" -ForegroundColor White
        Write-Host "        for directory brute-forcing, fuzzing, and content discovery." -ForegroundColor Gray
        Write-Host "`n    [13] Run All Scans" -ForegroundColor Green
        Write-Host "        Executes a comprehensive sequential assessment using all enabled scans" -ForegroundColor White
        Write-Host "        with configurable options and real-time progress display." -ForegroundColor Gray
        Write-Host "`n  CONFIGURATION FEATURES" -ForegroundColor Cyan
        Write-Host "    - Customizable scan selection and prioritization" -ForegroundColor White
        Write-Host "    - Configurable port ranges for banner grabbing" -ForegroundColor White
        Write-Host "    - Preset configurations for different assessment types" -ForegroundColor White
        Write-Host "    - Interactive configuration menus" -ForegroundColor White
        Write-Host "`n  OUTPUT & LOGGING" -ForegroundColor Cyan
        Write-Host "    - Structured console output with color coding" -ForegroundColor White
        Write-Host "    - Comprehensive log files with timestamps" -ForegroundColor White
        Write-Host "    - Automatic directory organization:" -ForegroundColor White
        Write-Host "      - Logs_PowerDns/ - Scan logs and activity records" -ForegroundColor Gray
        Write-Host "      - Fuzz_files/    - Generated wordlists for fuzzing" -ForegroundColor Gray
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
        Write-Host "" -ForegroundColor White
        Write-Host "    You are solely responsible for ensuring proper authorization and" -ForegroundColor White
        Write-Host "    compliance with all applicable laws and regulations." -ForegroundColor White
        Write-Host "`n  INSTALLATION & USAGE" -ForegroundColor Cyan
        Write-Host "    Requirements:" -ForegroundColor White
        Write-Host "    - Windows PowerShell 5.1 or newer" -ForegroundColor Gray
        Write-Host "    - Internet connectivity for target access" -ForegroundColor Gray
        Write-Host "    - Appropriate execution policy settings" -ForegroundColor Gray
        Write-Host "" -ForegroundColor White
        Write-Host "    Quick Start:" -ForegroundColor White
        Write-Host "    1. Configure scans (Option 0 -> Configure Scans)" -ForegroundColor Gray
        Write-Host "    2. Set port ranges (Option 0 -> Configure Ports)" -ForegroundColor Gray
        Write-Host "    3. Run individual scans or complete assessment" -ForegroundColor Gray
        Write-Host "    4. Review logs in Logs_PowerDns/ directory" -ForegroundColor Gray
        Write-Host "`n  CREDITS" -ForegroundColor Cyan
        Write-Host "    - Author: Luan Calazans (2025)" -ForegroundColor White
        Write-Host "    - PowerShell-based toolkit design and implementation: Luan Calazans" -ForegroundColor White
        Write-Host "    - Menu ASCII fonts and artwork assistance: WriteAscii project" -ForegroundColor White
        Write-Host "      Font and artwork source: https://github.com/EliteLoser/WriteAscii/blob/master/letters.xml" -ForegroundColor White
        Write-Host "    - Please respect the original font/artwork author and license when" -ForegroundColor White
        Write-Host "`n  LICENSE" -ForegroundColor Cyan
        Write-Host "    GNU Affero General Public License v3.0" -ForegroundColor White
        Write-Host "    This program is free software: you can redistribute it and/or modify" -ForegroundColor Gray
        Write-Host "    it under the terms of the GNU AGPLv3. See LICENSE file for details." -ForegroundColor Gray
        Write-Host "`n  REPOSITORY & SUPPORT" -ForegroundColor Cyan
        Write-Host "    GitHub: https://github.com/Luanqmata/PowerDiNSpec" -ForegroundColor White
        Write-Host "    Issues and contributions welcome via GitHub repository." -ForegroundColor Gray
        Write-Host "`n  FINAL REMINDER" -ForegroundColor Red
        Write-Host "    USE RESPONSIBLY - GET AUTHORIZATION - RESPECT PRIVACY - FOLLOW ETHICS" -ForegroundColor Yellow
        Write-Host "    This tool is for defensive security purposes only." -ForegroundColor White

        Write-Host "`n  Press Enter to return to the submenu..." -ForegroundColor DarkGray
        $null = Read-Host
    }

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
        "Security Headers Analysis",
        "Detect Technologies in Use",
        "Get-DNSRecords",
        "List Links Found in HTML",
        "Check the robots.txt File",
        "Check if Site has a Sitemap",
        "Capture Port's Banner's",
        "Get All Words from the Site",
        "Run All Scans (1 to 13)",
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
                        "Configure:  Cap'port Banner - Option [11]",
                        "Configure:  RunAllScans - Option [13] "
                    )

                    for ($i = 0; $i -lt $submenu.Count; $i++) {
                        $spacing = " " * 57
                        Write-Host -NoNewline "$spacing["
                        Write-Host -NoNewline (" {0} " -f $i) -ForegroundColor Green
                        Write-Host "]   " -NoNewline
                        Write-Host "$($submenu[$i])" -ForegroundColor Yellow
                        Write-Host ""
                    }
                    
                    Write-host "`n`n`n"
                    $option_costumization = Show-InputPrompt -input_name "Choose an option (0-2)" -PaddingLeft 35

                    $choice = 0 
                    if (-not [int]::TryParse($option_costumization, [ref]$choice)) {
                        Write-Host "`n`n`n               Invalid option. Choose a number between 0 and 3." -ForegroundColor Red
                        Write-Host "`n               Press Enter to continue..." -ForegroundColor Gray
                        $null = Read-Host
                        continue
                    }

                    switch ($choice) {
                        0 {
                            break
                        }
                        1 {
                            Help
                            continue
                        }
                        2{
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

                            # Calls the interactive function that returns the enabled scans
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
                        default {
                            Write-Host "`n`n               Invalid option. Choose a number between 0 and 3." -ForegroundColor Red
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
                    Test-SecurityHeaders -url $url
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
                    ScanTech -url $url
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
                    Get-DNSRecords -url $url
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
                    ScanLinks -url $url
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
                    ScanRobotsTxt -url $url
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
                    ScanSitemap -url $url
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
                    Get-PortBanner -url $url
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
                    ScanHTML -url $url
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
                    RunAllScans -url $url
                } else {
                    Write-Host "`n               Invalid URL. Use http:// or https://" -ForegroundColor Red
                    Write-Host "`n               Press Enter to continue..." -ForegroundColor Gray
                    $null = Read-Host
                }
            }
            15 {
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
                Write-Host "`n`n               Invalid option. Choose a number between 1 and 15." -ForegroundColor Red
                Write-Host "`n               Press Enter to continue..." -ForegroundColor Gray
                $null = Read-Host
            }
        }
    }
}

PowerDiNSpec
