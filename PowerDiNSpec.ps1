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
                                                        //               | |                (_)        |_|                           (_)           2.0.0v

                                         
"@ -split "`n"

    foreach ($line in $ascii) {
        Write-Host $line -ForegroundColor Red
    }
}

function Show-InputPrompt {
    param(
        [string]$User = $env:USERNAME,
        [string]$input_name = ""
    )
    
    $version = [System.Environment]::OSVersion.Version.ToString()

    Write-Host "`n`n               //~--~( " -NoNewline -ForegroundColor Red
    Write-Host "$User" -NoNewline -ForegroundColor Gray
    Write-Host "@Win_Version=" -NoNewline -ForegroundColor Cyan
    Write-Host "/$version/" -NoNewline -ForegroundColor Yellow
    Write-Host " )-[" -NoNewline -ForegroundColor Red
    Write-Host "~" -NoNewline -ForegroundColor White
    Write-Host "]--[" -NoNewline -ForegroundColor Red
    Write-Host "#" -NoNewline -ForegroundColor White
    Write-Host "]---> " -NoNewline -ForegroundColor Red
    Write-Host "$input_name" -ForegroundColor White
    # linha inferior
    Write-Host "              /__~----~" -NoNewline -ForegroundColor Red
    Write-Host " > " -NoNewline -ForegroundColor Red
    Write-Host "@: " -NoNewline -ForegroundColor White

    $origColor = [Console]::ForegroundColor
    [Console]::ForegroundColor = "Magenta"
    $option = Read-Host
    [Console]::ForegroundColor = $origColor
    
    return $option
}

function Busca-Por-DNS {
    $headers = @{
        "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.0.0 Safari/537.36"
    }

    $logFile = "scan_log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

    # === Funções Auxiliares ===
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
        Add-Content -Path $logFile -Value $logMessage
    }

    # === Funções de Scan ===
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
                Write-Host "`n  MX Records:" -ForegroundColor Yellow
                $mx | ForEach-Object { 
                    Write-Host "  $($_.NameExchange) (Pref: $($_.Preference))"
                }
                Write-Log "MX records found for: $domain" "INFO"
            }
        }
        catch {
            Write-Host "    No MX records found" -ForegroundColor Red
            Write-Log "No MX records found for: $domain" "WARNING"
        }

        try {
            Write-Log "Looking for NS records for: $domain" "INFO"
            $ns = Resolve-DnsName -Name $domain -Type NS -ErrorAction Stop
            if ($ns) {
                Write-Host "`n  NS Records:" -ForegroundColor Magenta
                $ns | ForEach-Object { 
                    Write-Host "  $($_.NameHost)"
                }
                Write-Log "NS records found for: $domain" "INFO"
            }
        }
        catch {
            Write-Host "    No NS records found" -ForegroundColor Red
            Write-Log "No NS records found for: $domain" "WARNING"
        }

        try {
            Write-Log "Looking for SOA records for: $domain" "INFO"
            $soa = Resolve-DnsName -Name $domain -Type SOA -ErrorAction Stop
            if ($soa) {
                Write-Host "`n  SOA Record:" -ForegroundColor DarkYellow
                $soa | ForEach-Object { 
                    Write-Host "    Primary Server: $($_.PrimaryServer)"
                    Write-Host "    Admin: $($_.NameAdministrator)"
                    Write-Host "    Serial: $($_.SerialNumber)"
                }
                Write-Log "SOA record found for: $domain" "INFO"
            }
        }
        catch {
            Write-Host "    No SOA record found" -ForegroundColor Red
            Write-Log "No SOA record found for: $domain" "WARNING"
        }

        try {
            Write-Log "Looking for CNAME records for: $domain" "INFO"
            $cname = Resolve-DnsName -Name $domain -Type CNAME -ErrorAction Stop
            if ($cname) {
                Write-Host "`n  CNAME Record:" -ForegroundColor DarkGreen
                $cname | ForEach-Object { 
                    Write-Host "    $($_.NameAlias) -> $($_.NameHost)"
                }
                Write-Log "CNAME records found for: $domain" "INFO"
            }
        }
        catch {
            Write-Host "    No CNAME records found" -ForegroundColor Red
            Write-Log "No CNAME records found for: $domain" "WARNING"
        }

        try {
            Write-Log "Looking for TXT records for: $domain" "INFO"
            $txt = Resolve-DnsName -Name $domain -Type TXT -ErrorAction Stop
            if ($txt) {
                Write-Host "`n  TXT Records:" -ForegroundColor DarkCyan
                $txt | ForEach-Object { 
                    Write-Host "    $($_.Strings -join '; ')"
                }
                Write-Log "TXT records found for: $domain" "INFO"
            }
        }
        catch {
            Write-Host "    No TXT records found" -ForegroundColor Red
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
            Write-Host "`n  Reverse Lookup (PTR):" -ForegroundColor Cyan
            Write-Log "Starting PTR lookups for $($ips.Count) IP addresses" "INFO"
            
            foreach ($ip in $ips) {
                try {
                    $hostEntry = [System.Net.Dns]::GetHostEntry($ip)
                    Write-Host "    $ip -> $($hostEntry.HostName)"
                    Write-Log "PTR found for $ip : $($hostEntry.HostName)" "INFO"
                }
                catch {
                    Write-Host "    $ip -> PTR not found" -ForegroundColor DarkYellow
                    Write-Log "PTR not found for: $ip" "WARNING"
                }
            }
        }
        else {
            Write-Host "`n  No IP addresses found for reverse lookup." -ForegroundColor DarkYellow
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
            [string]$url,
            [int[]]$Ports = @(21,22,80,443,8080)
        )

        Write-Host "`n Checking Port Banner's ... `n" -ForegroundColor Yellow
        Write-Log "Starting Get-PortBanner" "INFO"
        $uri = [System.Uri]$url
        $CleanHost = $uri.Host
        
        foreach ($Port in $Ports) {
            try {
                $client = New-Object System.Net.Sockets.TcpClient
                $client.ReceiveTimeout = 3000
                $client.SendTimeout = 3000
                $client.Connect($CleanHost, $Port)

                if ($client.Connected) {
                    $stream = $client.GetStream()
                    $buffer = New-Object Byte[] 1024
                    Start-Sleep -Milliseconds 500

                    $read = $stream.Read($buffer, 0, 1024)
                    $response = [System.Text.Encoding]::ASCII.GetString($buffer, 0, $read)

                    if ($response) {
                        Write-Host "[${CleanHost}:${Port}] Banner Found:$response" -ForegroundColor Green
                        Write-Log "Banner found on ${CleanHost}:${Port} - $response"
                    } else {
                        Write-Host "[${CleanHost}:${Port}] Sem banner visível" -ForegroundColor Yellow
                        Write-Log "No banner visible on ${CleanHost}:${Port}" "INFO"
                    }
                    $stream.Close()
                    $client.Close()
                }
            }
            catch {
                Write-Host "[${CleanHost}:${Port}] Erro: No Connection Established" -ForegroundColor Red # Erro: $_
                Write-Log "No connection to ${CleanHost}:${Port} - $($_.Exception.Message)" "WARNING"
            }
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

            # Extract words with improved regex
            $palavras = $htmlContent -split '[^\p{L}0-9_\-]+' |
                         Where-Object { $_.Length -gt 2 -and -not $_.StartsWith('#') -and -not $_.StartsWith('//') } |
                         Select-Object -Unique |
                         Sort-Object

            # Filter common words
            $commonWords = @('n0n9')
            $palavras = $palavras | Where-Object { $commonWords -notcontains $_.ToLower() }

            Write-Host "`nTotal unique words found: $($palavras.Count)" -ForegroundColor Gray
            Write-Log "Found $($palavras.Count) unique words for fuzzing"

            if ($palavras.Count -gt 0) {
                # Show example words
                Write-Host "`nExample of found words (first 10):" -ForegroundColor Yellow
                $palavras | Select-Object -First 10 | ForEach-Object {
                    Write-Host "   $_" -ForegroundColor White
                }

                $save = Read-Host "`nDo you want to save the words to a file for fuzzing? (Y/N)"

                if ($save -eq 'Y' -or $save -eq 'y') {
                    $filePath = Read-Host "`nEnter the file name (default: words_fuzzing.txt)"

                    if ([string]::IsNullOrEmpty($filePath)) {
                        $filePath = "words_fuzzing.txt"
                    }
                    $palavras | Out-File -FilePath $filePath -Encoding UTF8
                    $fullPath = (Get-Item $filePath).FullName
                    Write-Host "`nWords saved to: $filePath" -ForegroundColor Green
                    Write-Host "Full path: $fullPath" -ForegroundColor Gray
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
        #Logo_Menu # fazer um logo_menu 2
        Write-Host "`n                                  === Starting all checks for URL: $url ===`n" -ForegroundColor Red
        Write-Log "Starting RunAllScans for: $url"
        
        $scans = @(
            @{Name="HTTP Status Code"; Function={ScanStatusCode -url $url}},
            @{Name="Page Title"; Function={ScanTitle -url $url}},
            @{Name="IP Address from DNS"; Function={Get-ip-from-url -url $url}},
            @{Name="Allowed HTTP Methods"; Function={ScanOptions -url $url}},
            @{Name="Server Headers"; Function={ScanHeaders -url $url}}, 
            @{Name="Technologies in Use"; Function={ScanTech -url $url}},
            @{Name="Links in HTML"; Function={ScanLinks -url $url}}, 
            @{Name="Robots.txt"; Function={ScanRobotsTxt -url $url}},
            @{Name="Sitemap.xml"; Function={ScanSitemap -url $url}},
            @{Name="Searching Record's"; Function={Get-DNSRecords -url $url}},
            @{Name="Port Banner Grabbing"; Function={Get-PortBanner -url $url}},
            @{Name="Words for Fuzzing"; Function={ScanHTML -url $url}}   
        )
        
        $counter = 0
        foreach ($scan in $scans) {
            $counter++
            Write-Host "`n=== $counter. $($scan.Name) ===" -ForegroundColor Gray
            & $scan.Function
            Start-Sleep -Milliseconds 300
        }
        
        Write-Host "`n                                                  === All checks completed ===`n" -ForegroundColor Green
        Write-Log "RunAllScans completed for: $url"
        Write-Host "`nPress Enter to continue..." -ForegroundColor Gray
        $null = Read-Host
    }

# === Menu Principal ===
while ($true) {
    Clear-Host
    Logo_Menu
    Write-Host ""

    $menus = @(
        "Help & Customization",
        "Get HTTP Status Code",
        "Get the Page <title>",
        "Get IP Address from DNS",
        "Discover Allowed HTTP Methods",
        "Capture Server Headers",
        "Detect Technologies in Use",
        "Get-DNSRecords",
        "List Links Found in HTML",
        "Check the robots.txt File",
        "Check if Site has a Sitemap",
        "Capture Port's Banner's",
        "Get All Words from the Site",
        "Run All Scans (1 to 10)",
        "Exit"
    )

    for ($i=0; $i -lt $menus.Count; $i++) {
        $num = $i 
        $spacing = " " * 74
        Write-Host -NoNewline "$spacing["
        Write-Host -NoNewline (" {0} " -f $num) -ForegroundColor Cyan
        Write-Host "]   " -NoNewline
        Write-Host "$($menus[$i])" -ForegroundColor Red
        Write-Host ""
    }

    Write-Host "`n `n`n                                                                                                                                 Log is being saved to: $logFile" -ForegroundColor Yellow
    Write-Host "`n"

    # === Read-Host em vermelho ===
    $option = Show-InputPrompt -input_name "Choose an option (1-14)"

        switch ($option) {
            0 {
                while ($true) {
                    Clear-Host
                    Logo_Menu

                    $submenu = @(
                        "Back to Main Menu",
                        "Help",
                        "Customization"
                    )

                    for ($i = 0; $i -lt $submenu.Count; $i++) {
                        $spacing = " " * 74
                        Write-Host -NoNewline "$spacing["
                        Write-Host -NoNewline (" {0} " -f $i) -ForegroundColor Cyan
                        Write-Host "]   " -NoNewline
                        Write-Host "$($submenu[$i])" -ForegroundColor Red
                        Write-Host ""
                    }

                    $option_costumization = Show-InputPrompt -input_name "Choose an option (0-2)"

                    $choice = 0 
                    if (-not [int]::TryParse($option_costumization, [ref]$choice)) {
                        Write-Host "`n`n`n               Invalid option. Choose a number between 0 and 2." -ForegroundColor Red
                        Write-Host "`n               Press Enter to continue..." -ForegroundColor Gray
                        $null = Read-Host
                        continue
                    }

                    switch ($choice) {
                        0 {
                            # não faz nada aqui (sai do switch)
                            break
                        }
                        1 {
                            Clear-Host
                            Logo_Menu
                            Write-Host "`n                                                                          ==== HELP ====`n" -ForegroundColor Red

                            Write-Host "`n  POWERDINSPEC - PowerShell DNS Recon Tool" -ForegroundColor Yellow
                            Write-Host "`n  PowerDiNSpec is a PowerShell-based reconnaissance toolkit for websites" -ForegroundColor White
                            Write-Host "  and DNS records. It is intended for security researchers, pentesters and" -ForegroundColor White
                            Write-Host "  lab use. This help section is intentionally long and detailed. Read it" -ForegroundColor White
                            Write-Host "  carefully. You will see repeated emphasis on ethics, scope and proper use." -ForegroundColor White

                            Write-Host "`n  OVERVIEW" -ForegroundColor Cyan
                            Write-Host "    PowerDiNSpec automates a sequence of reconnaissance tasks against a" -ForegroundColor White
                            Write-Host "    specified URL or host. Each check is non-invasive by design but may" -ForegroundColor White
                            Write-Host "    still trigger alarms on remote systems. Use with authorization." -ForegroundColor White

                            Write-Host "`n  FEATURES (DETAILED)" -ForegroundColor Cyan
                            Write-Host "    - Capture server headers:" -ForegroundColor White
                            Write-Host "        Retrieves HTTP response headers and common server header fields" -ForegroundColor White
                            Write-Host "        such as Server, X-Powered-By and other header values useful for" -ForegroundColor White
                            Write-Host "        fingerprinting server software and versions." -ForegroundColor White
                            Write-Host ""
                            Write-Host "    - Discover allowed HTTP methods:" -ForegroundColor White
                            Write-Host "        Enumerates HTTP methods reported by the target and reports methods" -ForegroundColor White
                            Write-Host "        like GET, POST, OPTIONS, HEAD, PUT, DELETE, TRACE and others." -ForegroundColor White
                            Write-Host ""
                            Write-Host "    - List links found in HTML:" -ForegroundColor White
                            Write-Host "        Parses HTML content and extracts href/src links. This helps map" -ForegroundColor White
                            Write-Host "        internal pages, external references and potential attack surface." -ForegroundColor White
                            Write-Host ""
                            Write-Host "    - Extract words from HTML for fuzzing:" -ForegroundColor White
                            Write-Host "        Collects words and tokens from page HTML to compose wordlists for" -ForegroundColor White
                            Write-Host "        fuzzing, brute force or directory discovery tools in your workflow." -ForegroundColor White
                            Write-Host ""
                            Write-Host "    - Detect technologies in use:" -ForegroundColor White
                            Write-Host "        Attempts to infer frameworks, libraries and server software using" -ForegroundColor White
                            Write-Host "        header values and heuristics. Useful to guide follow-up testing." -ForegroundColor White
                            Write-Host ""
                            Write-Host "    - Get HTTP status codes:" -ForegroundColor White
                            Write-Host "        Shows the HTTP status code(s) returned by the target for the" -ForegroundColor White
                            Write-Host "        requested resource. Includes handling of redirects and final code." -ForegroundColor White
                            Write-Host ""
                            Write-Host "    - Search for IP addresses (DNS lookup):" -ForegroundColor White
                            Write-Host "        Retrieves IPv4 (A) and IPv6 (AAAA) addresses for the given domain." -ForegroundColor White
                            Write-Host "        Displays the found IPs or indicates if none are available." -ForegroundColor White
                            Write-Host ""
                            Write-Host "    - Retrieve <title> of the page:" -ForegroundColor White
                            Write-Host "        Reads the HTML title element to capture target page title metadata." -ForegroundColor White
                            Write-Host ""
                            Write-Host "    - Check robots.txt and sitemap.xml:" -ForegroundColor White
                            Write-Host "        Fetches and shows robots.txt and sitemap.xml when present. These" -ForegroundColor White
                            Write-Host "        files often reveal allowed/disallowed paths and sitemap locations." -ForegroundColor White
                            Write-Host ""
                            Write-Host "    - Capture service banners (ports):" -ForegroundColor White
                            Write-Host "        Optionally connects to given ports to read plaintext banners and" -ForegroundColor White
                            Write-Host "        service identifiers (when available)." -ForegroundColor White
                            Write-Host ""
                            Write-Host "    - Check DNS records for a domain:" -ForegroundColor White
                            Write-Host "        Retrieves DNS information including MX, NS, SOA, CNAME, TXT records," -ForegroundColor White
                            Write-Host "        and performs reverse lookup (PTR) for associated IP addresses." -ForegroundColor White
                            Write-Host "        Provides detailed output for each record type when available." -ForegroundColor White
                            Write-Host ""
                            Write-Host "    - Run All Scans (aggregate):" -ForegroundColor White
                            Write-Host "        Executes a sequential run of the major checks and compiles results." -ForegroundColor White
                            Write-Host ""
                            Write-Host "    - Logging:" -ForegroundColor White
                            Write-Host "        All actions, responses and summaries are written to a timestamped" -ForegroundColor White
                            Write-Host "        log file in the script directory for later review and auditing." -ForegroundColor White

                            Write-Host "`n  SECURITY, ETHICS AND LEGAL NOTICE" -ForegroundColor Yellow
                            Write-Host "    PowerDiNSpec is provided for educational, research and authorized" -ForegroundColor White
                            Write-Host "    security testing only. Running scans or probes against systems you do" -ForegroundColor White
                            Write-Host "    not own or do not have explicit permission to test may be illegal and" -ForegroundColor White
                            Write-Host "    could expose you to civil or criminal liability." -ForegroundColor White
                            Write-Host ""
                            Write-Host "    You must obtain written authorization before scanning third-party" -ForegroundColor White
                            Write-Host "    targets. Always follow your organization or client rules of engagement." -ForegroundColor White
                            Write-Host ""
                            Write-Host "    Repeated reminder: USE THIS TOOL ONLY WITH AUTHORIZATION." -ForegroundColor Red
                            Write-Host "    Use of the tool without authorization is strictly prohibited." -ForegroundColor Red

                            Write-Host "`n  INSTALLATION & PREREQUISITES" -ForegroundColor Cyan
                            Write-Host "    - Windows with PowerShell 5.1 or later is required." -ForegroundColor White
                            Write-Host "    - Clone or download the repository to a local folder." -ForegroundColor White
                            Write-Host "      Example: git clone https://github.com/Luanqmata/PowerDiNSpec.git" -ForegroundColor White
                            Write-Host "    - Change to the repository folder: cd PowerDiNSpec" -ForegroundColor White
                            Write-Host "    - Unlock script execution if required (adjust ExecutionPolicy as needed)." -ForegroundColor White
                            Write-Host "    - Ensure network connectivity and DNS resolution for the target hosts." -ForegroundColor White

                            Write-Host "`n  EXAMPLE: RUNNING ALL SCANS" -ForegroundColor Cyan
                            Write-Host "    - From the main menu choose the option that runs all scans (Run All)." -ForegroundColor White
                            Write-Host "    - Enter the target URL when requested (for example: https://example.com)." -ForegroundColor White
                            Write-Host "    - The tool will perform the sequence of checks and append output to" -ForegroundColor White
                            Write-Host "      the log file. Review logs for details and follow-up tasks." -ForegroundColor White

                            Write-Host "`n  LOGGING & OUTPUT" -ForegroundColor Cyan
                            Write-Host "    - Logs are written to the script directory with timestamps in filenames." -ForegroundColor White
                            Write-Host "    - Each run appends a summary header and the raw outputs for each check." -ForegroundColor White
                            Write-Host "    - Use the logs for audit, reporting and reproduction of findings." -ForegroundColor White

                            Write-Host "`n  CREDITS" -ForegroundColor Cyan
                            Write-Host "    - Author: Luan Calazans (2025)" -ForegroundColor White
                            Write-Host "    - PowerShell-based toolkit design and implementation: Luan Calazans" -ForegroundColor White
                            Write-Host "    - Menu ASCII fonts and artwork assistance: WriteAscii project" -ForegroundColor White
                            Write-Host "      Font and artwork source: https://github.com/EliteLoser/WriteAscii/blob/master/letters.xml" -ForegroundColor White
                            Write-Host "    - Please respect the original font/artwork author and license when" -ForegroundColor White

                            Write-Host "`n  FULL DISCLAIMER" -ForegroundColor Yellow
                            Write-Host "    PowerDiNSpec is distributed without any warranty. The author is not" -ForegroundColor White
                            Write-Host "    responsible for misuse or damage caused by this tool. You assume all" -ForegroundColor White
                            Write-Host "    responsibility for its use." -ForegroundColor White

                            Write-Host "`n  SUPPORT & REPOSITORY" -ForegroundColor Cyan
                            Write-Host "    - GitHub: https://github.com/Luanqmata/PowerDiNSpec" -ForegroundColor White
                            Write-Host "    - Issues, feature requests and contributions are welcome via the" -ForegroundColor White
                            Write-Host "      repository issue tracker." -ForegroundColor White

                            Write-Host "`n  REMARK: THIS HELP IS INTENTIONALLY VERBOSE" -ForegroundColor Red
                            Write-Host "    You have just read a long help section. It is intentionally wordy" -ForegroundColor White
                            Write-Host "    to ensure users pay attention to ethics, usage rules, and details." -ForegroundColor White
                            Write-Host "    REREAD THE SECTIONS ABOVE IF NECESSARY." -ForegroundColor White

                            Write-Host "`n  Press Enter to return to the submenu..." -ForegroundColor DarkGray
                            $null = Read-Host

                            continue
                        }
                        2 {
                            Clear-Host
                            Logo_Menu
                            Write-Host "`n==== CUSTOMIZATION ====`n" -ForegroundColor Yellow
                            Write-Host "          WORKING..." -ForegroundColor White
                            Write-Host "`nPress Enter to return to the submenu..." -ForegroundColor Gray
                            $null = Read-Host
                            continue
                        }
                        default {
                            Write-Host "`n`n               Invalid option. Choose a number between 0 and 2." -ForegroundColor Red
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
                $url = Show-InputPrompt -input_name "Enter the website URL (ex: http://scanme.nmap.org)"
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
                $url = Show-InputPrompt -input_name "Enter the website URL (ex: http://scanme.nmap.org)"
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
                $url = Show-InputPrompt -input_name "Enter the website URL (ex: http://scanme.nmap.org)"
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
                $url = Show-InputPrompt -input_name "Enter the website URL (ex: http://scanme.nmap.org)"
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
                $url = Show-InputPrompt -input_name "Enter the website URL (ex: http://scanme.nmap.org)"
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
                $url = Show-InputPrompt -input_name "Enter the website URL (ex: http://scanme.nmap.org)"
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
                $url = Show-InputPrompt -input_name "Enter the website URL (ex: http://scanme.nmap.org)"
                if (Test-ValidUrl $url) {
                    Get-DNSRecords -url $url
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
                $url = Show-InputPrompt -input_name "Enter the website URL (ex: http://scanme.nmap.org)"
                if (Test-ValidUrl $url) {
                    ScanLinks -url $url
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
                $url = Show-InputPrompt -input_name "Enter the website URL (ex: http://scanme.nmap.org)"
                if (Test-ValidUrl $url) {
                    ScanRobotsTxt -url $url
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
                $url = Show-InputPrompt -input_name "Enter the website URL (ex: http://scanme.nmap.org)"
                if (Test-ValidUrl $url) {
                    ScanSitemap -url $url
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
                $url = Show-InputPrompt -input_name "Enter the website URL (ex: http://scanme.nmap.org)"
                if (Test-ValidUrl $url) {
                    Get-PortBanner -url $url
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
                $url = Show-InputPrompt -input_name "Enter the website URL (ex: http://scanme.nmap.org)"
                if (Test-ValidUrl $url) {
                    ScanHTML -url $url
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
                $url = Show-InputPrompt -input_name "Enter the website URL (ex: http://scanme.nmap.org)"
                if (Test-ValidUrl $url) {
                    RunAllScans -url $url
                } else {
                    Write-Host "`n               Invalid URL. Use http:// or https://" -ForegroundColor Red
                    Write-Host "`n               Press Enter to continue..." -ForegroundColor Gray
                    $null = Read-Host
                }
            }
            14 {
                Clear-Host
                Logo_Menu

                Write-Host ""
                Write-Host "             Exiting . . ." -ForegroundColor Cyan
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
                Write-Host "`n`n               Invalid option. Choose a number between 1 and 14." -ForegroundColor Red
                Write-Host "`n               Press Enter to continue..." -ForegroundColor Gray
                $null = Read-Host
            }
        }
    }
}

Busca-Por-DNS
