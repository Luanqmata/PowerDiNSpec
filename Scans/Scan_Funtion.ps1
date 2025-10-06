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
        
        Write-Host "    Scanning ports: `n[ $($global:PortsForBannerScan -join ', ') ]`n" -ForegroundColor White
        
        # Define portas web para usar Test-HttpService
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

        foreach ($Port in $PortsShuffled) {
            $delay = Get-Random -Minimum 100 -Maximum 2000
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
                    # Cria a pasta fuzzing_words se não existir
                    $fuzzingDir = "words_4_fuzz"
                    if (-not (Test-Path $fuzzingDir)) {
                        New-Item -ItemType Directory -Path $fuzzingDir -Force | Out-Null
                        Write-Host "`nCreated directory: $fuzzingDir" -ForegroundColor Green
                    }

                    $filePath = Read-Host "`nEnter the file name (default: words_fuzzing.txt)"

                    if ([string]::IsNullOrEmpty($filePath)) {
                        $filePath = "words_fuzzing.txt"
                    }
                    
                    # Salva dentro da pasta fuzzing_words
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