
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

function Help {
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
    }