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

. .\Style\Styles.ps1
. .\Config\Fun_Config.ps1
. .\Config\Fun_Aux_Config.ps1
. .\Scans\Scan_Funtion.ps1


$global:PortsForBannerScan = @(21,22,80,443,8080)

$global:AllScans = @(
    @{ Name = "HTTP Status Code";       Enabled = 1; Function = { param($url) ScanStatusCode -url $url } },
    @{ Name = "Page Title";             Enabled = 1; Function = { param($url) ScanTitle -url $url } },
    @{ Name = "IP Address from DNS";    Enabled = 1; Function = { param($url) Get-ip-from-url -url $url } },
    @{ Name = "Allowed HTTP Methods";   Enabled = 1; Function = { param($url) ScanOptions -url $url } },
    @{ Name = "Server Headers";         Enabled = 1; Function = { param($url) ScanHeaders -url $url } },
    @{ Name = "Technologies in Use";    Enabled = 1; Function = { param($url) ScanTech -url $url } },
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

function PowerDiNSpec {
    $headers = @{
        "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.0.0 Safari/537.36"
    }

    $logFile = "scan_log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt" 
 
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
        "Get-DNSRecords",
        "List Links Found in HTML",
        "Check the robots.txt File",
        "Check if Site has a Sitemap",
        "Capture Port's Banner's",
        "Get All Words from the Site",
        "Run All Scans (1 to 12)",
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
                $url = Show-InputPrompt -input_name "Enter the website URL (ex: http://scanme.nmap.org)" -PaddingLeft 19
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
                $url = Show-InputPrompt -input_name "Enter the website URL (ex: http://scanme.nmap.org)" -PaddingLeft 19
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
                $url = Show-InputPrompt -input_name "Enter the website URL (ex: http://scanme.nmap.org)" -PaddingLeft 19
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
                $url = Show-InputPrompt -input_name "Enter the website URL (ex: http://scanme.nmap.org)" -PaddingLeft 19
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
                $url = Show-InputPrompt -input_name "Enter the website URL (ex: http://scanme.nmap.org)" -PaddingLeft 19
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
                $url = Show-InputPrompt -input_name "Enter the website URL (ex: http://scanme.nmap.org)" -PaddingLeft 19
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
                Write-Host "`n`n               Invalid option. Choose a number between 1 and 14." -ForegroundColor Red
                Write-Host "`n               Press Enter to continue..." -ForegroundColor Gray
                $null = Read-Host
            }
        }
    }
}

PowerDiNSpec