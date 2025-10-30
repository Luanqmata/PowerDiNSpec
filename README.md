
# PowerDiNSpec - PowerShell DNS Recon Tool v2.3.4

---

<img width="1407" height="987" alt="image" src="https://github.com/user-attachments/assets/4fbe9cb6-d393-4aef-ae03-7eeb399388eb" />

---

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-blue.svg)](https://docs.microsoft.com/powershell/)
[![License](https://img.shields.io/badge/License-AGPL--3.0-green.svg)](https://www.gnu.org/licenses/agpl-3.0.en.html)
[![Version](https://img.shields.io/badge/Version-2.3.0-red.svg)]()

PowerDiNSpec is an advanced PowerShell-based reconnaissance toolkit designed for comprehensive security assessments, penetration testing, and authorized vulnerability research. It provides extensive reconnaissance capabilities for web applications and DNS infrastructure.

---

## 🚀 Features Overview

### 🔍 Web Application Reconnaissance
- **HTTP Status Code Analysis** - Comprehensive status code analysis with color-coded categorization
- **Page Title Extraction** - Extract and analyze HTML page titles with length analysis
- **HTTP Methods Discovery** - Enumerate allowed HTTP methods with risk assessment
- **Server Headers Analysis** - Capture and analyze server headers and technologies
- **Technology Detection** - Advanced fingerprinting of frameworks, CMS, and server software
- **Security Headers Audit** - Comprehensive security headers analysis with scoring
- **HTML Link Discovery** - Extract all HTTP/HTTPS links from page content
- **Robots.txt Analysis** - Detailed robots.txt analysis with sensitive path detection
- **Sitemap Discovery** - XML sitemap analysis with URL categorization

### 🌐 DNS & Network Reconnaissance
- **DNS IP Resolution** - Comprehensive IPv4/IPv6 DNS lookups
- **DNS Zone Transfer Testing** - Test for DNS zone transfer vulnerabilities
- **Complete DNS Records** - Extensive DNS reconnaissance (A, AAAA, MX, NS, SOA, CNAME, TXT, PTR)
- **Port Banner Grabbing** - Advanced service detection on multiple ports
- **Reverse DNS Lookups** - PTR record analysis for discovered IPs

### ⚡ Advanced Fuzzing & Discovery
- **Wordlist Generation** - Extract unique words from HTML for customized fuzzing
- **Recursive Directory Fuzzing** - Advanced recursive discovery with configurable depth
- **Auto Fuzzing Mode** - Automated fuzzing pipeline with intelligent wordlist handling
- **Smart Duplicate Filtering** - Hash-based content deduplication
- **Real-time Progress Tracking** - Visual progress bars and statistics

### 🎯 Configuration & Presets
- **Customizable Scan Selection** - Enable/disable specific scans
- **Port Configuration** - Configurable port ranges with preset options
- **Fuzzing Parameters** - Granular control over depth, timeouts, and threads
- **Status Code Filtering** - Customizable HTTP status code filters
- **Multiple Presets** - Optimized configurations for different scenarios

---

## 🛠 Installation & Setup

### System Requirements
- Windows PowerShell 5.1 or newer
- Internet connectivity for target access
- Appropriate execution policy settings

### Quick Installation
```Ruby
# Clone the repository
git clone https://github.com/Luanqmata/PowerDiNSpec.git

# Navigate to directory
cd PowerDiNSpec

# Unlock execution policy (Windows 10/11)
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process

# Run the tool
.\PowerDiNSpec.ps1
```

### Execution Policy Solutions
```Ruby
# Method 1: Process scope (Recommended)
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process

# Method 2: Bypass for single session
powershell -ExecutionPolicy Bypass -File .\PowerDiNSpec.ps1

# Method 3: Current user scope
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

---

## 📖 Usage Guide

### Basic Usage
- Launch the tool: Run the PowerShell script
- Configure scans (Option 0): Set up your scanning preferences
- Choose target: Select individual scans or run comprehensive assessment
- Review results: Analyze findings in console and log files

### Scan Options Menu
```Ruby
[ 0 ]   Help & Configuration
[ 1 ]   Get HTTP Status Code
[ 2 ]   Get the Page <title>
[ 3 ]   Get IP Address from DNS
[ 4 ]   Discover Allowed HTTP Methods
[ 5 ]   Capture Server Headers
[ 6 ]   Detect Technologies in Use
[ 7 ]   Security Headers Analysis
[ 8 ]   DNS Zone Transfer Test
[ 9 ]   Check DNS Records
[ 10 ]   List Links Found in HTML
[ 11 ]   Check the robots.txt File
[ 12 ]   Check if Site has a Sitemap
[ 13 ]   Capture Port's Banner's
[ 14 ]   Get All Words from the Site
[ 15 ]   Fuzzing Recursive
[ 16 ]   Run All Scans (1 to 14)
[ 17 ]   Exit
```

### Configuration Submenu
```Ruby
[ 0 ]   Back Menu
[ 1 ]   Help
[ 2 ]   Configure: Cap'port Banner - Option [13]
[ 3 ]   Configure: RunAllScans - Option [16]
[ 4 ]   Toggle Auto Fuzzing Mode - Option [16]
[ 5 ]   Configure: Fuzzing Recursive - Option [15]
```

---

## ⚙️ Configuration Presets

### Scan Presets
- 🟢 **Basic Recon**: Essential information gathering (Status, Title, IP, Headers, Technologies)
- 🔵 **Web Application**: Focus on web app security (Status, Title, Methods, Headers, Technologies, Links)
- 🟡 **Network & DNS**: Infrastructure reconnaissance (IP, Zone Transfer, DNS Records, Ports)
- 🟣 **Content Discovery**: Directory and file enumeration (Links, Robots, Sitemap, Words)
- 🔴 **Security Audit**: Comprehensive security checks (Title, Methods, Security Headers, Zone Transfer, Ports)
- 🕵️ **Stealth Mode**: Minimal detection, maximum information
- ⚡ **Penetration Test**: Full aggressive assessment

### Port Configuration Presets
- **Common Services**: 21,22,23,25,53,80,443,3306,3389,5432,8080
- **Web Services**: 80,443,8080,8443,8888,9090,9080,8000,3000,5000
- **Database Ports**: 1433,1521,3306,5432,27017,6379,5984,9200,9300,11211
- **Email Services**: 25,110,143,465,587,993,995,2525
- **Custom Ranges**: User-defined port lists

---

## 🔬 Advanced Features

### Auto Fuzzing Mode
When enabled, automatically launches recursive fuzzing after word extraction:

1. Extracts words from HTML content
2. Automatically saves optimized wordlists
3. Launches recursive directory discovery
4. Provides real-time progress and results

### Intelligent Recursive Fuzzing
- **Infinite Depth**: Configurable recursion levels (1-10)
- **Smart Filtering**: Hash-based duplicate detection
- **Adaptive Discovery**: Pattern-based directory exploration
- **Real-time Analytics**: Requests/second, success rates, filtering statistics

### Comprehensive Logging
- Structured Logs: Timestamped activity records in `Logs_PowerDns/`
- Wordlist Storage: Generated wordlists in `Fuzz_files/`
- Scan Results: CSV exports for fuzzing discoveries
- Error Tracking: Detailed error reporting and troubleshooting

---

## 📊 Output Examples

### Sample Scan Output
```Ruby
=== 1. HTTP Status Code ===
Status Code: 200 OK
Category: Success

=== 2. Page Title ===
Page title: Example Corporation - Home
Length: 32 characters

=== 3. DNS IP Resolution ===
IPv4 Address: 192.0.2.1
IPv6 Address: 2001:db8::1
```

### Fuzzing Results
```Ruby
[200 - OK] Depth 2 - https://target.com/admin/login
       Title: Administration Panel
       Size: 5421 bytes

[403 - FORBIDDEN] Depth 1 - https://target.com/backup
       Size: 312 bytes
```

---

## ⚠️ Security & Ethical Usage

### Legal Notice
PowerDiNSpec is designed for authorized security assessments only.

### Authorized Use Cases
- ✅ Penetration testing with explicit written permission
- ✅ Security research in controlled lab environments
- ✅ Educational purposes and cybersecurity training
- ✅ Bug bounty programs within defined scope
- ✅ Internal security assessments on owned infrastructure

### Strictly Prohibited
- ❌ Scanning systems without explicit authorization
- ❌ Testing outside of approved scope boundaries
- ❌ Malicious or unauthorized activities
- ❌ Network disruption or denial of service
- ❌ Privacy violations or data theft

You are solely responsible for ensuring proper authorization and compliance with all applicable laws, regulations, and organizational policies.

---

## 🗂 File Structure
```Ruby
PowerDiNSpec/
├── PowerDiNSpec.ps1          # Main script file
├── Logs_PowerDns/            # Scan logs and activity records
│   └── scan_log_YYYYMMDD_HHMMSS.txt
├── Fuzz_files/               # Generated wordlists
│   └── wordlist_domain_timestamp.txt
└── fuzzing_results_timestamp.csv    # Fuzzing discovery exports
```

---

## 🔧 Troubleshooting

### Common Issues
```Ruby
# Execution Policy Error
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process

# Module Import Issues
Install-Module -Name DnsClient -Force

# Network Timeouts
# Adjust timeout settings in configuration menu
```

### Performance Tips
- Use Stealth Mode for sensitive environments
- Configure appropriate timeout values for your network
- Enable Auto Fuzzing for comprehensive assessments
- Monitor memory usage during large-scale fuzzing

---

## 📄 License
This program is licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)**. You may redistribute and/or modify it under the terms of this license.

```
Copyright (C) 2025 Luan Calazans
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions. See the LICENSE file for details.
```

---

## 👨‍💻 Author & Credits
**Luan Calazans** - 2025  
Cybersecurity Researcher & Tool Developer

**Credits**
- PowerShell Community - Foundation and inspiration
- WriteAscii Project - ASCII art fonts and styling
- Security Researchers - Testing and feedback contributions

Contributions, issues, and feature requests are welcome! Feel free to check the issues page.

---

## 🌟 Support & Resources
- Documentation: Comprehensive help system included in tool
- GitHub Repository: https://github.com/Luanqmata/PowerDiNSpec
- Issue Tracking: GitHub Issues for bug reports and feature requests
- Community: PowerShell and cybersecurity forums

---

*Powered by PowerShell ☕💻 — Built for Security Professionals 🔒🛡️*

*Remember: With great power comes great responsibility. Always use ethical hacking principles and obtain proper authorization before conducting security assessments.*

---

<img width="1227" height="908" alt="image" src="https://github.com/user-attachments/assets/c5199238-c467-494c-9fa6-141b7942f0b6" />

---

<img width="1196" height="916" alt="image" src="https://github.com/user-attachments/assets/a359eebe-4a82-4657-bf0d-0743936b11e6" />

---

<img width="1370" height="981" alt="image" src="https://github.com/user-attachments/assets/b91d8913-ef94-4e81-a388-3af22688c81c" />

