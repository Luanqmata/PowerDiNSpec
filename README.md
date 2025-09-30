# PowerDiNSpec

<img width="1373" height="732" alt="image" src="https://github.com/user-attachments/assets/288c8138-d75d-49cf-a761-cadc18336f08" />


##  **PowerShell DNS Recon Tool**
  


PowerDiNSpec is a PowerShell-based tool designed to help security enthusiasts and penetration testers perform reconnaissance on websites and DNS records. It allows you to scan server headers, HTTP methods, links, HTML words, detect technologies, check status codes, and more.

---

## Features

* Capture server headers
* Discover allowed HTTP methods
* List links found in HTML
* Extract words from website HTML for fuzzing
* Detect technologies in use (X-Powered-By, Server)
* Get HTTP status codes
* Retrieve the `<title>` of the page
* Check for `robots.txt`
* Check for `sitemap.xml`
* Check for Banner
* Run all scans automatically
* Log all actions to a file

---
## Security & Ethical Use Notice ⚠️

PowerDiNSpec is intended only for educational purposes, authorized penetration testing, or personal lab environments.
Using this tool on websites or networks without explicit permission from the owner may be illegal and could result in criminal or civil penalties.

Always ensure you have authorization before scanning any system and respect the ethical guidelines of cybersecurity.

---

## Installation

1. Make sure you have **PowerShell 5.1** or later installed on Windows.
2. Clone or download this repository:

```powershell
git clone https://github.com/Luanqmata/PowerDiNSpec.git
```

3. Navigate to the folder:

```powershell
cd PowerDiNSpec
```

4. Unlock Script

<p align="center">
  <img width="361" height="508" alt="screenshot1" src="https://github.com/user-attachments/assets/e52f7f5f-b129-4294-bbdb-51488eb2428c" />
  <img width="367" height="513" alt="screenshot2" src="https://github.com/user-attachments/assets/ed6b684e-e6a9-458f-a9d0-f9dc8abb84a2" />
</p>

---

## Usage

1. Open PowerShell.
2. Run the script:

```powershell
.\PowerDiNSpec.ps1
```

3. The menu will appear. Choose an option (1-12) to perform the desired scan.
4. Enter the target URL or host when prompted.
5. Logs will be automatically saved in the script directory with timestamps.
6. Press Enter to return to the menu after each scan.

---

## Example

Run all scans for a website:

```
Choose option: 10
Enter the website URL (e.g., https://example.com)
```

The tool will sequentially run all checks and display the results in the terminal.

---

## License

This program is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
You can redistribute and/or modify it under the terms of this license.

See the LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html.

---

## Author

Luan Calazans, 2025
Powered by PowerShell ☕💻
