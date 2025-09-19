# PowersDiNSpector

**PowerShell DNS Recon Tool**

PowersDiNSpector is a PowerShell-based tool designed to help security enthusiasts and penetration testers perform reconnaissance on websites and DNS records. It allows you to scan server headers, HTTP methods, links, HTML words, detect technologies, check status codes, and more.

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
* Run all scans automatically
* Log all actions to a file

---

## Installation

1. Make sure you have **PowerShell 5.1** or later installed on Windows.
2. Clone or download this repository:

```powershell
git clone https://github.com/Luanqmata/PowersDiNSpector.git
```

3. Navigate to the folder:

```powershell
cd PowersDiNSpector
```

4. If the script is blocked by execution policies, run:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

---

## Usage

1. Open PowerShell.
2. Run the script:

```powershell
.\PowersDiNSpector.ps1
```

3. The menu will appear. Choose an option (1-11) to perform the desired scan.
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

This program is licensed under the **GNU Affero General Public License v3.0** (AGPL-3.0).
You can redistribute and/or modify it under the terms of this license.

See the LICENSE file or visit [https://www.gnu.org/licenses/agpl-3.0.html](https://www.gnu.org/licenses/agpl-3.0.html).

---

<p align="center">
  <img width="551" height="475" alt="image" src="https://github.com/user-attachments/assets/edd8a3e0-3936-4c03-99a9-a0250d426eb8" />
</p>
