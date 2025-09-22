# PowerDiNSpec

*PowerShell DNS Recon Tool*

PowerDiNSpec is a PowerShell-based tool designed to help security enthusiasts and penetration testers perform reconnaissance on websites and DNS records. It allows you to scan server headers, HTTP methods, links, HTML words, detect technologies, check status codes, and more.

---

## Features

* Capture server headers
* Discover allowed HTTP methods
* List links found in HTML
* Extract words from website HTML for fuzzing
* Detect technologies in use (X-Powered-By, Server)
* Get HTTP status codes
* Retrieve the <title> of the page
* Check for robots.txt
* Check for sitemap.xml
* Check for Banner
* Run all scans automatically
* Log all actions to a file

---

## Installation

1. Make sure you have *PowerShell 5.1* or later installed on Windows.
2. Clone or download this repository:

```powershell
git clone https://github.com/Luanqmata/PowerDiNSpec.git
```

3. Navigate to the folder:

```powershell
cd PowerDiNSpec
```

4. If the script is blocked by execution policies, run:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

<p align="center">
  <img width="361" height="508" alt="image" src="https://github.com/user-attachments/assets/e52f7f5f-b129-4294-bbdb-51488eb2428c" />
  <img width="367" height="513" alt="image" src="https://github.com/user-attachments/assets/ed6b684e-e6a9-458f-a9d0-f9dc8abb84a2" />
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


Choose option: 10
Enter the website URL (e.g., https://example.com)


The tool will sequentially run all checks and display the results in the terminal.
