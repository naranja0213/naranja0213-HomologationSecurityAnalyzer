# Homologation Security Analyzer

Windows desktop tool for enterprise software homologation and security review.

It can analyze a ZIP file or a folder, recursively extract ZIP files, scan target files,
calculate hashes, check Windows Authenticode signatures, query VirusTotal API v3 by SHA256,
apply risk rules, and export an Excel report.

## Features

- Tkinter desktop GUI
- ZIP extraction with 7-Zip when available
- Fallback ZIP extraction through Python `zipfile`
- Nested ZIP extraction
- Recursive file inventory
- SHA256, SHA1, and MD5 hashes
- Authenticode signature status through PowerShell
- Windows file version metadata
- VirusTotal API v3 hash lookup only
- Excel report with Summary, Hash Report, Detected Files, Unsigned Files, and All Files
- JSON result export
- Analysis log file

## Install Python

Install Python 3.12 for Windows from:

https://www.python.org/downloads/windows/

During installation, enable:

- Add python.exe to PATH
- pip

Verify:

```powershell
python --version
pip --version
```

## Install Dependencies

Open PowerShell in the project directory:

```powershell
cd HomologationSecurityAnalyzer
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Run

```powershell
python main.py
```

In the GUI:

1. Select a ZIP file or a folder.
2. Enter a VirusTotal API key, or leave it empty to skip VirusTotal lookup.
3. Set the query delay. The default is 15 seconds for free API rate limits.
4. Click Start Analysis.

Reports are written next to the selected ZIP file or selected folder:

- `Homologation_Report_<name>_<timestamp>.xlsx`
- `analysis_log_<timestamp>.txt`
- `Homologation_Result_<timestamp>.json`

Temporary extracted files are stored under:

```text
C:\HSA_TMP\
```

If that directory cannot be created, the tool falls back to the current Windows temp directory.

## VirusTotal API Key

The tool never uploads files to VirusTotal. It only queries existing reports by SHA256:

```http
GET https://www.virustotal.com/api/v3/files/{sha256}
```

You can provide the key in the GUI for the current run only.

You can also set it as an environment variable:

```powershell
$env:VT_API_KEY="your_api_key_here"
python main.py
```

For a persistent user environment variable:

```powershell
setx VT_API_KEY "your_api_key_here"
```

Restart PowerShell after using `setx`.

## Target Extensions

The Hash Report focuses on:

```text
.exe .dll .sys .msi .cab .cat .ps1 .bat .cmd .vbs .js .jar .apk .zip .rar .7z
```

The All Files sheet still records every file found during scanning.

## Risk Rules

The tool applies these automatic rules:

- `malicious = 0` and valid signature: Approved
- `malicious = 0` and not signed: Approved after manual review
- `malicious = 1-2` and valid signature: Likely false positive / Approved after manual review
- `malicious = 1-2` and not signed: Manual Review Required
- `malicious = 3-5`: Medium Risk / Manual Review Required
- `malicious > 5`: High Risk / Reject or escalate
- Publisher or source containing Microsoft with `malicious <= 1`: Approved after manual review

If VirusTotal is skipped, not found, or fails, the tool marks the file as unknown and keeps it
available for manual review.

## Build EXE With PyInstaller

From the activated virtual environment:

```powershell
pyinstaller --noconsole --onefile --name HomologationSecurityAnalyzer main.py
```

The executable will be created under:

```text
dist\HomologationSecurityAnalyzer.exe
```

Recommended test after packaging:

```powershell
.\dist\HomologationSecurityAnalyzer.exe
```

## Security Notes

- API keys are not hard-coded.
- GUI-entered API keys are used only for the current run.
- The tool supports `VT_API_KEY` from the environment.
- Files are not uploaded to VirusTotal.
- ZIP extraction skips unsafe path traversal entries when using Python `zipfile`.
- Prefer installing 7-Zip on analyst workstations for better archive compatibility.

