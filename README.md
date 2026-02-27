# 🔍 MemScout — Memory Forensics Automation Tool

MemScout automates memory image analysis by wrapping Volatility 3, running plugins, detecting suspicious activity, and generating professional reports — all from a single command.

---

## Features

- **Auto OS detection** — detects Windows, Linux, or macOS from the image
- **Three scan modes** — full, triage, or custom plugin list
- **Threat analysis** — flags suspicious processes, network connections, code injection, and malicious command lines
- **Report generation** — HTML and JSON reports (PDF with WeasyPrint)
- **CLI interface** — clean, intuitive command-line tool

---

## Installation

### 1. Clone and set up

```bash
git clone https://github.com/you/memscout.git
cd memscout
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```
Download and install GTK from here:
👉 https://github.com/tschoonj/GTK-for-Windows-Runtime-Environment-Installer/releases
Download the latest .exe, install it, then restart your terminal and try again.
### 2. Install Volatility 3

```bash
pip install volatility3
```

Verify: `vol --help`

---

## Usage

### Quick triage (recommended first step)

```bash
python cli/main.py scan /path/to/memory.dmp
```

### Full scan

```bash
python cli/main.py scan /path/to/memory.dmp --mode full
```

### Custom plugins

```bash
python cli/main.py scan /path/to/memory.dmp --mode custom \
  --plugins windows.pslist.PsList \
  --plugins windows.netscan.NetScan \
  --plugins windows.malfind.Malfind
```

### Force OS type

```bash
python cli/main.py scan memory.dmp --os windows
```

### Custom output directory

```bash
python cli/main.py scan memory.dmp --output ./case_001/results
```

### List available plugins

```bash
python cli/main.py plugins
```

### View report summary from JSON

```bash
python cli/main.py summary output/memscout_report_*.json
```

---

## Output

Each scan creates a timestamped directory inside `output/`:

```
output/
└── memory_20240315_143022/
    ├── raw_results.json          # All plugin output
    ├── memscout_report_*.html    # Visual HTML report
    ├── memscout_report_*.json    # Structured JSON report
    └── memscout_report_*.pdf     # PDF (if WeasyPrint installed)
```

---

## Detection Capabilities

| Category | Examples |
|---|---|
| Suspicious Processes | Typosquatting, unexpected paths, too many instances |
| Code Injection | Malfind hits, process hollowing indicators |
| Network Anomalies | C2 ports, backdoor listeners |
| Malicious Commands | Encoded PowerShell, persistence, lateral movement |
| Privilege Escalation | Shells/interpreters running as root (Linux) |

---

## Project Structure

```
memscout/
├── core/
│   ├── runner.py        # Volatility 3 execution engine
│   └── analyzer.py      # Threat detection logic
├── cli/
│   └── main.py          # CLI (Click)
├── reports/
│   └── generator.py     # HTML/JSON/PDF report builder
├── output/              # Scan results saved here
├── requirements.txt
└── README.md
```

---

## Roadmap

- [ ] PyQt6 GUI dashboard
- [ ] Timeline view of process creation
- [ ] YARA rule scanning integration
- [ ] VirusTotal hash lookups
- [ ] Multi-image batch scanning
- [ ] Sigma rule support

---

> ⚠️ For authorized forensic analysis only. Always work on legal copies of memory images.


