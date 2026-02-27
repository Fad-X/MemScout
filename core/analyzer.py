"""
core/analyzer.py
Post-processing and suspicious activity detection for MemScout.
"""

from typing import Optional
import re


# Known legitimate Windows system processes and their expected parents
KNOWN_PROCESSES = {
    "System": {"parent": None, "expected_path": None, "max_instances": 1},
    "smss.exe": {"parent": "System", "expected_path": r"\\Windows\\System32\\smss.exe", "max_instances": 1},
    "csrss.exe": {"parent": "smss.exe", "expected_path": r"\\Windows\\System32\\csrss.exe", "max_instances": 2},
    "wininit.exe": {"parent": "smss.exe", "expected_path": r"\\Windows\\System32\\wininit.exe", "max_instances": 1},
    "winlogon.exe": {"parent": "smss.exe", "expected_path": r"\\Windows\\System32\\winlogon.exe", "max_instances": None},
    "services.exe": {"parent": "wininit.exe", "expected_path": r"\\Windows\\System32\\services.exe", "max_instances": 1},
    "lsass.exe": {"parent": "wininit.exe", "expected_path": r"\\Windows\\System32\\lsass.exe", "max_instances": 1},
    "svchost.exe": {"parent": "services.exe", "expected_path": r"\\Windows\\System32\\svchost.exe", "max_instances": None},
    "explorer.exe": {"parent": "userinit.exe", "expected_path": r"\\Windows\\explorer.exe", "max_instances": None},
    "taskhost.exe": {"parent": "services.exe", "expected_path": r"\\Windows\\System32\\taskhost.exe", "max_instances": None},
    "spoolsv.exe": {"parent": "services.exe", "expected_path": r"\\Windows\\System32\\spoolsv.exe", "max_instances": 1},
}

# Suspicious process names (typosquatting common system processes)
SUSPICIOUS_NAMES = [
    "svch0st.exe", "scvhost.exe", "svchost32.exe",
    "lssas.exe", "lsas.exe", "lsass32.exe",
    "csrs.exe", "cssrs.exe",
    "iexplore.exe",  # Often abused
    "rundll32.exe",  # Often abused
    "regsvr32.exe",  # Often abused
    "systemsync.exe",
    "syslog.exe",
    "rmcs.exe",
    "lassa.exe"
]

# Suspicious network indicators
SUSPICIOUS_PORTS = [4444, 1337, 31337, 8888, 9999, 6666, 6667, 6668, 6669]
SUSPICIOUS_IP_RANGES = [
    "0.0.0.0",
    "255.255.255.255",
]


class Analyzer:
    """
    Analyzes Volatility 3 scan results and flags suspicious indicators.
    """

    def __init__(self, results: dict, os_type: str = "windows"):
        self.results = results
        self.os_type = os_type
        self.findings: list[dict] = []
        self.stats: dict = {}

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def analyze(self) -> dict:
        """Run all analysis checks and return a structured findings report."""
        print("[*] Running analysis on scan results...")

        if self.os_type == "windows":
            self._analyze_processes()
            self._analyze_network()
            self._analyze_malfind()
            self._analyze_cmdline()

        elif self.os_type == "linux":
            self._analyze_processes_linux()
            self._analyze_malfind()

        self._compute_stats()

        print(f"[+] Analysis complete — {len(self.findings)} findings ({self._count_by_severity()})")
        return {
            "findings": self.findings,
            "stats": self.stats,
            "summary": self._build_summary(),
        }

    # ------------------------------------------------------------------
    # Windows analysis
    # ------------------------------------------------------------------

    def _analyze_processes(self):
        """Analyze process list for suspicious activity."""
        pslist_key = self._find_result_key("pslist")
        pstree_key = self._find_result_key("pstree")

        rows = []
        if pslist_key:
            rows = self.results[pslist_key].get("rows", [])
        elif pstree_key:
            rows = self.results[pstree_key].get("rows", [])

        if not rows:
            return

        process_counts: dict[str, int] = {}
        process_names = [self._get_field(r, ["ImageFileName", "Name", "name"]) for r in rows]

        for row in rows:
            name = self._get_field(row, ["ImageFileName", "Name", "name"]) or ""
            pid = self._get_field(row, ["PID", "pid", "Pid"])
            ppid = self._get_field(row, ["PPID", "ppid", "PPid"])
            path = self._get_field(row, ["ImagePathName", "Path", "path"]) or ""

            process_counts[name] = process_counts.get(name, 0) + 1

            # Check for suspicious names
            if name.lower() in [s.lower() for s in SUSPICIOUS_NAMES]:
                self._add_finding(
                    severity="HIGH",
                    category="Suspicious Process",
                    title=f"Known malicious process name: {name}",
                    detail=f"PID: {pid}, PPID: {ppid}",
                    evidence={"name": name, "pid": pid, "ppid": ppid},
                )

            # Check for processes masquerading as system processes
            for legit_name, info in KNOWN_PROCESSES.items():
                if name.lower() == legit_name.lower():
                    # Check instance count
                    max_inst = info.get("max_instances")
                    if max_inst and process_counts[name] > max_inst:
                        self._add_finding(
                            severity="MEDIUM",
                            category="Process Anomaly",
                            title=f"Multiple instances of {name} (expected max {max_inst})",
                            detail=f"Found {process_counts[name]} instances",
                            evidence={"name": name, "count": process_counts[name]},
                        )

            # Hollow process check: system process running from unusual path
            if name.lower() in [k.lower() for k in KNOWN_PROCESSES] and path:
                expected = KNOWN_PROCESSES.get(name, {}).get("expected_path", "")
                if expected and "system32" not in path.lower() and "windows" not in path.lower():
                    self._add_finding(
                        severity="HIGH",
                        category="Process Hollowing Indicator",
                        title=f"{name} running from unexpected path",
                        detail=f"Path: {path}",
                        evidence={"name": name, "pid": pid, "path": path},
                    )

    def _analyze_network(self):
        """Analyze network connections for suspicious activity."""
        netscan_key = self._find_result_key("netscan") or self._find_result_key("netstat")
        if not netscan_key:
            return

        rows = self.results[netscan_key].get("rows", [])
        for row in rows:
            foreign_addr = self._get_field(row, ["ForeignAddr", "ForeignAddress", "foreign_addr"]) or ""
            foreign_port = self._get_field(row, ["ForeignPort", "foreign_port"])
            local_port = self._get_field(row, ["LocalPort", "local_port"])
            state = self._get_field(row, ["State", "state"]) or ""
            owner = self._get_field(row, ["Owner", "PID", "pid"]) or ""

            # Check for suspicious ports
            for port in [foreign_port, local_port]:
                if port and int(port) in SUSPICIOUS_PORTS:
                    self._add_finding(
                        severity="HIGH",
                        category="Suspicious Network",
                        title=f"Connection on known C2/backdoor port {port}",
                        detail=f"Foreign: {foreign_addr}:{foreign_port}, State: {state}, Process: {owner}",
                        evidence=row,
                    )

            # Check for listening on all interfaces (potential backdoor)
            if "0.0.0.0" in str(foreign_addr) and state.upper() == "LISTENING":
                if local_port and int(local_port) > 1024:
                    self._add_finding(
                        severity="MEDIUM",
                        category="Suspicious Network",
                        title=f"Process listening on all interfaces port {local_port}",
                        detail=f"Process: {owner}",
                        evidence=row,
                    )

    def _analyze_malfind(self):
        """Analyze malfind output for injected code."""
        malfind_key = self._find_result_key("malfind")
        if not malfind_key:
            return

        rows = self.results[malfind_key].get("rows", [])
        if not rows:
            return

        # Group by process
        procs: dict[str, list] = {}
        for row in rows:
            name = self._get_field(row, ["Process", "ImageFileName", "process"]) or "Unknown"
            procs.setdefault(name, []).append(row)

        for proc_name, injections in procs.items():
            self._add_finding(
                severity="HIGH",
                category="Code Injection",
                title=f"Malfind detected {len(injections)} suspicious memory region(s) in {proc_name}",
                detail=f"Process: {proc_name}, Regions: {len(injections)}",
                evidence={"process": proc_name, "count": len(injections)},
            )

    def _analyze_cmdline(self):
        """Flag suspicious command-line arguments."""
        cmdline_key = self._find_result_key("cmdline")
        if not cmdline_key:
            return

        rows = self.results[cmdline_key].get("rows", [])
        suspicious_patterns = [
            (r"powershell.*-enc", "PowerShell encoded command (obfuscation)"),
            (r"powershell.*-w.*hidden", "PowerShell hidden window"),
            (r"cmd.*\/c.*del", "Command deleting files"),
            (r"net\s+user.*\/add", "Adding user account"),
            (r"net\s+localgroup.*administrators.*\/add", "Adding user to administrators"),
            (r"reg\s+add.*run", "Registry run key modification"),
            (r"schtasks.*\/create", "Scheduled task creation"),
            (r"bitsadmin.*\/transfer", "BITS transfer (often used by malware)"),
            (r"wscript|cscript", "Script host execution"),
            (r"mshta", "MSHTA execution (HTML application host)"),
            (r"certutil.*-decode", "CertUtil decode (often used for payload delivery)"),
        ]

        for row in rows:
            args = self._get_field(row, ["Args", "CommandLine", "args"]) or ""
            name = self._get_field(row, ["ImageFileName", "Process", "name"]) or ""

            for pattern, description in suspicious_patterns:
                if re.search(pattern, args, re.IGNORECASE):
                    self._add_finding(
                        severity="HIGH",
                        category="Suspicious Command Line",
                        title=description,
                        detail=f"Process: {name}\nCommand: {args[:200]}",
                        evidence={"process": name, "cmdline": args},
                    )
                    break  # One finding per row

    # ------------------------------------------------------------------
    # Linux analysis
    # ------------------------------------------------------------------

    def _analyze_processes_linux(self):
        """Basic Linux process analysis."""
        pslist_key = self._find_result_key("pslist")
        if not pslist_key:
            return

        rows = self.results[pslist_key].get("rows", [])
        for row in rows:
            name = self._get_field(row, ["COMM", "name", "Name"]) or ""
            pid = self._get_field(row, ["PID", "pid"])

            # Processes running as root that shouldn't be
            uid = self._get_field(row, ["UID", "uid"])
            if uid == 0 and name in ["bash", "sh", "nc", "ncat", "python", "perl", "ruby"]:
                self._add_finding(
                    severity="MEDIUM",
                    category="Privilege Escalation Indicator",
                    title=f"Shell/interpreter running as root: {name}",
                    detail=f"PID: {pid}, Name: {name}",
                    evidence=row,
                )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _add_finding(self, severity: str, category: str, title: str, detail: str, evidence: dict):
        self.findings.append({
            "severity": severity,
            "category": category,
            "title": title,
            "detail": detail,
            "evidence": evidence,
        })

    def _find_result_key(self, keyword: str) -> Optional[str]:
        """Find a result key containing the keyword."""
        for key in self.results:
            if keyword.lower() in key.lower():
                return key
        return None

    def _get_field(self, row, field_names: list):
        """Try multiple field name variants to get a value from a row."""
        if isinstance(row, dict):
            for name in field_names:
                if name in row:
                    return row[name]
        return None

    def _compute_stats(self):
        """Compute statistics about findings."""
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        category_counts: dict[str, int] = {}

        for f in self.findings:
            sev = f.get("severity", "INFO")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            cat = f.get("category", "Other")
            category_counts[cat] = category_counts.get(cat, 0) + 1

        self.stats = {
            "total_findings": len(self.findings),
            "by_severity": severity_counts,
            "by_category": category_counts,
        }

    def _count_by_severity(self) -> str:
        counts = self.stats.get("by_severity", {})
        parts = [f"{k}: {v}" for k, v in counts.items() if v > 0]
        return ", ".join(parts) if parts else "none"

    def _build_summary(self) -> str:
        total = len(self.findings)
        if total == 0:
            return "No suspicious indicators detected."
        high = self.stats["by_severity"].get("HIGH", 0) + self.stats["by_severity"].get("CRITICAL", 0)
        return (
            f"{total} finding(s) detected. "
            f"{high} high/critical severity indicator(s) require immediate attention."
        )
