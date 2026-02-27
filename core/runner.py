"""
core/runner.py
Volatility 3 plugin execution engine for MemScout.
"""

import subprocess
import json
import re
import os
import sys
from pathlib import Path
from typing import Optional
from datetime import datetime


# Simple scan plugins — OS info, users, cmdline, network
SIMPLE_PLUGINS = {
    "windows": [
        "windows.info.Info",
        "windows.envars.Envars",
        "windows.sessions.Sessions",
        "windows.cmdline.CmdLine",
        "windows.netscan.NetScan",
    ],
    "linux": [
        "linux.bash.Bash",
        "linux.pslist.PsList",
        "linux.netfilter.Netfilter",
    ],
    "mac": [
        "mac.pslist.PsList",
        "mac.netstat.Netstat",
        "mac.bash.Bash",
    ],
}

# Default plugins to run during a full scan
DEFAULT_PLUGINS = {
    "windows": [
        # -- Simple mode features (also in full) --
        "windows.info.Info",
        "windows.envars.Envars",
        "windows.sessions.Sessions",
        "windows.cmdline.CmdLine",
        "windows.netscan.NetScan",
        # -- Full scan extras --
        "windows.pslist.PsList",
        "windows.pstree.PsTree",
        "windows.netstat.NetStat",
        "windows.dlllist.DllList",
        "windows.malfind.Malfind",
        "windows.handles.Handles",
        "windows.registry.hivelist.HiveList",
        "windows.hashdump.Hashdump",
    ],
    "linux": [
        "linux.pslist.PsList",
        "linux.pstree.PsTree",
        "linux.netfilter.Netfilter",
        "linux.bash.Bash",
        "linux.check_creds.Check_creds",
        "linux.malfind.Malfind",
    ],
    "mac": [
        "mac.pslist.PsList",
        "mac.pstree.PsTree",
        "mac.netstat.Netstat",
        "mac.bash.Bash",
        "mac.malfind.Malfind",
    ],
}

# Quick triage plugins (faster scan)
TRIAGE_PLUGINS = {
    "windows": [
        "windows.pslist.PsList",
        "windows.pstree.PsTree",
        "windows.netscan.NetScan",
        "windows.malfind.Malfind",
        "windows.cmdline.CmdLine",
    ],
    "linux": [
        "linux.pslist.PsList",
        "linux.pstree.PsTree",
        "linux.malfind.Malfind",
    ],
    "mac": [
        "mac.pslist.PsList",
        "mac.pstree.PsTree",
        "mac.malfind.Malfind",
    ],
}


class VolatilityRunner:
    """
    Wraps Volatility 3 CLI to programmatically run plugins
    against a memory image and collect structured results.
    """

    def __init__(
        self,
        image_path: str,
        vol_path: Optional[str] = None,
        output_dir: Optional[str] = None,
        verbose: bool = False,
    ):
        self.image_path = Path(image_path).resolve()
        self.vol_path = vol_path or self._find_volatility()
        self.output_dir = Path(output_dir) if output_dir else Path("output") / self._session_name()
        self.verbose = verbose
        self.results: dict = {}
        self.errors: dict = {}
        self.os_type: Optional[str] = None
        self.scan_start: Optional[datetime] = None
        self.scan_end: Optional[datetime] = None

        # Validate
        if not self.image_path.exists():
            raise FileNotFoundError(f"Memory image not found: {self.image_path}")
        if not self.vol_path:
            raise EnvironmentError(
                "Volatility 3 not found. Install it or pass vol_path= explicitly.\n"
                "Install: pip install volatility3"
            )

        self.output_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Setup helpers
    # ------------------------------------------------------------------

    def _find_volatility(self) -> Optional[str]:
        """Auto-detect vol.py or vol3 on PATH."""
        import shutil
        for candidate in ("vol", "vol3", "vol.py", "volatility3"):
            path = shutil.which(candidate)
            if path:
                return path
        # Try common pip install location
        python_scripts = Path(sys.executable).parent / "vol"
        if python_scripts.exists():
            return str(python_scripts)
        return None

    def _session_name(self) -> str:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        stem = self.image_path.stem
        return f"{stem}_{ts}"

    # ------------------------------------------------------------------
    # OS Detection
    # ------------------------------------------------------------------

    def detect_os(self) -> str:
        """
        Try to detect OS type from the image using windows.info or banners.
        Falls back to 'windows' if unable to determine.
        """
        print("[*] Detecting OS type from memory image...")

        for os_type, info_plugin in [
            ("windows", "windows.info.Info"),
            ("linux", "linux.banner.Banner"),
            ("mac", "mac.pslist.PsList"),
        ]:
            result = self._run_plugin(info_plugin, capture=True)
            if result and result.get("returncode") == 0:
                self.os_type = os_type
                print(f"[+] Detected OS: {os_type}")
                return os_type

        # Default fallback
        self.os_type = "windows"
        print(f"[!] Could not auto-detect OS. Defaulting to: {self.os_type}")
        return self.os_type

    # ------------------------------------------------------------------
    # Plugin execution
    # ------------------------------------------------------------------

    def _run_plugin(
        self,
        plugin: str,
        extra_args: list = None,
        capture: bool = False,
    ) -> dict:
        """
        Execute a single Volatility 3 plugin and return structured output.
        """
        cmd = [
            self.vol_path,
            "-f", str(self.image_path),
            "-r", "json",   # Request JSON output
            plugin,
        ]
        if extra_args:
            cmd.extend(extra_args)

        if self.verbose:
            print(f"  [CMD] {' '.join(cmd)}")

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5 min per plugin
            )
            output = {
                "plugin": plugin,
                "returncode": proc.returncode,
                "stdout": proc.stdout,
                "stderr": proc.stderr,
                "rows": [],
            }

            # Try to parse JSON rows from stdout
            if proc.stdout:
                try:
                    data = json.loads(proc.stdout)
                    output["rows"] = data.get("rows", data) if isinstance(data, dict) else data
                except json.JSONDecodeError:
                    # Fall back to raw text if not JSON
                    output["rows"] = proc.stdout.splitlines()

            return output

        except subprocess.TimeoutExpired:
            return {"plugin": plugin, "returncode": -1, "error": "Timeout after 300s", "rows": []}
        except Exception as e:
            return {"plugin": plugin, "returncode": -1, "error": str(e), "rows": []}

    def run_plugin(self, plugin: str, extra_args: list = None) -> dict:
        """
        Run a single plugin, store and return results.
        """
        print(f"  [~] Running: {plugin}")
        result = self._run_plugin(plugin, extra_args)

        if result.get("returncode") == 0:
            self.results[plugin] = result
            row_count = len(result.get("rows", []))
            print(f"  [+] {plugin} — {row_count} rows")
        else:
            err = result.get("error") or result.get("stderr", "")[:120]
            self.errors[plugin] = err
            print(f"  [!] {plugin} failed: {err}")

        return result

    def run_plugins(self, plugins: list) -> dict:
        """
        Run a list of plugins sequentially and collect all results.
        """
        all_results = {}
        total = len(plugins)
        for i, plugin in enumerate(plugins, 1):
            print(f"[{i}/{total}] {plugin}")
            all_results[plugin] = self.run_plugin(plugin)
        return all_results

    # ------------------------------------------------------------------
    # Scan modes
    # ------------------------------------------------------------------

    def simple_scan(self) -> dict:
        """
        Simple mode: OS info, logged-in users, suspicious cmdlines,
        network connections with internal/external IP separation.
        """
        self.scan_start = datetime.now()
        if not self.os_type:
            self.detect_os()

        plugins = SIMPLE_PLUGINS.get(self.os_type, SIMPLE_PLUGINS["windows"])
        print(f"\n[*] Starting SIMPLE scan — {len(plugins)} plugins on {self.image_path.name}")
        print(f"[*] Output directory: {self.output_dir}\n")

        self.run_plugins(plugins)

        # Post-process simple mode results
        simple_data = self._process_simple_results()

        # Save simple report JSON
        simple_out = self.output_dir / "simple_report.json"
        with open(simple_out, "w") as f:
            json.dump(simple_data, f, indent=2, default=str)
        print(f"[*] Simple report saved to: {simple_out}")

        self.scan_end = datetime.now()
        self._save_raw_results()
        print(f"\n[+] Simple scan complete in {self._elapsed()}s")

        # Attach simple data to results for report generator
        self.results["__simple__"] = simple_data
        return self.results

    def _process_simple_results(self) -> dict:
        """Extract and structure data from simple scan plugins."""
        simple = {
            "os_info": self._extract_os_info(),
            "logged_in_users": self._extract_users(),
            "suspicious_cmdlines": self._extract_suspicious_cmdlines(),
            "network": self._extract_network_simple(),
        }
        return simple

    def _extract_os_info(self) -> dict:
        """Parse windows.info.Info or envars for OS/hardware details."""
        info = {}

        # Try windows.info.Info first
        info_key = self._find_result_key("info.Info")
        if info_key:
            rows = self.results[info_key].get("rows", [])
            for row in rows:
                if isinstance(row, dict):
                    variable = row.get("Variable", row.get("variable", ""))
                    value = row.get("Value", row.get("value", ""))
                    if variable and value:
                        info[str(variable)] = str(value)
                elif isinstance(row, list) and len(row) >= 2:
                    info[str(row[0])] = str(row[1])

        # Parse key fields into clean structure
        return {
            "os_type": self.os_type,
            "kernel_version": info.get("NtBuildLab", info.get("Kernel", "N/A")),
            "system_time": info.get("SystemTime", "N/A"),
            "number_of_processors": info.get("NtSystemRoot", info.get("NumberOfProcessors", "N/A")),
            "image_type": info.get("ImageType", "N/A"),
            "memory_model": info.get("MemoryModel", "N/A"),
            "raw": info,
        }

    def _extract_users(self) -> list[str]:
        """Extract unique logged-in usernames from sessions."""
        users = set()

        sessions_key = self._find_result_key("sessions.Sessions")
        if sessions_key:
            rows = self.results[sessions_key].get("rows", [])
            for row in rows:
                if isinstance(row, dict):
                    for field in ["UserName", "Username", "username", "User", "user"]:
                        val = row.get(field)
                        if val and str(val).strip() and str(val) != "N/A":
                            users.add(str(val).strip())
                            break

        # Fallback: parse envars for USERNAME
        envars_key = self._find_result_key("envars.Envars")
        if envars_key:
            rows = self.results[envars_key].get("rows", [])
            for row in rows:
                if isinstance(row, dict):
                    var = str(row.get("Variable", row.get("variable", "")))
                    val = str(row.get("Value", row.get("value", "")))
                    if var.upper() == "USERNAME" and val and val not in ("N/A", ""):
                        users.add(val)

        return sorted(users) if users else ["[No sessions detected]"]

    def _extract_suspicious_cmdlines(self) -> list[dict]:
        """
        Scan cmdline output for suspicious keywords:
        connect, -pass, password, username, users, -user, net use, etc.
        """
        SUSPICIOUS_KEYWORDS = [
            r"\bconnect\b",
            r"-pass(word)?",
            r"\bpassword\b",
            r"\busername\b",
            r"\buser\b",
            r"net\s+use",
            r"net\s+user",
            r"psexec",
            r"invoke-expression",
            r"iex\s*\(",
            r"-credential",
            r"runas",
            r"logon",
            r"--password",
            r"--user",
            r"ssh\s+",
            r"ftp\s+",
            r"wce\b",              # Windows Credential Editor
            r"mimikatz",
            r"sekurlsa",
            r"lsadump",
        ]

        combined = re.compile("|".join(SUSPICIOUS_KEYWORDS), re.IGNORECASE)

        hits = []
        cmdline_key = self._find_result_key("cmdline.CmdLine")
        if not cmdline_key:
            return hits

        rows = self.results[cmdline_key].get("rows", [])
        for row in rows:
            if not isinstance(row, dict):
                continue
            args = str(row.get("Args", row.get("CommandLine", row.get("args", ""))))
            if not args or args in ("N/A", "Required memory at"):
                continue
            match = combined.search(args)
            if match:
                hits.append({
                    "process": str(row.get("ImageFileName", row.get("Process", row.get("name", "?")))),
                    "pid": row.get("PID", row.get("pid")),
                    "cmdline": args[:300],
                    "matched_keyword": match.group(0),
                })
        return hits

    def _extract_network_simple(self) -> dict:
        """
        Parse netscan results and split connections into
        internal vs external IP addresses.
        """
        INTERNAL_RANGES = [
            re.compile(r"^10\."),
            re.compile(r"^172\.(1[6-9]|2\d|3[01])\."),
            re.compile(r"^192\.168\."),
            re.compile(r"^127\."),
            re.compile(r"^::1$"),
            re.compile(r"^fe80:"),
            re.compile(r"^0\.0\.0\.0$"),
            re.compile(r"^\*$"),
        ]

        def is_internal(ip: str) -> bool:
            ip = ip.strip()
            return any(p.match(ip) for p in INTERNAL_RANGES)

        netscan_key = (
            self._find_result_key("netscan.NetScan")
            or self._find_result_key("netstat.NetStat")
        )
        if not netscan_key:
            return {"internal": [], "external": [], "raw_count": 0}

        rows = self.results[netscan_key].get("rows", [])
        internal = []
        external = []

        for row in rows:
            if not isinstance(row, dict):
                continue

            local_addr = str(row.get("LocalAddr", row.get("local_addr", "")))
            local_port = str(row.get("LocalPort", row.get("local_port", "")))
            foreign_addr = str(row.get("ForeignAddr", row.get("ForeignAddress", row.get("foreign_addr", ""))))
            foreign_port = str(row.get("ForeignPort", row.get("foreign_port", "")))
            state = str(row.get("State", row.get("state", "")))
            owner = str(row.get("Owner", row.get("PID", row.get("pid", ""))))
            proto = str(row.get("Proto", row.get("proto", "")))

            entry = {
                "local": f"{local_addr}:{local_port}",
                "foreign": f"{foreign_addr}:{foreign_port}",
                "state": state,
                "owner": owner,
                "proto": proto,
            }

            # Classify by foreign address
            if foreign_addr and foreign_addr not in ("", "N/A", "*", "0.0.0.0"):
                if is_internal(foreign_addr):
                    internal.append(entry)
                else:
                    external.append(entry)
            else:
                # No foreign = listening locally
                internal.append(entry)

        return {
            "internal": internal,
            "external": external,
            "raw_count": len(rows),
        }

    def _find_result_key(self, keyword: str) -> Optional[str]:
        """Find a result key containing the keyword (case-insensitive)."""
        for key in self.results:
            if keyword.lower() in key.lower():
                return key
        return None

    def full_scan(self) -> dict:
        """
        Full scan: all plugins + simple mode features
        + string extraction + URL mining.
        """
        self.scan_start = datetime.now()
        if not self.os_type:
            self.detect_os()

        plugins = DEFAULT_PLUGINS.get(self.os_type, DEFAULT_PLUGINS["windows"])
        print(f"\n[*] Starting FULL scan — {len(plugins)} plugins on {self.image_path.name}")
        print(f"[*] Output directory: {self.output_dir}\n")

        self.run_plugins(plugins)

        # --- Simple mode post-processing (included in full scan) ---
        print("\n[*] Processing simple mode data (users, cmdlines, network)...")
        simple_data = self._process_simple_results()
        simple_out = self.output_dir / "simple_report.json"
        with open(simple_out, "w") as f:
            json.dump(simple_data, f, indent=2, default=str)
        self.results["__simple__"] = simple_data

        # --- String extraction + URL mining ---
        print("\n[*] Running string extraction and URL mining...")
        try:
            from core.strings_extractor import StringsExtractor
            extractor = StringsExtractor(
                image_path=str(self.image_path),
                output_dir=str(self.output_dir),
            )
            url_data = extractor.run_all()
            self.results["__urls__"] = url_data
        except Exception as e:
            print(f"[!] String extraction error: {e}")

        self.scan_end = datetime.now()
        self._save_raw_results()
        print(f"\n[+] Full scan complete in {self._elapsed()}s")
        return self.results

    def triage_scan(self) -> dict:
        """Run a quick triage scan with essential plugins only."""
        self.scan_start = datetime.now()
        if not self.os_type:
            self.detect_os()

        plugins = TRIAGE_PLUGINS.get(self.os_type, TRIAGE_PLUGINS["windows"])
        print(f"\n[*] Starting TRIAGE scan — {len(plugins)} plugins on {self.image_path.name}")
        print(f"[*] Output directory: {self.output_dir}\n")

        self.run_plugins(plugins)

        self.scan_end = datetime.now()
        self._save_raw_results()
        print(f"\n[+] Triage scan complete in {self._elapsed()}s")
        return self.results

    def custom_scan(self, plugins: list) -> dict:
        """Run a user-defined list of plugins."""
        self.scan_start = datetime.now()
        print(f"\n[*] Starting CUSTOM scan — {len(plugins)} plugins on {self.image_path.name}\n")

        self.run_plugins(plugins)

        self.scan_end = datetime.now()
        self._save_raw_results()
        print(f"\n[+] Custom scan complete in {self._elapsed()}s")
        return self.results

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _elapsed(self) -> float:
        if self.scan_start and self.scan_end:
            return round((self.scan_end - self.scan_start).total_seconds(), 2)
        return 0.0

    def _save_raw_results(self):
        """Save raw JSON results to output directory."""
        out_file = self.output_dir / "raw_results.json"
        summary = {
            "image": str(self.image_path),
            "os_type": self.os_type,
            "scan_start": self.scan_start.isoformat() if self.scan_start else None,
            "scan_end": self.scan_end.isoformat() if self.scan_end else None,
            "elapsed_seconds": self._elapsed(),
            "plugins_run": list(self.results.keys()),
            "plugins_failed": list(self.errors.keys()),
            "results": self.results,
            "errors": self.errors,
        }
        with open(out_file, "w") as f:
            json.dump(summary, f, indent=2, default=str)
        print(f"[*] Raw results saved to: {out_file}")

    def get_summary(self) -> dict:
        """Return a high-level summary of the scan."""
        return {
            "image": str(self.image_path),
            "os_type": self.os_type,
            "scan_start": self.scan_start.isoformat() if self.scan_start else None,
            "scan_end": self.scan_end.isoformat() if self.scan_end else None,
            "elapsed_seconds": self._elapsed(),
            "plugins_run": len(self.results),
            "plugins_failed": len(self.errors),
            "total_rows": sum(len(v.get("rows", [])) for v in self.results.values()),
            "output_dir": str(self.output_dir),
        }
