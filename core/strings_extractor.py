"""
core/strings_extractor.py
Extract printable strings from a memory image and mine URLs from them.
"""

import subprocess
import re
import json
from pathlib import Path
from typing import Optional


# Minimum string length to capture
MIN_STRING_LEN = 6

# Regex patterns for URL extraction
URL_PATTERN = re.compile(
    r'(?:https?|ftp|ftps|sftp|smb|ldap|ldaps|telnet|ssh|rdp|vnc)'
    r'://[^\s\'"<>\x00-\x1f\x7f]{4,}',
    re.IGNORECASE,
)

# Also catch bare domain-like patterns (no scheme)
BARE_DOMAIN_PATTERN = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
    r'(?:com|net|org|io|gov|edu|mil|co|uk|de|ru|cn|top|xyz|club|online|site|info|biz)'
    r'(?:/[^\s\'"<>\x00-\x1f\x7f]*)?\b',
    re.IGNORECASE,
)

# Suspicious URL keywords
SUSPICIOUS_URL_KEYWORDS = [
    "pastebin", "ngrok", "tunnel", "payload", "shell", "cmd",
    "malware", "rat", "c2", "beacon", "exploit", "inject",
    "download", "dropper", "stager", "loader", "reverse",
    "base64", "encoded", ".onion", "darkweb", "tor2web",
    "temp-mail", "disposable", "filebin", "transfer.sh", "bat",
]


class StringsExtractor:
    """
    Extracts printable strings from a memory image using the system
    'strings' binary (Linux/macOS) or a pure-Python fallback.
    Mines all URLs from the extracted strings.
    """

    def __init__(self, image_path: str, output_dir: str, min_len: int = MIN_STRING_LEN):
        self.image_path = Path(image_path).resolve()
        self.output_dir = Path(output_dir)
        self.min_len = min_len
        self.strings_file = self.output_dir / "memory_strings.txt"
        self.urls_file = self.output_dir / "extracted_urls.json"

    # ------------------------------------------------------------------
    # String extraction
    # ------------------------------------------------------------------

    def extract_strings(self) -> Path:
        """
        Extract all printable strings from the memory image.
        Returns path to the strings file.
        """
        print("[*] Extracting strings from memory image (this may take a while)...")

        # Try system 'strings' command first (fastest)
        if self._try_system_strings():
            return self.strings_file

        # Pure Python fallback
        print("[*] System 'strings' not found, using Python fallback...")
        self._python_strings()
        return self.strings_file

    def _try_system_strings(self) -> bool:
        """Use system strings binary if available."""
        import shutil
        strings_bin = shutil.which("strings")
        if not strings_bin:
            return False

        try:
            cmd = [strings_bin, "-n", str(self.min_len), str(self.image_path)]
            with open(self.strings_file, "w", encoding="utf-8", errors="replace") as out:
                proc = subprocess.run(
                    cmd,
                    stdout=out,
                    stderr=subprocess.DEVNULL,
                    timeout=600,  # 10 min for large images
                )
            line_count = self._count_lines(self.strings_file)
            print(f"[+] Strings extracted: {line_count:,} strings → {self.strings_file}")
            return proc.returncode == 0
        except subprocess.TimeoutExpired:
            print("[!] Strings extraction timed out after 10 minutes")
            return False
        except Exception as e:
            print(f"[!] System strings failed: {e}")
            return False

    def _python_strings(self):
        """Pure Python string extractor fallback."""
        printable = set(
            b'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
            b'0123456789 !"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'
        )
        count = 0
        chunk_size = 4 * 1024 * 1024  # 4 MB chunks

        with open(self.image_path, "rb") as img, \
             open(self.strings_file, "w", encoding="utf-8", errors="replace") as out:

            current = bytearray()
            while True:
                chunk = img.read(chunk_size)
                if not chunk:
                    break
                for byte in chunk:
                    if byte in printable:
                        current.append(byte)
                    else:
                        if len(current) >= self.min_len:
                            out.write(current.decode("utf-8", errors="replace") + "\n")
                            count += 1
                        current.clear()

        print(f"[+] Strings extracted (Python): {count:,} strings → {self.strings_file}")

    def _count_lines(self, path: Path) -> int:
        try:
            with open(path, "rb") as f:
                return sum(1 for _ in f)
        except Exception:
            return 0

    # ------------------------------------------------------------------
    # URL extraction
    # ------------------------------------------------------------------

    def extract_urls(self) -> dict:
        """
        Mine URLs from the extracted strings file.
        Returns structured dict of URLs categorized as suspicious/clean.
        """
        if not self.strings_file.exists():
            self.extract_strings()

        print("[*] Extracting URLs from strings...")

        all_urls: set[str] = set()
        bare_domains: set[str] = set()

        with open(self.strings_file, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                # Full URLs
                for match in URL_PATTERN.finditer(line):
                    url = match.group(0).rstrip(".,;)'\"")
                    all_urls.add(url)
                # Bare domains
                for match in BARE_DOMAIN_PATTERN.finditer(line):
                    domain = match.group(0).rstrip(".,;)'\"")
                    bare_domains.add(domain)

        # Classify URLs
        suspicious_urls = []
        clean_urls = []

        for url in sorted(all_urls):
            lower = url.lower()
            is_suspicious = any(kw in lower for kw in SUSPICIOUS_URL_KEYWORDS)
            entry = {"url": url, "type": "full_url"}
            if is_suspicious:
                entry["reason"] = next(kw for kw in SUSPICIOUS_URL_KEYWORDS if kw in lower)
                suspicious_urls.append(entry)
            else:
                clean_urls.append(entry)

        # Add bare domains to clean (they may be normal web traffic)
        bare_list = [{"url": d, "type": "bare_domain"} for d in sorted(bare_domains)]

        result = {
            "total_full_urls": len(all_urls),
            "total_bare_domains": len(bare_domains),
            "suspicious_urls": suspicious_urls,
            "clean_urls": clean_urls,
            "bare_domains": bare_list,
        }

        # Save to file
        with open(self.urls_file, "w") as f:
            json.dump(result, f, indent=2)

        print(
            f"[+] URLs found: {len(all_urls)} full URLs, {len(bare_domains)} bare domains "
            f"({len(suspicious_urls)} suspicious)"
        )
        return result

    def run_all(self) -> dict:
        """Extract strings then mine URLs — full pipeline."""
        self.extract_strings()
        return self.extract_urls()
