"""
cli/main.py
MemScout CLI — Memory Forensics Automation Tool
"""

import sys
import os
import json
from pathlib import Path

try:
    import click
except ImportError:
    print("Error: 'click' not installed. Run: pip install click")
    sys.exit(1)

# Add parent dir to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.runner import VolatilityRunner
from core.analyzer import Analyzer
from reports.generator import ReportGenerator


# ── Banner ──────────────────────────────────────────────────────────────────

BANNER = r"""
  __  __                 ____                  _   
 |  \/  | ___ _ __ ___ / ___|  ___ ___  _   _| |_ 
 | |\/| |/ _ \ '_ ` _ \\___ \ / __/ _ \| | | | __|
 | |  | |  __/ | | | | |___) | (_| (_) | |_| | |_ 
 |_|  |_|\___|_| |_| |_|____/ \___\___/ \__,_|\__|
  Memory Forensics Automation Tool  |  Powered by Volatility 3
  Built by Fad-X
"""


# ── CLI Commands ─────────────────────────────────────────────────────────────

@click.group()
@click.version_option("1.0.0", prog_name="memscout")
def cli():
    """MemScout — Automated Memory Image Analysis Tool."""
    click.echo(click.style(BANNER, fg="cyan"))


@cli.command()
@click.argument("image", type=click.Path(exists=True))
@click.option("--mode", "-m", type=click.Choice(["simple", "full", "triage", "custom"]), default="triage",
              show_default=True, help="Scan mode.")
@click.option("--plugins", "-p", multiple=True, help="Plugins to run (for --mode=custom).")
@click.option("--os", "os_type", type=click.Choice(["windows", "linux", "mac"]),
              default=None, help="Force OS type (auto-detect if omitted).")
@click.option("--output", "-o", type=click.Path(), default="output",
              show_default=True, help="Output directory for results and reports.")
@click.option("--vol-path", default=None, help="Path to vol/vol3 executable.")
@click.option("--no-report", is_flag=True, help="Skip report generation.")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output.")
def scan(image, mode, plugins, os_type, output, vol_path, no_report, verbose):
    """
    Analyze a memory image.

    \b
    Modes:
      simple  — OS info, logged-in users, suspicious cmdlines, network (internal vs external)
      triage  — Quick scan: processes, network, malfind, cmdline
      full    — Everything: all plugins + simple features + strings + URL extraction
      custom  — You pick the plugins

    \b
    Examples:
      memscout scan memory.dmp --mode simple
      memscout scan memory.dmp --mode full
      memscout scan memory.dmp --mode custom --plugins windows.pslist.PsList
    """
    click.echo(f"[*] Target image : {image}")
    click.echo(f"[*] Scan mode    : {mode}")
    click.echo(f"[*] Output dir   : {output}\n")

    # Initialise runner
    try:
        runner = VolatilityRunner(
            image_path=image,
            vol_path=vol_path,
            output_dir=output,
            verbose=verbose,
        )
    except (FileNotFoundError, EnvironmentError) as e:
        click.echo(click.style(f"[!] {e}", fg="red"))
        sys.exit(1)

    # Override OS if specified
    if os_type:
        runner.os_type = os_type
        click.echo(f"[*] OS type forced to: {os_type}")
    else:
        runner.detect_os()

    # Run the scan
    if mode == "simple":
        runner.simple_scan()
        _print_simple_results(runner.results.get("__simple__", {}))
    elif mode == "full":
        runner.full_scan()
        _print_simple_results(runner.results.get("__simple__", {}))
        _print_url_results(runner.results.get("__urls__", {}))
    elif mode == "triage":
        runner.triage_scan()
    elif mode == "custom":
        if not plugins:
            click.echo(click.style("[!] --mode=custom requires at least one --plugins argument.", fg="red"))
            sys.exit(1)
        runner.custom_scan(list(plugins))

    # Analyze results
    click.echo("\n" + "─" * 60)
    click.echo("[*] Running threat analysis...")
    analyzer = Analyzer(runner.results, os_type=runner.os_type)
    analysis = analyzer.analyze()

    # Print findings to terminal
    _print_findings(analysis["findings"])

    # Generate reports
    if not no_report:
        click.echo("\n" + "─" * 60)
        reporter = ReportGenerator(output_dir=runner.output_dir)
        report_paths = reporter.generate(
            runner_summary=runner.get_summary(),
            scan_results=runner.results,
            analysis=analysis,
            errors=runner.errors,
        )
        click.echo(click.style("\n[+] Reports ready!", fg="green"))
        for fmt, path in report_paths.items():
            click.echo(f"    {fmt.upper()}: {path}")

    click.echo(click.style("\n[✓] MemScout scan complete.\n", fg="green"))


@cli.command()
@click.argument("image", type=click.Path(exists=True))
@click.option("--vol-path", default=None, help="Path to vol/vol3 executable.")
def detect(image, vol_path):
    """Auto-detect the OS type of a memory image."""
    try:
        runner = VolatilityRunner(image_path=image, vol_path=vol_path)
        os_type = runner.detect_os()
        click.echo(click.style(f"\n[+] Detected OS: {os_type}", fg="green"))
    except Exception as e:
        click.echo(click.style(f"[!] Error: {e}", fg="red"))


@cli.command()
def plugins():
    """List all default plugins organized by OS."""
    from core.runner import DEFAULT_PLUGINS, TRIAGE_PLUGINS

    click.echo(click.style("\n── Full Scan Plugins ──", fg="cyan"))
    for os_type, plugin_list in DEFAULT_PLUGINS.items():
        click.echo(click.style(f"\n  {os_type.upper()}", fg="yellow"))
        for p in plugin_list:
            click.echo(f"    • {p}")

    click.echo(click.style("\n── Triage Plugins ──", fg="cyan"))
    for os_type, plugin_list in TRIAGE_PLUGINS.items():
        click.echo(click.style(f"\n  {os_type.upper()}", fg="yellow"))
        for p in plugin_list:
            click.echo(f"    • {p}")


@cli.command()
@click.argument("json_report", type=click.Path(exists=True))
def summary(json_report):
    """Print a summary from a previously generated JSON report."""
    with open(json_report) as f:
        report = json.load(f)

    meta = report.get("meta", {})
    stats = report.get("stats", {})
    findings = report.get("findings", [])

    click.echo(click.style("\n── Report Summary ──", fg="cyan"))
    click.echo(f"  Image   : {meta.get('image_name')}")
    click.echo(f"  OS      : {meta.get('os_type')}")
    click.echo(f"  Duration: {meta.get('elapsed_seconds')}s")
    click.echo(f"  Plugins : {meta.get('plugins_run')}")
    click.echo(f"\n{report.get('summary', '')}")

    _print_findings(findings)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _print_simple_results(simple: dict):
    """Pretty-print simple scan results to the terminal."""
    if not simple:
        return

    click.echo("\n" + "=" * 60)
    click.echo(click.style("  SIMPLE SCAN RESULTS", fg="cyan", bold=True))
    click.echo("=" * 60)

    # OS Info
    os_info = simple.get("os_info", {})
    if os_info:
        click.echo(click.style("\n  [ OS & SYSTEM INFO ]", fg="yellow", bold=True))
        fields = [
            ("OS Type", os_info.get("os_type", "N/A")),
            ("Kernel / Build", os_info.get("kernel_version", "N/A")),
            ("System Time", os_info.get("system_time", "N/A")),
            ("Memory Model", os_info.get("memory_model", "N/A")),
            ("Image Type", os_info.get("image_type", "N/A")),
        ]
        for label, value in fields:
            if value and value != "N/A":
                click.echo(f"    {click.style(label + ':', bold=True)} {value}")
        # Extra raw fields
        raw = os_info.get("raw", {})
        for key, val in list(raw.items())[:10]:
            if key not in ("NtBuildLab", "SystemTime", "MemoryModel", "ImageType", "NtSystemRoot"):
                click.echo(f"    {click.style(key + ':', bold=True)} {val}")

    # Logged-in Users
    users = simple.get("logged_in_users", [])
    click.echo(click.style("\n  [ LOGGED-IN USERS ]", fg="yellow", bold=True))
    if users:
        for u in users:
            click.echo(f"    • {u}")
    else:
        click.echo("    (none detected)")

    # Suspicious Cmdlines
    hits = simple.get("suspicious_cmdlines", [])
    click.echo(click.style("\n  [ SUSPICIOUS COMMAND LINES ]", fg="yellow", bold=True))
    if hits:
        for h in hits:
            click.echo(
                f"    {click.style('[!]', fg='red')} {h['process']} (PID {h['pid']}) "
                f"— keyword: {click.style(h['matched_keyword'], fg='red')}"
            )
            click.echo(click.style(f"        {h['cmdline'][:200]}", fg="bright_black"))
    else:
        click.echo(click.style("    [✓] No suspicious cmdlines found.", fg="green"))

    # Network
    net = simple.get("network", {})
    click.echo(click.style("\n  [ NETWORK CONNECTIONS ]", fg="yellow", bold=True))
    click.echo(f"    Total connections: {net.get('raw_count', 0)}")

    internal = net.get("internal", [])
    external = net.get("external", [])

    if internal:
        click.echo(click.style(f"\n    Internal IPs ({len(internal)}):", fg="cyan"))
        for conn in internal[:20]:
            click.echo(
                f"      {conn['proto']:5} {conn['local']:28} → {conn['foreign']:28}"
                f"  [{conn['state']}]  pid:{conn['owner']}"
            )
        if len(internal) > 20:
            click.echo(f"      ... and {len(internal) - 20} more")

    if external:
        click.echo(click.style(f"\n    External IPs ({len(external)}):", fg="magenta"))
        for conn in external[:30]:
            click.echo(
                f"      {conn['proto']:5} {conn['local']:28} → "
                f"{click.style(conn['foreign'], fg='magenta'):28}"
                f"  [{conn['state']}]  pid:{conn['owner']}"
            )
        if len(external) > 30:
            click.echo(f"      ... and {len(external) - 30} more")

    click.echo("=" * 60)


def _print_url_results(url_data: dict):
    """Print URL extraction summary to terminal."""
    if not url_data:
        return

    click.echo(click.style("\n  [ URLs EXTRACTED FROM MEMORY STRINGS ]", fg="yellow", bold=True))
    click.echo(f"    Full URLs found   : {url_data.get('total_full_urls', 0)}")
    click.echo(f"    Bare domains found: {url_data.get('total_bare_domains', 0)}")

    sus = url_data.get("suspicious_urls", [])
    if sus:
        click.echo(click.style(f"\n    Suspicious URLs ({len(sus)}):", fg="red"))
        for entry in sus[:20]:
            click.echo(
                f"      {click.style('[!]', fg='red')} [{entry.get('reason', '?')}] {entry['url'][:120]}"
            )
        if len(sus) > 20:
            click.echo(f"      ... and {len(sus) - 20} more (see extracted_urls.json)")
    else:
        click.echo(click.style("    [✓] No suspicious URLs found.", fg="green"))


def _print_findings(findings: list):
    """Pretty-print findings to the terminal."""
    if not findings:
        click.echo(click.style("\n[✓] No suspicious indicators detected.", fg="green"))
        return

    severity_colors = {
        "CRITICAL": "red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "blue",
        "INFO": "cyan",
    }

    click.echo(click.style(f"\n── Findings ({len(findings)}) ──", fg="red"))
    for f in findings:
        color = severity_colors.get(f["severity"], "white")
        sev_label = click.style(f"[{f['severity']}]", fg=color, bold=True)
        click.echo(f"\n  {sev_label} {f['title']}")
        click.echo(click.style(f"    Category: {f['category']}", fg="bright_black"))
        click.echo(click.style(f"    {f['detail'][:200]}", fg="bright_black"))


# ── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    cli()
