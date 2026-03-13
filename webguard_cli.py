# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""
WebGuard Interactive CLI Launcher
Handles setup automatically and provides an interactive scan menu.
"""

import os
import sys
import subprocess
import platform
import shutil
from pathlib import Path

# -- Path Setup ---------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
VENV_DIR = BASE_DIR / "venv"
REPORTS_DIR = BASE_DIR / "reports"

IS_WINDOWS = platform.system() == "Windows"
PYTHON_BIN = str(VENV_DIR / ("Scripts/python.exe" if IS_WINDOWS else "bin/python"))
PIP_BIN    = str(VENV_DIR / ("Scripts/pip.exe"    if IS_WINDOWS else "bin/pip"))
MANAGE     = str(BASE_DIR / "manage.py")

# -- Colorama bootstrap (before venv is guaranteed) ---------------------------
try:
    from colorama import init, Fore, Style, Back
    init(autoreset=True)
    _HAS_COLOR = True
except ImportError:
    _HAS_COLOR = False
    class _Dummy:                       # noqa: E302
        def __getattr__(self, _): return ""
    Fore = Style = Back = _Dummy()


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

def _run(cmd, *, capture=False, check=True):
    """Run a shell command list. Returns CompletedProcess."""
    return subprocess.run(
        cmd,
        capture_output=capture,
        text=True,
        check=check,
        cwd=str(BASE_DIR),
    )


def _print_line(char="-", width=70, color=Fore.CYAN):
    print(f"{color}{char * width}{Style.RESET_ALL}")


def _header(text, color=Fore.CYAN):
    _print_line(color=color)
    print(f"{color}{Style.BRIGHT}  {text}{Style.RESET_ALL}")
    _print_line(color=color)


def _ok(msg):  print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {msg}")
def _info(msg): print(f"{Fore.BLUE}[*]{Style.RESET_ALL} {msg}")
def _warn(msg): print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")
def _err(msg):  print(f"{Fore.RED}[-]{Style.RESET_ALL} {msg}", file=sys.stderr)


# -----------------------------------------------------------------------------
# Banner
# -----------------------------------------------------------------------------

BANNER = (
    "\n"
    + Fore.CYAN + Style.BRIGHT
    + "  __        __   _     ____                     _ \n"
    + "  \\ \\      / /__| |__ / ___|_   _  __ _ _ __ __| |\n"
    + "   \\ \\ /\\ / / _ \\ '_ \\\\ _| | | | |/ _` | '__/ _` |\n"
    + "    \\ V  V /  __/ |_) | |___| |_| | (_| | | | (_| |\n"
    + "     \\_/\\_/ \\___|_.__/|_____|\\__,_|\\__,_|_|  \\__,_|\n"
    + Style.RESET_ALL + "\n"
    + Fore.WHITE + "        Web Vulnerability Scanning Framework  "
    + Fore.YELLOW + "v1.0" + Style.RESET_ALL + "\n"
    + Fore.CYAN + "        " + "-" * 50 + Style.RESET_ALL + "\n"
    + Fore.RED + "  [!] " + Fore.WHITE
    + "For authorized security testing and educational use only."
    + Style.RESET_ALL + "\n"
)


def print_banner():
    os.system("cls" if IS_WINDOWS else "clear")
    print(BANNER)


# -----------------------------------------------------------------------------
# Automated Setup
# -----------------------------------------------------------------------------

def setup():
    """One-time automated environment bootstrap."""
    _header("Automated Setup", Fore.CYAN)

    # 1. Virtual environment
    if not VENV_DIR.exists():
        _info("Creating virtual environment ...")
        _run([sys.executable, "-m", "venv", str(VENV_DIR)])
        _ok("Virtual environment created.")
    else:
        _ok("Virtual environment found.")

    # 2. Dependencies
    _info("Installing / verifying dependencies ...")
    _run([PIP_BIN, "install", "-r", str(BASE_DIR / "requirements.txt"), "-q"])
    _ok("Dependencies ready.")

    # 3. Migrations
    _info("Applying database migrations ...")
    _run([PYTHON_BIN, MANAGE, "migrate", "--run-syncdb"])
    _ok("Database ready.")

    # 4. Reports directory
    REPORTS_DIR.mkdir(exist_ok=True)
    _ok("Reports directory ready.")

    print()
    _ok(f"{Style.BRIGHT}Setup complete. Launching scanner menu ...")
    print()
    input(f"  {Fore.CYAN}Press Enter to continue ...{Style.RESET_ALL}")


# -----------------------------------------------------------------------------
# Input helpers
# -----------------------------------------------------------------------------

def _prompt_url(prompt="  Enter target URL: "):
    while True:
        url = input(f"{Fore.YELLOW}{prompt}{Style.RESET_ALL}").strip()
        if url.startswith(("http://", "https://")):
            return url
        _warn("URL must start with http:// or https://  (e.g. https://example.com)")


def _prompt_int(prompt, default, lo, hi):
    raw = input(f"{Fore.YELLOW}{prompt} [{default}]: {Style.RESET_ALL}").strip()
    if not raw:
        return default
    try:
        val = int(raw)
        if lo <= val <= hi:
            return val
    except ValueError:
        pass
    _warn(f"Invalid value - using default ({default})")
    return default


def _list_reports():
    reports = sorted(REPORTS_DIR.glob("*"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not reports:
        _warn("No reports found in reports/ directory.")
        return
    _header("Generated Reports", Fore.MAGENTA)
    for i, r in enumerate(reports, 1):
        size_kb = r.stat().st_size / 1024
        mtime   = r.stat().st_mtime
        import datetime
        ts = datetime.datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M")
        ext_color = Fore.GREEN if r.suffix == ".html" else Fore.CYAN
        print(f"  {Fore.WHITE}{i:>2}.{Style.RESET_ALL} {ext_color}{r.name}{Style.RESET_ALL}"
              f"  {Fore.WHITE}({size_kb:.1f} KB  {ts}){Style.RESET_ALL}")
    print()


def _open_report():
    reports = sorted(REPORTS_DIR.glob("*.html"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not reports:
        _warn("No HTML reports found.")
        return
    latest = reports[0]
    _info(f"Opening: {latest.name}")
    if IS_WINDOWS:
        os.startfile(str(latest))
    elif platform.system() == "Darwin":
        subprocess.run(["open", str(latest)])
    else:
        subprocess.run(["xdg-open", str(latest)])


# -----------------------------------------------------------------------------
# Scan runners
# -----------------------------------------------------------------------------

def run_recon():
    _header("Reconnaissance Scan", Fore.BLUE)
    url = _prompt_url()
    print()
    _run([PYTHON_BIN, MANAGE, "recon", url], check=False)


def run_crawl():
    _header("Web Crawler", Fore.BLUE)
    url   = _prompt_url()
    depth = _prompt_int("  Crawl depth", default=2, lo=1, hi=10)
    maxu  = _prompt_int("  Max URLs to crawl", default=100, lo=1, hi=500)
    print()
    _run([PYTHON_BIN, MANAGE, "crawl", url, "--depth", str(depth), "--max", str(maxu)], check=False)


def run_vuln_only():
    _header("Vulnerability Scan (no crawl)", Fore.RED)
    _warn("This scans only the root URL for vulnerabilities without crawling.")
    url = _prompt_url()
    print()
    _run([PYTHON_BIN, MANAGE, "scan", url], check=False)


def run_full_scan():
    _header("Full Scan  [Recon -> Crawl -> Vuln -> Report]", Fore.MAGENTA)
    url   = _prompt_url()
    depth = _prompt_int("  Crawl depth", default=2, lo=1, hi=10)
    maxu  = _prompt_int("  Max URLs to crawl", default=100, lo=1, hi=500)
    print()
    _run(
        [PYTHON_BIN, MANAGE, "scan", url,
         "--full-scan", "--depth", str(depth), "--max-urls", str(maxu)],
        check=False,
    )
    print()
    open_now = input(f"  {Fore.CYAN}Open HTML report in browser? (y/N): {Style.RESET_ALL}").strip().lower()
    if open_now == "y":
        _open_report()


# -----------------------------------------------------------------------------
# Main Menu
# -----------------------------------------------------------------------------

MENU_ITEMS = [
    ("1", "Reconnaissance Only     ", "DNS . IP . Server headers . Technologies", Fore.BLUE,    run_recon),
    ("2", "Web Crawler             ", "Discover internal endpoints and forms",      Fore.CYAN,   run_crawl),
    ("3", "Vulnerability Scan      ", "SQLi . XSS . Header misconfigs (root only)", Fore.YELLOW, run_vuln_only),
    ("4", "Full Scan  *            ", "Recon + Crawl + Vuln + Report generation",   Fore.MAGENTA, run_full_scan),
    ("5", "View Reports            ", "List all generated JSON / HTML reports",     Fore.GREEN,  _list_reports),
    ("6", "Open Latest HTML Report ", "Launch the most recent report in browser",   Fore.GREEN,  _open_report),
    ("0", "Exit                    ", "",                                            Fore.RED,    None),
]


def print_menu():
    print_banner()
    _print_line(color=Fore.CYAN)
    print(f"{Fore.CYAN}{Style.BRIGHT}  SCANNER MENU{Style.RESET_ALL}")
    _print_line(color=Fore.CYAN)
    print()
    for key, label, desc, color, _ in MENU_ITEMS:
        desc_str = f"{Fore.WHITE}- {desc}{Style.RESET_ALL}" if desc else ""
        print(f"  {color}{Style.BRIGHT}[{key}]{Style.RESET_ALL}  {color}{label}{Style.RESET_ALL}  {desc_str}")
    print()
    _print_line(color=Fore.CYAN)


def main():
    print_banner()
    setup()

    while True:
        print_menu()
        choice = input(f"  {Fore.CYAN}Select option: {Style.RESET_ALL}").strip()
        print()

        matched = next((item for item in MENU_ITEMS if item[0] == choice), None)
        if matched is None:
            _warn("Invalid option. Please choose from the menu.")
            input(f"\n  {Fore.CYAN}Press Enter to continue ...{Style.RESET_ALL}")
            continue

        key, label, _, _, handler = matched
        if key == "0":
            print(f"\n{Fore.CYAN}  Goodbye. Stay safe.{Style.RESET_ALL}\n")
            sys.exit(0)

        try:
            handler()
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}  [!] Interrupted.{Style.RESET_ALL}")

        print()
        input(f"  {Fore.CYAN}Press Enter to return to menu ...{Style.RESET_ALL}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.CYAN}  Goodbye.{Style.RESET_ALL}\n")
        sys.exit(0)
