#!/usr/bin/env python3
"""
SubdomainFinder.py  —  Async Subdomain Enumeration & Alive Checker  v5.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Features:
  • Multi-source subdomain enumeration  (crt.sh, HackerTarget, AlienVault,
    RapidDNS, urlscan.io, ThreatCrowd, SecurityTrails)
  • subfinder binary integration (auto-detected, merges results)
  • Real-time alive probing via async HTTP
  • Alive subdomains saved to  alive_subdomains.txt  (clean list)
  • JSON + CSV export
  • Fully async (asyncio + aiohttp)
"""

import argparse
import asyncio
import csv
import json
import logging
import re
import shutil
import subprocess
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional

import aiohttp
from rich import box
from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

# ─────────────────────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.WARNING,
    handlers=[RichHandler(rich_tracebacks=True, show_path=False)],
)
log = logging.getLogger("subfinder")

console = Console(highlight=False)

# ─────────────────────────────────────────────────────────────────────────────
# Data structures
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class SubResult:
    subdomain:   str
    status_code: Optional[int] = None
    final_url:   str           = ""
    alive:       bool          = False
    source:      str           = ""
    timestamp:   str           = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

# ─────────────────────────────────────────────────────────────────────────────
# Global state
# ─────────────────────────────────────────────────────────────────────────────

found_set:  set  = set()
results:    list = []
state_lock       = asyncio.Lock()

stats = {
    "discovered": 0,
    "alive":      0,
    "dead":       0,
    "errors":     0,
}

# ─────────────────────────────────────────────────────────────────────────────
# HTTP session factory
# ─────────────────────────────────────────────────────────────────────────────

def make_session(timeout_secs: int = 8) -> aiohttp.ClientSession:
    timeout   = aiohttp.ClientTimeout(total=timeout_secs, connect=4)
    connector = aiohttp.TCPConnector(
        limit=200,
        ssl=False,
        ttl_dns_cache=300,
        use_dns_cache=True,
    )
    headers = {"User-Agent": "Mozilla/5.0 (compatible; SubFinder/5.0)"}
    return aiohttp.ClientSession(
        connector=connector,
        timeout=timeout,
        headers=headers,
    )

# ─────────────────────────────────────────────────────────────────────────────
# Sync fetch (runs in executor)
# ─────────────────────────────────────────────────────────────────────────────

def sync_fetch(url, extra_headers=None, timeout=15, retries=2):
    base_headers = {
        "User-Agent": "Mozilla/5.0 (compatible; SubFinder/5.0)",
        "Accept":     "application/json, text/plain, */*",
    }
    if extra_headers:
        base_headers.update(extra_headers)
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(url, headers=base_headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read().decode("utf-8", errors="ignore")
        except urllib.error.HTTPError as e:
            if e.code == 429:
                time.sleep(3 * (attempt + 1))
            else:
                return None
        except Exception:
            if attempt < retries:
                time.sleep(2)
    return None

# ─────────────────────────────────────────────────────────────────────────────
# Enumeration sources
# ─────────────────────────────────────────────────────────────────────────────

def _crtsh(domain):
    data = sync_fetch(f"https://crt.sh/?q=%25.{domain}&output=json")
    if not data:
        return []
    try:
        subs = []
        for entry in json.loads(data):
            for name in entry.get("name_value", "").split("\n"):
                subs.append((name.strip(), "crt.sh"))
        return subs
    except Exception:
        return []

def _hackertarget(domain):
    data = sync_fetch(f"https://api.hackertarget.com/hostsearch/?q={domain}")
    if not data or "error" in data.lower():
        return []
    subs = []
    for line in data.splitlines():
        parts = line.split(",")
        if parts and parts[0].strip():
            subs.append((parts[0].strip(), "hackertarget"))
    return subs

def _alienvault(domain):
    subs = []
    page = 1
    while True:
        data = sync_fetch(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns?page={page}"
        )
        if not data:
            break
        try:
            j = json.loads(data)
            records = j.get("passive_dns", [])
            if not records:
                break
            for r in records:
                h = r.get("hostname", "")
                if h:
                    subs.append((h, "alienvault"))
            if not j.get("has_next"):
                break
            page += 1
        except Exception:
            break
    return subs

def _rapiddns(domain):
    data = sync_fetch(f"https://rapiddns.io/subdomain/{domain}?full=1")
    if not data:
        return []
    pattern = re.compile(r'<td>([a-zA-Z0-9._-]+\.' + re.escape(domain) + r')</td>')
    return [(s, "rapiddns") for s in pattern.findall(data)]

def _urlscan(domain):
    data = sync_fetch(f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=200")
    if not data:
        return []
    subs = []
    try:
        for result in json.loads(data).get("results", []):
            for f in [
                result.get("task", {}).get("domain", ""),
                result.get("page", {}).get("domain", ""),
            ]:
                if f:
                    subs.append((f, "urlscan"))
    except Exception:
        pass
    return subs

def _threatcrowd(domain):
    data = sync_fetch(
        f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
    )
    if not data:
        return []
    try:
        return [(s, "threatcrowd") for s in json.loads(data).get("subdomains", [])]
    except Exception:
        return []

def _securitytrails(domain, api_key):
    data = sync_fetch(
        f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
        extra_headers={"APIKEY": api_key},
    )
    if not data:
        return []
    try:
        return [
            (f"{s}.{domain}", "securitytrails")
            for s in json.loads(data).get("subdomains", [])
        ]
    except Exception:
        return []

# ─────────────────────────────────────────────────────────────────────────────
# subfinder binary integration
# ─────────────────────────────────────────────────────────────────────────────

def _run_subfinder_binary(domain: str) -> list:
    """
    Run the external `subfinder` binary if it is on PATH.
    Returns list of (subdomain, 'subfinder') tuples.
    """
    binary = shutil.which("subfinder")
    if not binary:
        console.print(
            "  [dim yellow]subfinder binary not found on PATH — skipping.[/]\n"
            "  [dim]Install: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest[/]"
        )
        return []

    console.print(f"  [green]subfinder binary found at {binary}[/]")
    try:
        proc = subprocess.run(
            [binary, "-d", domain, "-silent", "-all"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        subs = []
        for line in proc.stdout.splitlines():
            line = line.strip().lower()
            if line:
                subs.append((line, "subfinder"))
        if proc.returncode != 0 and proc.stderr:
            log.debug(f"subfinder stderr: {proc.stderr[:200]}")
        console.print(f"  [dim]subfinder returned {len(subs)} subdomains[/]")
        return subs
    except subprocess.TimeoutExpired:
        console.print("  [red]subfinder timed out after 120 s[/]")
        return []
    except Exception as e:
        console.print(f"  [red]subfinder error: {e}[/]")
        return []

SOURCES = {
    "crt.sh":       _crtsh,
    "hackertarget": _hackertarget,
    "alienvault":   _alienvault,
    "rapiddns":     _rapiddns,
    "urlscan":      _urlscan,
    "threatcrowd":  _threatcrowd,
}

# ─────────────────────────────────────────────────────────────────────────────
# Validation
# ─────────────────────────────────────────────────────────────────────────────

_VALID_SUB = re.compile(r"^(?:[a-zA-Z0-9_-]+\.)+[a-zA-Z]{2,}$")

def is_valid_sub(sub: str, domain: str) -> bool:
    sub = sub.strip().lower().lstrip("*.")
    if not sub:
        return False
    if not (sub.endswith(f".{domain}") or sub == domain):
        return False
    return bool(_VALID_SUB.match(sub))

def normalize(sub: str) -> str:
    return sub.strip().lower().lstrip("*.")

# ─────────────────────────────────────────────────────────────────────────────
# Rich UI helpers
# ─────────────────────────────────────────────────────────────────────────────

def code_color(code: Optional[int]) -> Text:
    if code is None:
        return Text("DEAD", style="bold red")
    s = str(code)
    if 200 <= code < 300:
        return Text(s, style="bold green")
    if 300 <= code < 400:
        return Text(s, style="bold cyan")
    if 400 <= code < 500:
        return Text(s, style="bold yellow")
    return Text(s, style="bold red")

# ─────────────────────────────────────────────────────────────────────────────
# Alive probe
# ─────────────────────────────────────────────────────────────────────────────

async def probe_alive(
    sub:        str,
    source:     str,
    session:    aiohttp.ClientSession,
    semaphore:  asyncio.Semaphore,
    output_q:   asyncio.Queue,
    alive_only: bool,
    timeout:    int,
) -> Optional[SubResult]:
    """Check if a subdomain responds over HTTP/S. Returns SubResult or None."""
    async with semaphore:
        result = SubResult(subdomain=sub, source=source)
        alive  = False

        for scheme in ("https", "http"):
            try:
                async with session.get(
                    f"{scheme}://{sub}",
                    allow_redirects=True,
                    timeout=aiohttp.ClientTimeout(total=timeout),
                ) as resp:
                    result.status_code = resp.status
                    result.final_url   = str(resp.url)
                    result.alive       = True
                    alive = True
                    break
            except aiohttp.ClientResponseError as e:
                result.status_code = e.status
                result.alive       = True
                alive = True
                break
            except Exception:
                continue

        async with state_lock:
            if alive:
                stats["alive"] += 1
                results.append(result)
            else:
                stats["dead"] += 1

        if not alive:
            if not alive_only:
                await output_q.put(("dead", sub))
            return None

        await output_q.put(("alive", result))
        return result

# ─────────────────────────────────────────────────────────────────────────────
# Output printer (consumes output_q)
# ─────────────────────────────────────────────────────────────────────────────

async def output_printer(q: asyncio.Queue, alive_only: bool):
    while True:
        item = await q.get()
        if item is None:
            break
        kind = item[0]

        if kind == "dead":
            _, sub = item
            if not alive_only:
                console.print(f"  [bold red][ DEAD][/] [dim]{sub}[/]")

        elif kind == "alive":
            _, r = item
            redir = ""
            if r.final_url and r.final_url not in (
                f"http://{r.subdomain}", f"https://{r.subdomain}", ""
            ):
                redir = f"  [dim]→ {r.final_url}[/]"
            code = r.status_code
            if code and 200 <= code < 300:
                style = "green"
            elif code and 300 <= code < 400:
                style = "cyan"
            elif code and 400 <= code < 500:
                style = "yellow"
            else:
                style = "red"
            console.print(
                f"  [bold green][ALIVE][/] [[{style}]{code}[/]] "
                f"[bold]{r.subdomain}[/]{redir}"
            )

        elif kind == "found":
            _, sub, source, count = item
            console.print(
                f"  [green][{count:>4}][/] {sub:<55} [dim]← {source}[/]"
            )

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 1 — Enumeration
# ─────────────────────────────────────────────────────────────────────────────

async def enumerate_subdomains(
    domain:        str,
    sources:       list,
    api_key:       str,
    use_subfinder: bool,
    output_q:      asyncio.Queue,
) -> list:
    """Enumerate from all sources + optional subfinder binary. Returns deduped list."""
    loop      = asyncio.get_event_loop()
    collected = []

    # ── Built-in HTTP sources ─────────────────────────────────────────────────
    for name in sources:
        console.rule(f"[yellow]Querying {name}[/]", style="dim")
        before = stats["discovered"]

        if name == "securitytrails":
            if not api_key:
                console.print("  [red]skipped — no API key (-k)[/]")
                continue
            raw = await loop.run_in_executor(None, _securitytrails, domain, api_key)
        else:
            raw = await loop.run_in_executor(None, SOURCES[name], domain)

        for sub_raw, src in raw:
            sub = normalize(sub_raw)
            if not is_valid_sub(sub, domain):
                continue
            async with state_lock:
                if sub in found_set:
                    continue
                found_set.add(sub)
                stats["discovered"] += 1
                count = stats["discovered"]
            await output_q.put(("found", sub, src, count))
            collected.append((sub, src))

        after = stats["discovered"]
        console.print(f"  [dim]↳ {after - before} new  |  total: {after}[/]")

    # ── subfinder binary ──────────────────────────────────────────────────────
    if use_subfinder:
        console.rule("[yellow]Querying subfinder (binary)[/]", style="dim")
        before = stats["discovered"]
        raw    = await loop.run_in_executor(None, _run_subfinder_binary, domain)

        for sub_raw, src in raw:
            sub = normalize(sub_raw)
            if not is_valid_sub(sub, domain):
                continue
            async with state_lock:
                if sub in found_set:
                    continue
                found_set.add(sub)
                stats["discovered"] += 1
                count = stats["discovered"]
            await output_q.put(("found", sub, src, count))
            collected.append((sub, src))

        after = stats["discovered"]
        console.print(f"  [dim]↳ {after - before} new  |  total: {after}[/]")

    return collected

# ─────────────────────────────────────────────────────────────────────────────
# Export
# ─────────────────────────────────────────────────────────────────────────────

def export_alive_txt(path: str):
    """Write a plain list of alive subdomains — one per line."""
    with open(path, "w") as f:
        for r in results:
            if r.alive:
                f.write(r.subdomain + "\n")
    console.print(f"[green][+] Alive subdomains → {path}[/]")

def export_json(path: str):
    with open(path, "w") as f:
        json.dump([asdict(r) for r in results], f, indent=2)
    console.print(f"[green][+] JSON export → {path}[/]")

def export_csv(path: str):
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "subdomain", "status_code", "final_url", "alive", "source", "timestamp"
        ])
        for r in results:
            writer.writerow([
                r.subdomain, r.status_code, r.final_url,
                r.alive, r.source, r.timestamp,
            ])
    console.print(f"[green][+] CSV export  → {path}[/]")

# ─────────────────────────────────────────────────────────────────────────────
# Banner
# ─────────────────────────────────────────────────────────────────────────────

def print_banner():
    console.print(
        "\n[bold cyan]  Passive Subdomain Parser by Rakib Nadir[/bold cyan]\n"
        "[dim]  Async Recon Framework  |  Enumeration + Alive Check  |  v5.0[/dim]\n"
    )

# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

async def async_main(args):
    domain = (
        args.domain.lower().strip()
        .removeprefix("http://")
        .removeprefix("https://")
        .split("/")[0]
    )

    print_banner()
    console.print(f"[bold][*] Target      :[/] {domain}")
    console.print(f"[bold][*] Sources     :[/] {', '.join(args.sources)}")
    sf_status = "[green]enabled[/]" if args.subfinder else "[dim]disabled (use --subfinder to enable)[/]"
    console.print(f"[bold][*] subfinder   :[/] {sf_status}")
    console.print(f"[bold][*] Threads     :[/] {args.threads}")
    console.print(f"[bold][*] Alive output:[/] alive_subdomains.txt")
    console.print()

    semaphore = asyncio.Semaphore(args.threads)
    output_q  = asyncio.Queue()
    start     = time.time()

    async with make_session(args.timeout) as session:

        printer_task = asyncio.create_task(output_printer(output_q, args.alive_only))

        # ── PHASE 1: Enumerate ────────────────────────────────────────────────
        console.rule("[cyan bold]PHASE 1 — Subdomain Enumeration[/]")
        collected = await enumerate_subdomains(
            domain        = domain,
            sources        = args.sources,
            api_key        = args.api_key,
            use_subfinder  = args.subfinder,
            output_q       = output_q,
        )
        console.print(
            f"\n[bold green][+] Enumeration complete — "
            f"{stats['discovered']} unique subdomains found[/]\n"
        )

        if args.no_probe:
            await output_q.put(None)
            await printer_task
        else:
            # ── PHASE 2: Alive check ──────────────────────────────────────────
            console.rule("[cyan bold]PHASE 2 — Alive Check (concurrent)[/]")
            probe_tasks = [
                asyncio.create_task(
                    probe_alive(
                        sub, src, session, semaphore, output_q,
                        args.alive_only, args.timeout,
                    )
                )
                for sub, src in collected
            ]
            await asyncio.gather(*probe_tasks, return_exceptions=True)
            console.print(
                f"\n[bold green][+] Alive check complete — "
                f"{stats['alive']} alive / {stats['dead']} dead[/]\n"
            )

            await output_q.put(None)
            await printer_task

    elapsed = time.time() - start

    # ── Always save alive_subdomains.txt ─────────────────────────────────────
    export_alive_txt("alive_subdomains.txt")

    # ── Optional exports ──────────────────────────────────────────────────────
    if args.json:
        export_json(args.json)
    if args.csv:
        export_csv(args.csv)

    # ── Final summary ─────────────────────────────────────────────────────────
    console.print()
    console.rule("[bold cyan]SCAN COMPLETE[/]")
    dash = Table(title="Results Summary", box=box.ROUNDED, border_style="cyan")
    dash.add_column("Metric",  style="bold")
    dash.add_column("Count",   justify="right")
    dash.add_row("Total Discovered", f"[bold]{stats['discovered']}[/]")
    dash.add_row("Alive",            f"[bold green]{stats['alive']}[/]")
    dash.add_row("Dead",             f"[bold red]{stats['dead']}[/]")
    dash.add_row("Errors",           f"[dim]{stats['errors']}[/]")
    dash.add_row("Elapsed",          f"[dim]{elapsed:.1f}s[/]")
    console.print(dash)

# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def main():
    all_sources = list(SOURCES.keys()) + ["securitytrails"]
    parser = argparse.ArgumentParser(
        description="Async subdomain enumeration + alive checker",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("domain", help="Target domain  (e.g. example.com)")
    parser.add_argument(
        "-s", "--sources",
        nargs="+",
        default=list(SOURCES.keys()),
        choices=all_sources,
        metavar="SOURCE",
        help="Sources to use (default: all free)\nAvailable: " + ", ".join(all_sources),
    )
    parser.add_argument("-k",  "--api-key",    help="SecurityTrails API key")
    parser.add_argument(
        "--subfinder",
        action="store_true",
        help="Also run the local `subfinder` binary (auto-detected on PATH)",
    )
    parser.add_argument("-t",  "--threads",    type=int, default=80,
                        help="Concurrency limit (default: 80)")
    parser.add_argument("--timeout",           type=int, default=8,
                        help="HTTP timeout seconds (default: 8)")
    parser.add_argument("--alive-only",        action="store_true",
                        help="Suppress DEAD output in terminal")
    parser.add_argument("--no-probe",          action="store_true",
                        help="Enumerate only — skip alive check")
    parser.add_argument("--json",              metavar="FILE",
                        help="Export alive results to JSON file")
    parser.add_argument("--csv",               metavar="FILE",
                        help="Export alive results to CSV file")
    parser.add_argument("-v", "--verbose",     action="store_true",
                        help="Enable debug logging")

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger("subfinder").setLevel(logging.DEBUG)

    asyncio.run(async_main(args))


if __name__ == "__main__":
    main()
