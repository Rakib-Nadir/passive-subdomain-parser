# 🔍 Passive Subdomain Parser

> Async passive subdomain enumeration & alive checker — built for bug bounty hunters and VAPT engineers.

![Tool Banner](banner.png)

---

## ✨ Features

- 🌐 **Multi-source enumeration** — crt.sh, HackerTarget, AlienVault, RapidDNS, urlscan.io, ThreatCrowd, SecurityTrails
- ⚡ **Fully async** — blazing fast concurrent alive checking via `asyncio` + `aiohttp`
- 🔗 **subfinder integration** — auto-detects and merges results from the binary if installed
- 💾 **Auto-saves** alive subdomains to `alive_subdomains.txt`
- 📦 **Export** results to JSON or CSV
- 🎨 **Rich terminal UI** — color-coded status codes, live output, summary dashboard

---

## 📦 Installation

```bash
git clone https://github.com/Rakib-Nadir/passive-subdomain-parser.git
cd passive-subdomain-parser
pip install -r requirements.txt
```

---

## 🚀 Usage

```bash
# Basic scan
python passive-subdomain-parser.py example.com

# Use specific sources only
python passive-subdomain-parser.py example.com -s crt.sh alienvault urlscan

# With SecurityTrails API key
python passive-subdomain-parser.py example.com -k YOUR_API_KEY

# Enable subfinder binary
python passive-subdomain-parser.py example.com --subfinder

# Show alive only, export to JSON and CSV
python passive-subdomain-parser.py example.com --alive-only --json out.json --csv out.csv

# Enumerate only — skip alive check
python passive-subdomain-parser.py example.com --no-probe
```

---

## ⚙️ Options

| Flag | Description |
|------|-------------|
| `-s`, `--sources` | Sources to query (default: all free sources) |
| `-k`, `--api-key` | SecurityTrails API key |
| `--subfinder` | Run local `subfinder` binary and merge results |
| `-t`, `--threads` | Concurrency limit (default: 80) |
| `--timeout` | HTTP timeout in seconds (default: 8) |
| `--alive-only` | Suppress dead subdomains from terminal output |
| `--no-probe` | Skip alive check, enumerate only |
| `--json FILE` | Export results to JSON |
| `--csv FILE` | Export results to CSV |
| `-v`, `--verbose` | Enable debug logging |

---

## 📡 Sources

| Source | Auth Required |
|--------|---------------|
| crt.sh | No |
| HackerTarget | No |
| AlienVault OTX | No |
| RapidDNS | No |
| urlscan.io | No |
| ThreatCrowd | No |
| SecurityTrails | API Key |
| subfinder | Binary |

---

## 📄 Output

Alive subdomains are always saved to `alive_subdomains.txt` after every run. Optional JSON and CSV exports available via flags.

---

## ⚠️ Disclaimer

This tool is intended for **authorized security testing and bug bounty programs only**. Always obtain proper permission before scanning any target. The author is not responsible for any misuse.

---

<p align="center">Made with ❤️ by <a href="https://github.com/Rakib-Nadir">Rakib Nadir</a></p>
