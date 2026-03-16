<p align="center">
  <img src="screenshots/fbi_watchdog_banner.png" alt="FBI Watchdog Banner" width="700">
</p>

<h1 align="center">FBI Watchdog</h1>

<p align="center">
  <strong>Domain seizure detection and monitoring tool for cyber threat intelligence</strong>
</p>

<p align="center">
  <a href="https://darkwebinformer.com">DarkWebInformer.com</a> ·
  <a href="https://x.com/DarkWebInformer">@DarkWebInformer</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-3.0.0-blue" alt="Version">
  <img src="https://img.shields.io/badge/python-3.9+-yellow" alt="Python">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License">
</p>

---

FBI Watchdog is a multi-layered domain monitoring tool that detects law enforcement seizures, DNS changes, HTTP fingerprint shifts, WHOIS record mutations, and IP address changes across clearnet domains and Tor onion sites. Built for threat intelligence analysts, security researchers, and anyone tracking domain infrastructure changes in real time.

When a seizure signal is detected across any monitor, the tool triggers a cross-monitor escalation audit, captures a screenshot of the seized page, and sends consolidated alerts to Discord and Telegram with full evidence.

<p align="center">
  <img src="screenshots/scan_cycle.png" alt="Scan Cycle">
</p>

---

## Features

- **DNS Monitoring** - Tracks A, AAAA, CNAME, MX, NS, and TXT records across all monitored domains. Detects never-before-seen record combinations and flags seizure-related DNS entries (e.g., `fbi.seized`, `seized.gov`, `usssdomainseizure`).

- **HTTP Fingerprint Monitoring** - Fingerprints server headers, status codes, body content hashes, redirect chains, and page size. Detects seizure keywords in page content, redirect-to-government patterns, and simultaneous server + body changes that indicate infrastructure takeover.

- **WHOIS Monitoring** - Tracks registrar, nameservers, registrant organization, status codes (EPP), and creation/expiration dates. Detects seizure indicators in WHOIS data including law enforcement registrar changes, server prohibition flags, and known LE Cloudflare nameservers.

- **IP Change Monitoring** - Monitors A and AAAA record IP addresses with reverse DNS lookups. Classifies changes as CDN rotation, hosting migration, provider change, or seizure signal based on rDNS matching against known law enforcement infrastructure.

- **Onion Site Monitoring** - Connects via Tor to monitor `.onion` sites for seizure banners. Supports automatic Tor circuit rotation on connection failures. Detects seizure keywords from FBI, Europol, BKA, AFP, Garda, RCMP, Polisen, and other international law enforcement agencies.

- **Cross-Monitor Seizure Escalation** - When any single monitor detects a seizure signal, an escalation engine triggers a full audit across all monitors, captures a screenshot, and sends a consolidated multi-evidence alert.

- **Automated Screenshot Capture** - Uses headless Chromium via Playwright to capture full-page screenshots of seized domains, attached to Discord and Telegram notifications.

- **Discord & Telegram Alerts** - Real-time notifications with rich embeds (Discord) and formatted messages (Telegram). Screenshots are attached directly to seizure alerts.

- **Silent Mode** - First scan cycle(s) can run silent to build a baseline state without triggering notifications. Prevents alert floods on first run or after a state reset.

- **Event Feed** - Maintains a rolling JSON event feed of all detected changes, baselines, and seizure events for external consumption or dashboard integration.

- **Hot Reload** - Monitored sites list is re-read from disk every scan cycle. Add or remove sites without restarting the watchdog.

- **SOCKS5 Proxy Support** - Route all clearnet HTTP/WHOIS requests through a SOCKS5 proxy. Proxy exit IP is validated against your real IP on startup. Note: screenshot capture via Playwright does not support SOCKS5 proxies with authentication and will fall back to a direct connection if proxy auth is configured. All other requests (HTTP, WHOIS, DNS, IP) work normally with authenticated proxies.

<table>
  <tr>
    <td><img src="screenshots/discord_alert.png" alt="Discord Alert" width="400"></td>
    <td><img src="screenshots/telegram_alert.png" alt="Telegram Alert" width="400"></td>
  </tr>
</table>

<p align="center">Real notifications captured during the LeakBase domain forum seizure by law enforcement.</p>

---

## FBI Watchdog Live Feed

A live, continuously updated feed powered by this tool is available at [darkwebinformer.com/fbi-watchdog-feed](https://darkwebinformer.com/fbi-watchdog-feed). The feed displays real-time seizure detections, DNS changes, HTTP fingerprint shifts, WHOIS mutations, and IP changes as they are detected across monitored domains and onion sites.

The live feed is available exclusively to paying subscribers of [Dark Web Informer](https://darkwebinformer.com/pricing).

---

## Architecture

```
┌───────────────────────────────────────────────────────────────────────┐
│                          FBI Watchdog v3.0.0                          │
├─────────────┬──────────────┬───────────────┬───────────┬──────────────┤
│ DNS Monitor │ HTTP Monitor │ WHOIS Monitor │IP Monitor │Onion Monitor │
│ (dnspython) │  (requests)  │(python-whois) │(dnspython)│ (Tor SOCKS)  │
├─────────────┴──────────────┴───────────────┴───────────┴──────────────┤
│                           Escalation Engine                           │
│              (Cross-monitor audit + screenshot capture)               │
├───────────────────────────────────┬───────────────────────────────────┤
│         Discord Webhooks          │         Telegram Bot API          │
├─────────────────────┬─────────────┴─────────────┬─────────────────────┤
│ State Files (JSON)  │     Event Feed (JSON)     │  Screenshots (PNG)  │
└─────────────────────┴───────────────────────────┴─────────────────────┘
```

---

## Requirements

- Python 3.9+
- Tor (for onion site monitoring)
- Chromium (installed via Playwright for screenshot capture)

---

## Running with Docker

To run FBI Watchdog in Docker (with Tor and Playwright Chromium), see **[docker/README.md](docker/README.md)** for setup, build, and usage. Quick start from the repo root (no .env required by default):

```bash
docker compose -f docker/docker-compose.yml up -d --build
```

---

## Installation

**1. Clone the repository**

```bash
git clone https://github.com/DarkWebInformer/FBIWatchdog.git
cd FBIWatchdog
```

**2. Install Python dependencies**

```bash
pip install -r requirements.txt
```

**3. Install Playwright browsers**

```bash
playwright install chromium
```

**4. Configure environment variables**

```bash
cp .env.example .env
chmod 600 .env
```

Edit `.env` and add your Discord webhook URL, Telegram credentials, or both. All notification channels are optional - the watchdog runs without any configured.

**5. Add sites to monitor**

```bash
python3 fbi_watchdog.py --add example.com anothersite.org somehiddenservice.onion
```

Or edit `monitored_sites.json` directly (see `monitored_sites.example.json` for format).

**6. Run**

```bash
python3 fbi_watchdog.py
```

---

## Configuration

### Environment Variables

| Variable | Required | Description |
|---|---|---|
| `WEBHOOKFBIWATCHDOG` | No | Discord webhook URL (`https://discord.com/api/webhooks/...`) |
| `TELEGRAM_BOT_TOKEN` | No | Telegram bot token for alert delivery |
| `TELEGRAM_CHAT_ID` | No | Telegram chat/channel ID for alerts |
| `CLEARNET_PROXY` | No | SOCKS5 proxy for clearnet requests (e.g., `socks5h://127.0.0.1:1080`). When configured, startup validation makes two requests to `api.ipify.org` to verify the proxy exit IP differs from your real IP. |

All notification channels are optional. Configure Discord, Telegram, both, or neither. Without any notification channels, the watchdog still runs and logs all detections to the console and event feed JSON.

### Monitored Sites

Sites are stored in `monitored_sites.json` and can be managed via CLI flags or the interactive menu:

```json
{
  "domains": [
    "example.com",
    "anotherdomain.org"
  ],
  "onion_sites": [
    "exampleonion1234.onion"
  ]
}
```

Sites are validated on add and reload. Invalid entries (malformed domains, path traversal attempts) are rejected.

The sites file is hot-reloaded every scan cycle - you can edit it while the watchdog is running.

---

## Usage

### Interactive Menu

```bash
python3 fbi_watchdog.py
```

Launches an interactive menu where you can start monitoring, manage sites, toggle individual monitors, view state stats, reset state files, and see the CLI reference.

![Menu](screenshots/startup_menu.png)

### Headless / PM2

```bash
# Start with 1 silent baseline cycle (default)
python3 fbi_watchdog.py --no-menu --silent

# Start with notifications active from cycle 1
python3 fbi_watchdog.py --no-menu --loud

# Reset all state and start fresh
python3 fbi_watchdog.py --no-menu --reset

# Disable specific monitors
python3 fbi_watchdog.py --no-menu --silent --no-whois --no-ip

# Route clearnet requests through a proxy
python3 fbi_watchdog.py --no-menu --silent --proxy socks5h://127.0.0.1:1080
```

### PM2 Examples

```bash
# Standard deployment
pm2 start fbi_watchdog.py --interpreter python3 -- --no-menu --silent

# Notifications hot from cycle 1
pm2 start fbi_watchdog.py --interpreter python3 -- --no-menu --loud

# Full reset and restart
pm2 start fbi_watchdog.py --interpreter python3 -- --no-menu --reset

# DNS and onion monitoring only
pm2 start fbi_watchdog.py --interpreter python3 -- --no-menu --silent --no-http --no-whois --no-ip
```

### Site Management (CLI)

```bash
# Add sites
python3 fbi_watchdog.py --add newsite.cc somemarket.onion

# Remove sites
python3 fbi_watchdog.py --remove oldsite.cc

# List all monitored sites
python3 fbi_watchdog.py --list-sites
```

### CLI Flags Reference

| Flag | Description |
|---|---|
| `--silent [N]` | Run N silent cycles before enabling notifications (default: 1) |
| `--loud` | Start with notifications active immediately |
| `--no-menu` | Skip interactive menu (for PM2/systemd/daemon usage) |
| `--reset` | Wipe all state files before starting (implies `--silent`) |
| `--add SITE [...]` | Add one or more sites to monitoring |
| `--remove SITE [...]` | Remove one or more sites from monitoring |
| `--list-sites` | List all monitored sites and exit |
| `--no-dns` | Disable DNS monitoring |
| `--no-http` | Disable HTTP fingerprint monitoring |
| `--no-whois` | Disable WHOIS monitoring |
| `--no-ip` | Disable IP change monitoring |
| `--no-onion` | Disable onion site monitoring |
| `--proxy URL` | SOCKS5 proxy for clearnet requests (overrides `CLEARNET_PROXY` env var) |

---

## Monitors

### DNS Monitor

Queries A, AAAA, CNAME, MX, NS, and TXT records for each clearnet domain. Maintains a history of up to 10 unique record sets per domain/record type. Fires an alert when a never-before-seen record combination appears.

Seizure-specific DNS indicators (e.g., `fbi.seized`, `seized.gov`, `europol`, `usssdomainseizure`) trigger immediate seizure alerts with screenshot capture.

### HTTP Fingerprint Monitor

Fetches each domain over HTTPS (falling back to HTTP) and fingerprints tracked response headers (`server`, `x-powered-by`, `strict-transport-security`, `via`, `x-cdn`, etc.), status code, final URL after redirects, and a SHA-256 hash of the response body.

Change detection filters out noise from transient HTTP errors (502-524), Cloudflare/DDoS-Guard challenge pages, and minor body fluctuations (under 35% size change). Runs fetches in parallel (10 concurrent by default).

Seizure signals include government domain redirects, seizure keywords in page content, simultaneous server header + body changes, and status code changes to 403/451.

### WHOIS Monitor

Queries WHOIS data for each clearnet domain and tracks registrar, nameservers, registrant organization, registrant country, EPP status codes, and key dates. Runs lookups in parallel (5 concurrent by default).

Normalizes registrar names (e.g., "Tucows Domains Inc." → "tucows"), strips ICANN EPP URL prefixes from status codes, deduplicates compound EPP tokens, and filters out privacy-service org changes to reduce false positives. Includes a state migration system that re-normalizes stored records when normalization logic changes between versions.

Seizure indicators include law enforcement keywords in WHOIS data, known LE Cloudflare nameservers paired with server prohibition flags, and registrar changes to government entities.

### IP Monitor

Resolves A and AAAA records and tracks IP address changes across scan cycles. Performs reverse DNS on new IPs and classifies changes into categories: CDN rotation (same provider, different IP pool), hosting migration (complete IP replacement), provider change (CDN swap or CDN removal), and seizure signal (rDNS matching known law enforcement infrastructure like `fbi.gov`, `justice.gov`, `europol`, etc.).

### Onion Monitor

Connects to each `.onion` site via Tor SOCKS proxy, downloads page content (capped at 5MB), and scans for seizure keywords from international law enforcement agencies. Supports automatic Tor circuit rotation on connection failures or timeouts, with a single retry on a fresh circuit.

### Seizure Escalation Engine

When any monitor detects a seizure signal (not just a change - a signal with seizure-specific indicators), the escalation engine triggers a full cross-monitor audit:

1. Immediate DNS audit across all record types
2. Screenshot capture via headless Chromium
3. Consolidated alert sent to Discord and Telegram with evidence from all monitors

This ensures that a single seizure indicator triggers comprehensive evidence collection rather than a piecemeal alert.

---

## State Files

The watchdog maintains separate state files for each monitor:

| File | Contents |
|---|---|
| `fbi_watchdog_results.json` | DNS record history per domain |
| `http_watchdog_results.json` | HTTP fingerprints per domain |
| `whois_watchdog_results.json` | WHOIS records and seizure indicators |
| `ip_watchdog_results.json` | Current A/AAAA records per domain |
| `onion_watchdog_results.json` | Onion site status (active/seized/unreachable) |
| `event_feed.json` | Rolling event feed (last 500 events) |
| `monitored_sites.json` | List of monitored clearnet and onion sites |

All state files use atomic writes (write to temp file, then `os.replace`) to prevent corruption on crash or power loss.

State can be reset via `--reset` flag or the interactive menu.

---

## Tor Setup

Onion site monitoring requires a running Tor instance with SOCKS proxy on port 9050 (default) or 9150 (Tor Browser).

**Install Tor:**

```bash
# Debian/Ubuntu
sudo apt install tor

# Start the service
sudo systemctl start tor
sudo systemctl enable tor
```

**Optional: Enable circuit rotation**

To allow the watchdog to rotate Tor circuits on connection failures, enable the control port in `/etc/tor/torrc`:

```
ControlPort 9051
CookieAuthentication 0
```

Then restart Tor:

```bash
sudo systemctl restart tor
```

For shared servers, use `HashedControlPassword` instead of disabling cookie authentication:

```bash
tor --hash-password "your_password"
```

Add the output to `torrc` as `HashedControlPassword`.

The watchdog verifies Tor connectivity by checking `https://check.torproject.org/` through the SOCKS proxy before starting onion scans. If Tor is not running, onion monitoring is skipped gracefully.

![Onion Scan Cycle](screenshots/onion_scan.png)

---

## Security

- All credentials are loaded from environment variables via `.env` - nothing is hardcoded
- The `.env` file permission is checked on startup and warns if it is readable by other users
- Discord webhook URL is validated against `https://discord.com/api/webhooks/` prefix
- Telegram bot token and chat ID are format-validated before use
- SOCKS5 proxy URL is regex-validated and exit IP is tested against your real IP on startup
- Site input is validated with a strict regex, rejects path traversal and malformed domains
- Screenshot paths are validated against the screenshots directory to prevent path traversal
- HTTP responses are streamed with a 5MB cap to prevent memory exhaustion
- Onion responses are capped at 5MB
- Keyword scanning is limited to the first 1MB of body content
- All state files use atomic writes to prevent corruption
- Proxy credentials are sanitized from error messages before console output
- Playwright runs headless with JavaScript disabled, downloads disabled, and `--no-sandbox`
- Event IDs use `secrets.token_hex()` (cryptographically secure)
- Signal handlers ensure graceful shutdown with state file saves on SIGINT/SIGTERM

### External Network Calls

When `CLEARNET_PROXY` is configured, the watchdog makes two requests to `https://api.ipify.org` on startup: one through the proxy and one direct. This is used solely to verify the proxy is working by comparing exit IPs. No data is sent to `api.ipify.org` beyond a standard GET request. These calls only occur once at startup and only when a proxy is configured. During normal monitoring, the only external calls are DNS queries, HTTP requests to monitored domains, WHOIS lookups, Tor connectivity checks via `check.torproject.org`, and notification delivery to Discord/Telegram APIs.

---

## Support FBI Watchdog & Dark Web Informer

FBI Watchdog is an open-source project dedicated to cyber threat intelligence, monitoring seizure banners, and providing real-time insights. Your support helps keep this project running!

You can also get access to premium cyber threat intelligence on **[Dark Web Informer](https://darkwebinformer.com)**.

### Subscription Options:  
- **Standard and Crypto Subscription:** [Sign up here](https://darkwebinformer.com/pricing)

Stay ahead of the latest cyber threats with real-time intelligence.

### ❤️ Donate to Support Dark Web Informer's Work
If you find Dark Web Informer and/or FBI Watchdog valuable, consider making a **donation** to help future development, research, and cyber threat intelligence.
[Donate here](https://darkwebinformer.com/donations)

### Advertise With Dark Web Informer
Looking to **promote your cybersecurity services** or **reach the right audience**?
Check out the **advertising options** here: [Advertising Rates](https://darkwebinformer.com/advertising-rates)

Your support helps keep **FBI Watchdog** and **Dark Web Informer** independent and continuously improving. Thank you!

---

## Star History

<a href="https://star-history.com/#DarkWebInformer/FBI_Watchdog&Date">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=DarkWebInformer/FBI_Watchdog&type=Date&theme=dark" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/svg?repos=DarkWebInformer/FBI_Watchdog&type=Date" />
   <img alt="Star History Chart" src="https://api.star-history.com/svg?repos=DarkWebInformer/FBI_Watchdog&type=Date" />
 </picture>
</a>

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

---

<p align="center">
  Built by <a href="https://darkwebinformer.com">Dark Web Informer</a>
</p>
