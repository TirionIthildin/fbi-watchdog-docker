# Running FBI Watchdog with Docker

Run FBI Watchdog in Docker with Tor and Playwright Chromium included. State, screenshots, and your monitored sites list are stored in a Docker volume so they persist across restarts.

**Run all commands from the repository root** (one level above this folder).

By default, no `.env` file is used. The watchdog runs without Discord/Telegram/proxy unless you add them (see optional section below).

---

## 1. Build and start

```bash
docker compose -f docker/docker-compose.yml up -d --build
```

The container runs the watchdog in headless mode with one silent baseline cycle by default.

**View logs:**

```bash
docker compose -f docker/docker-compose.yml logs -f fbi-watchdog
```

---

## 2. Add or manage sites

Sites are stored inside the `watchdog-data` volume. To add sites, run the CLI inside the container:

```bash
docker compose -f docker/docker-compose.yml exec fbi-watchdog python3 fbi_watchdog.py --add example.com anothersite.org somehiddenservice.onion
```

**List sites:**

```bash
docker compose -f docker/docker-compose.yml exec fbi-watchdog python3 fbi_watchdog.py --list-sites
```

To edit `monitored_sites.json` directly, run a shell in a one-off container with the data volume mounted and edit the file (e.g. install an editor in the image or bind-mount a host file over `/app/data/monitored_sites.json`).

---

## 3. Optional: Discord, Telegram, or proxy

To send alerts or use a SOCKS5 proxy, either use a `.env` file or set variables in Compose.

**Option A – .env file**

Create `.env` in the repo root from the example, then add `env_file: [../.env]` to the service in your compose override:

```bash
cp docker/env.example .env
chmod 600 .env
```

Edit `.env` with your values. In **[docker-compose.example.yml](docker-compose.example.yml)** the `env_file` block is commented; uncomment it in a copy or override so Compose loads `.env`.

**Option B – Set in Compose**

Use **[docker-compose.example.yml](docker-compose.example.yml)** as reference. Copy it to `docker-compose.override.yml` and set `WEBHOOKFBIWATCHDOG`, `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`, and/or `CLEARNET_PROXY` (or pass them from your shell when running `docker compose`).

**.env examples (if using Option A):**

| Scenario        | Set in .env |
|----------------|-------------|
| Discord only   | `WEBHOOKFBIWATCHDOG=https://discord.com/api/webhooks/...` |
| Telegram only  | `TELEGRAM_BOT_TOKEN=...`, `TELEGRAM_CHAT_ID=...` |
| SOCKS5 proxy   | `CLEARNET_PROXY=socks5h://127.0.0.1:1080` |
| All optional   | Leave all empty; alerts only in console and event feed |

---

## 4. Run with different options

Override the default command to run with notifications from the first cycle, or with specific monitors disabled:

```bash
docker compose -f docker/docker-compose.yml run --rm fbi-watchdog python3 fbi_watchdog.py --no-menu --loud
docker compose -f docker/docker-compose.yml run --rm fbi-watchdog python3 fbi_watchdog.py --no-menu --silent --no-whois --no-ip
```

---

## 5. Using the image without Compose

Build the image from the repo root, then run with a volume for data. Add `--env-file .env` only if you use a `.env` file:

```bash
docker build -t fbi-watchdog -f docker/Dockerfile .
docker run -d --name fbi-watchdog \
  -e FBI_WATCHDOG_DATA_DIR=/app/data \
  -v watchdog-data:/app/data \
  fbi-watchdog
```

With Discord/Telegram/proxy via `.env`:

```bash
docker run -d --name fbi-watchdog \
  -e FBI_WATCHDOG_DATA_DIR=/app/data \
  -v watchdog-data:/app/data \
  --env-file .env \
  fbi-watchdog
```

**Add sites when using plain `docker run`:**

```bash
docker exec fbi-watchdog python3 fbi_watchdog.py --add example.com
```

---

## Troubleshooting

If Chromium fails to launch in the container (e.g. shared memory issues), try running with `ipc: host` under the service in `docker/docker-compose.yml` or `docker run --ipc=host`.
