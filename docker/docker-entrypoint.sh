#!/bin/sh
set -e

# If using a data dir and monitored_sites.json is missing, seed from example
if [ -n "$FBI_WATCHDOG_DATA_DIR" ] && [ ! -f "$FBI_WATCHDOG_DATA_DIR/monitored_sites.json" ]; then
    cp /app/monitored_sites.example.json "$FBI_WATCHDOG_DATA_DIR/monitored_sites.json"
fi

# Start Tor in the background (SOCKS 9050, control 9051)
tor &

# Give Tor a moment to open the SOCKS port
sleep 3

# Run the watchdog (exec so it receives signals)
exec "$@"
