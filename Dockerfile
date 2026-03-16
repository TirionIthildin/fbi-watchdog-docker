# FBI Watchdog - Docker image with Python, Playwright Chromium, and Tor
# Playwright image includes Chromium and system deps; we add Tor for onion monitoring.
FROM mcr.microsoft.com/playwright/python:v1.49.0-noble

USER root

# Install Tor (SOCKS 9050, control 9051 for circuit rotation)
RUN apt-get update && apt-get install -y --no-install-recommends tor \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Enable Tor control port for circuit renewal (CookieAuthentication 0 = empty password)
RUN echo "ControlPort 9051" >> /etc/tor/torrc \
    && echo "CookieAuthentication 0" >> /etc/tor/torrc

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY fbi_watchdog.py .
COPY env.example ./env.example
COPY monitored_sites.example.json ./monitored_sites.example.json

# Entrypoint: start Tor, then run the watchdog
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["python3", "fbi_watchdog.py", "--no-menu", "--silent"]
