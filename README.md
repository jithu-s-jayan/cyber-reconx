# Cyber ReconX

A powerful OSINT (Open Source Intelligence) platform built with Flask — featuring domain intelligence, username/identity fingerprinting, port scanning, IP geolocation, and scan history.

## Features

- 🔍 **Website Intelligence** — WHOIS, DNS, SSL, security headers analysis
- 👤 **Identity Fingerprint** — Username & real-name social media footprint scanner (powered by Wikidata)
- 🔌 **Port Sweeper** — Multithreaded TCP port scanner
- 🌍 **IP Geolocation** — ASN, ISP, coordinates, VPN/proxy detection
- 📋 **Scan History** — Persistent audit trail of all operations
- 🔐 **Authentication** — Login/Register system with Google OAuth support

## Tech Stack

- **Backend**: Python / Flask
- **Frontend**: Vanilla HTML, CSS, JavaScript
- **Database**: SQLite
- **Intelligence APIs**: Wikidata, ipinfo, public OSINT endpoints

## Setup

```bash
# Install dependencies
pip install -r requirements.txt

# Run the app
python app.py
```

Open http://localhost:5000

## Disclaimer

This tool is strictly for **educational and ethical use**. Only scan targets you have explicit permission to test.
