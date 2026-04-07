# 👻 Phantom — OSINT Intelligence Dashboard

![Python](https://img.shields.io/badge/Python-3.x-blue?style=flat-square&logo=python)
![Flask](https://img.shields.io/badge/Flask-2.x-green?style=flat-square&logo=flask)
![License](https://img.shields.io/badge/License-MIT-red?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)

> A powerful OSINT automation tool built with Python & Flask. Designed for passive reconnaissance in penetration testing.

---

## What is Phantom?

Phantom is an OSINT Intelligence Dashboard that automates the passive reconnaissance phase of a penetration test. Instead of running multiple tools manually, Phantom aggregates all the information you need in one clean, real-time interface.

---

## Features

### Domain Recon
- WHOIS lookup — registrar, dates, country
- DNS records — A, MX, TXT, NS
- Subdomain enumeration via crt.sh
- HTTP headers analysis
- SSL/TLS certificate analysis — version, expiry, cipher, SANs
- Email spoofing check — SPF, DMARC, DKIM
- Technology detection — CMS, frameworks, CDN, analytics
- Automatic risk score (0-100) with detailed findings

### IP Investigation
- Geolocation — country, city, ISP, timezone
- Reverse DNS lookup
- Network info — ASN, organization
- Interactive map with precise marker

### Username Lookup
- Check presence on 20+ platforms simultaneously
- GitHub, Twitter, Instagram, Reddit, TikTok, HackTheBox, TryHackMe...

### Email Analysis
- Format validation
- MX records verification
- Provider detection
- HaveIBeenPwned integration (API key required)

### Shodan Integration
- Open ports and services
- CVE detection
- OS fingerprinting
- Tags and hostnames

### Live Terminal
- Real-time streaming of scan results
- Color-coded output
- Progress bar
- Auto-redirect to report on completion

### Dashboard
- Global stats — total scans, avg risk score
- Risk distribution chart
- Top detected technologies
- Full scan history

---

## Installation

git clone https://github.com/Mahmd-75/Phantom.git
cd Phantom
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 app.py

Then open http://127.0.0.1:5000 in your browser.

---

## Optional API Keys

Create a .env file in the root directory:

SHODAN_API_KEY=your_shodan_key
HIBP_API_KEY=your_hibp_key

- Shodan — Free tier available at shodan.io
- HaveIBeenPwned — Available at haveibeenpwned.com/API/Key

---

## Tech Stack

Backend: Python 3, Flask
DNS: dnspython
WHOIS: python-whois
HTTP: requests, BeautifulSoup4
Shodan: shodan
Maps: Leaflet.js
Frontend: HTML, CSS, Vanilla JS

---

## Project Structure

phantom/
app.py — Flask app + SSE streaming
modules/
  domain_recon.py — WHOIS, DNS, subdomains
  ip_recon.py — Geolocation, reverse DNS
  username_recon.py — Multi-platform lookup
  email_recon.py — Email analysis + HIBP
  shodan_recon.py — Shodan API integration
  ssl_analysis.py — SSL/TLS certificate analysis
  email_spoofing.py — SPF/DMARC/DKIM checker
  tech_detect.py — Technology fingerprinting
  risk_score.py — Automatic risk scoring
templates/
  base.html — Base layout
  index.html — Dashboard + scan form
  terminal.html — Live terminal view
  report.html — Scan report
  history.html — Scan history

---

## Disclaimer

This tool is for educational purposes only. Only use Phantom on systems you own or have explicit permission to test. The author is not responsible for any misuse.

---

## Author

Mahmd-75 — Cybersecurity student | Pentest & Offensive Security
GitHub: https://github.com/Mahmd-75
LinkedIn: www.linkedin.com/in/mahmoud-el-shetewi-2a3027331
