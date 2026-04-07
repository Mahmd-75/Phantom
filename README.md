# 👻 Phantom — OSINT Intelligence Dashboard

![Python](https://img.shields.io/badge/Python-3.x-blue?style=flat-square&logo=python)
![Flask](https://img.shields.io/badge/Flask-2.x-green?style=flat-square&logo=flask)
![License](https://img.shields.io/badge/License-MIT-red?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)
![Stars](https://img.shields.io/github/stars/Mahmd-75/Phantom?style=flat-square&color=red)
![Forks](https://img.shields.io/github/forks/Mahmd-75/Phantom?style=flat-square&color=gray)

> A powerful OSINT automation tool built with Python & Flask.  
> Designed for **passive reconnaissance** in penetration testing.

---

## 🔍 What is Phantom?

Phantom is an OSINT Intelligence Dashboard that automates the **passive reconnaissance phase** of a penetration test.

Instead of running 10 different tools manually, Phantom aggregates everything — WHOIS, DNS, subdomains, SSL, ports, technologies, risk score — in one clean **real-time terminal interface**.

> 💡 *"Before attacking a target, a pentester always starts with reconnaissance. I automated this phase."*

---

## ⚡ Features

| Module | Description |
|---|---|
| 🌐 **Domain Recon** | WHOIS, DNS, subdomains, HTTP headers, SSL/TLS |
| 📡 **IP Investigation** | Geolocation, reverse DNS, ASN, interactive map |
| 👤 **Username Lookup** | 20+ platforms — GitHub, Twitter, HTB, THM... |
| 📧 **Email Analysis** | Format, MX records, provider, HIBP |
| 🔎 **Shodan** | Open ports, CVEs, OS fingerprinting |
| 🔒 **SSL/TLS Analysis** | Version, cipher, expiry, wildcard, SANs |
| 📨 **Email Spoofing** | SPF, DMARC, DKIM checker + verdict |
| ⚡ **Tech Detection** | CMS, frameworks, CDN, analytics |
| 📊 **Risk Score** | Automatic 0-100 scoring with findings |
| 🖥️ **Live Terminal** | Real-time streaming, color-coded output |
| 📈 **Dashboard** | Stats, risk distribution, scan history |

---

## 🚀 Installation
```bash
git clone https://github.com/Mahmd-75/Phantom.git
cd Phantom
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 app.py
```

Open `http://127.0.0.1:5000` in your browser.

---

## ⚙️ Optional API Keys

Create a `.env` file in the root directory:
```env
SHODAN_API_KEY=your_shodan_key
HIBP_API_KEY=your_hibp_key
```

- **Shodan** — Free tier at [shodan.io](https://shodan.io)
- **HaveIBeenPwned** — At [haveibeenpwned.com/API/Key](https://haveibeenpwned.com/API/Key)

---

## 🛠️ Tech Stack
```
Backend    → Python 3, Flask, SSE (Server-Sent Events)
DNS        → dnspython
WHOIS      → python-whois
HTTP       → requests, BeautifulSoup4
Shodan     → shodan
Maps       → Leaflet.js (OpenStreetMap + CARTO dark tiles)
Frontend   → HTML, CSS, Vanilla JS
```

---

## 📁 Project Structure
```
phantom/
├── app.py                  # Flask app + SSE live streaming
├── modules/
│   ├── domain_recon.py     # WHOIS, DNS, subdomains
│   ├── ip_recon.py         # Geolocation, reverse DNS
│   ├── username_recon.py   # Multi-platform lookup
│   ├── email_recon.py      # Email analysis + HIBP
│   ├── shodan_recon.py     # Shodan API integration
│   ├── ssl_analysis.py     # SSL/TLS certificate analysis
│   ├── email_spoofing.py   # SPF/DMARC/DKIM checker
│   ├── tech_detect.py      # Technology fingerprinting
│   └── risk_score.py       # Automatic risk scoring
└── templates/
    ├── base.html           # Base layout + dark theme
    ├── index.html          # Dashboard + scan form
    ├── terminal.html       # Live terminal view
    ├── report.html         # Full scan report
    └── history.html        # Scan history
```

---

## ⚠️ Disclaimer

This tool is for **educational purposes only**.  
Only use Phantom on systems you **own** or have **explicit permission** to test.  
The author is not responsible for any misuse.

---

## 👤 Author

**Mahmoud El Shetewi** — Cybersecurity student | Pentest & Offensive Security

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Mahmoud%20El%20Shetewi-blue?style=flat-square&logo=linkedin)](https://www.linkedin.com/in/mahmoud-el-shetewi-2a3027331/)
[![GitHub](https://img.shields.io/badge/GitHub-Mahmd--75-red?style=flat-square&logo=github)](https://github.com/Mahmd-75)
