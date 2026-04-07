# 👻 Phantom — OSINT Intelligence Dashboard

![Python](https://img.shields.io/badge/Python-3.x-blue?style=flat-square&logo=python)
![Flask](https://img.shields.io/badge/Flask-2.x-green?style=flat-square&logo=flask)
![License](https://img.shields.io/badge/License-MIT-red?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)

> A powerful OSINT automation tool built with Python & Flask. Designed for passive reconnaissance in penetration testing.

---

## 🔍 What is Phantom?

Phantom automates the **passive reconnaissance phase** of a penetration test. Instead of running multiple tools manually, Phantom aggregates everything in one real-time interface.

---

## ⚡ Features

**🌐 Domain Recon**
- WHOIS, DNS records, subdomain enumeration via crt.sh
- SSL/TLS analysis — version, expiry, cipher, SANs
- Email spoofing check — SPF, DMARC, DKIM
- Technology detection — CMS, frameworks, CDN
- Automatic risk score (0-100)

**📡 IP Investigation**
- Geolocation, reverse DNS, ASN
- Interactive map with marker

**👤 Username Lookup**
- 20+ platforms — GitHub, Twitter, Instagram, HackTheBox...

**📧 Email Analysis**
- Format validation, MX records, provider detection

**🔎 Shodan Integration**
- Open ports, CVEs, OS fingerprinting

**🖥️ Live Terminal**
- Real-time streaming, color-coded output, progress bar

**📊 Dashboard**
- Stats, risk distribution, scan history

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

Open `http://127.0.0.1:5000`

---

## ⚙️ Optional API Keys

Create a `.env` file:
```
SHODAN_API_KEY=your_key
HIBP_API_KEY=your_key
```

---

## 🛠️ Stack

Python 3 • Flask • dnspython • python-whois • requests • Shodan • Leaflet.js

---

## ⚠️ Disclaimer

For educational purposes only. Use responsibly and legally.

---

## 👤 Author

**Mahmd-75** — Cybersecurity student | Pentest & Offensive Security

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue?style=flat-square&logo=linkedin)](h[ttps://linkedin.com/in/mahmoud-el-shetewi](https://www.linkedin.com/in/mahmoud-el-shetewi-2a3027331/))
