from flask import Flask, render_template, request, jsonify, Response, stream_with_context
from modules.shodan_recon import scan_shodan
from modules.tech_detect import detect_technologies
from modules.risk_score import calculate_risk
from modules.username_recon import PLATFORMS
from modules.email_recon import scan_email
from modules.ssl_analysis import analyze_ssl
from modules.email_spoofing import check_spoofing
import uuid
import json
import time
from datetime import datetime

app = Flask(__name__)

reports = {}
history = []

def format_sse(data):
    return f"data: {json.dumps(data)}\n\n"

def stream_domain(target):
    yield format_sse({'type': 'log', 'msg': f'[*] Target: {target}', 'color': 'white'})
    time.sleep(0.3)
    yield format_sse({'type': 'log', 'msg': '[*] Starting WHOIS lookup...', 'color': 'yellow'})
    time.sleep(0.3)

    import whois
    import requests
    import socket
    import dns.resolver

    try:
        w = whois.whois(target)
        whois_data = {
            'registrar': w.registrar,
            'creation_date': str(w.creation_date),
            'expiration_date': str(w.expiration_date),
            'name_servers': w.name_servers,
            'country': w.country
        }
        yield format_sse({'type': 'log', 'msg': f'[+] Registrar: {w.registrar}', 'color': 'green'})
        yield format_sse({'type': 'log', 'msg': f'[+] Country: {w.country}', 'color': 'green'})
        time.sleep(0.2)
    except Exception as e:
        whois_data = {'error': str(e)}
        yield format_sse({'type': 'log', 'msg': f'[-] WHOIS failed: {str(e)}', 'color': 'red'})

    yield format_sse({'type': 'log', 'msg': '[*] Resolving DNS records...', 'color': 'yellow'})
    time.sleep(0.3)

    dns_data = {}
    for record_type in ['A', 'MX', 'TXT', 'NS']:
        try:
            answers = dns.resolver.resolve(target, record_type)
            records = [str(r) for r in answers]
            dns_data[record_type] = records
            for r in records[:2]:
                yield format_sse({'type': 'log', 'msg': f'[+] {record_type}: {r[:60]}', 'color': 'green'})
            time.sleep(0.2)
        except:
            dns_data[record_type] = []

    yield format_sse({'type': 'log', 'msg': '[*] Enumerating subdomains via crt.sh...', 'color': 'yellow'})
    time.sleep(0.3)

    subdomains = []
    try:
        url = f"https://crt.sh/?q=%.{target}&output=json"
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            subdomains = list(set([
                entry['name_value']
                for entry in data
                if '*' not in entry['name_value']
            ]))[:20]
            yield format_sse({'type': 'log', 'msg': f'[+] Found {len(subdomains)} subdomains', 'color': 'green'})
            for sub in subdomains[:5]:
                yield format_sse({'type': 'log', 'msg': f'    -> {sub}', 'color': 'cyan'})
            time.sleep(0.2)
    except Exception as e:
        yield format_sse({'type': 'log', 'msg': f'[-] Subdomain enum failed: {str(e)}', 'color': 'red'})

    yield format_sse({'type': 'log', 'msg': '[*] Fetching HTTP headers...', 'color': 'yellow'})
    time.sleep(0.3)

    headers_data = {}
    ip = ''
    try:
        ip = socket.gethostbyname(target)
        yield format_sse({'type': 'log', 'msg': f'[+] IP Address: {ip}', 'color': 'green'})
        response = requests.get(f"http://{target}", timeout=5)
        headers_data = dict(response.headers)
        server = headers_data.get('Server', 'Unknown')
        yield format_sse({'type': 'log', 'msg': f'[+] Server: {server}', 'color': 'green'})
    except Exception as e:
        yield format_sse({'type': 'log', 'msg': f'[-] Headers failed: {str(e)}', 'color': 'red'})

    yield format_sse({'type': 'log', 'msg': '[*] Analyzing SSL/TLS certificate...', 'color': 'yellow'})
    time.sleep(0.3)

    ssl_data = analyze_ssl(target)
    if ssl_data.get('valid'):
        yield format_sse({'type': 'log', 'msg': f'[+] Issuer: {ssl_data.get("issuer")}', 'color': 'green'})
        yield format_sse({'type': 'log', 'msg': f'[+] TLS: {ssl_data.get("tls_version")}', 'color': 'green' if ssl_data.get('tls_secure') else 'red'})
        yield format_sse({'type': 'log', 'msg': f'[+] Expires: {ssl_data.get("not_after")} ({ssl_data.get("days_left")} days)', 'color': 'green' if not ssl_data.get('expiring_soon') else 'red'})
        if ssl_data.get('wildcard'):
            yield format_sse({'type': 'log', 'msg': '[!] Wildcard certificate detected', 'color': 'yellow'})
    else:
        yield format_sse({'type': 'log', 'msg': f'[-] SSL failed: {ssl_data.get("error")}', 'color': 'red'})

    yield format_sse({'type': 'log', 'msg': '', 'color': 'white'})
    yield format_sse({'type': 'log', 'msg': '[*] Checking email spoofing...', 'color': 'yellow'})
    time.sleep(0.3)

    spoofing_data = check_spoofing(target)
    yield format_sse({'type': 'log', 'msg': f'[*] SPF: {"found" if spoofing_data["spf"].get("found") else "missing"}', 'color': 'green' if spoofing_data['spf'].get('found') else 'red'})
    yield format_sse({'type': 'log', 'msg': f'[*] DMARC: {"found" if spoofing_data["dmarc"].get("found") else "missing"}', 'color': 'green' if spoofing_data['dmarc'].get('found') else 'red'})
    yield format_sse({'type': 'log', 'msg': f'[!] Verdict: {spoofing_data["verdict"]}', 'color': 'red' if spoofing_data['spoofable'] else 'green'})
    time.sleep(0.2)

    yield format_sse({'type': 'log', 'msg': '', 'color': 'white'})
    yield format_sse({'type': 'log', 'msg': '[*] Detecting technologies...', 'color': 'yellow'})
    time.sleep(0.3)

    tech_data = detect_technologies(target)
    if tech_data.get('technologies'):
        for tech in tech_data['technologies']:
            yield format_sse({'type': 'log', 'msg': f'[+] Detected: {tech}', 'color': 'cyan'})
            time.sleep(0.1)
    else:
        yield format_sse({'type': 'log', 'msg': '[-] No technologies detected', 'color': 'red'})

    result = {
        'whois': whois_data,
        'dns': dns_data,
        'subdomains': subdomains,
        'ip': ip,
        'headers': headers_data,
        'ssl': ssl_data,
        'spoofing': spoofing_data,
        'technologies': tech_data
    }

    risk = calculate_risk('domain', result)
    result['risk'] = risk

    yield format_sse({'type': 'log', 'msg': '', 'color': 'white'})
    yield format_sse({'type': 'log', 'msg': f'[*] Risk Score: {risk["score"]}/100 - {risk["level"]}', 'color': 'yellow'})

    report_id = str(uuid.uuid4())[:8]
    timestamp = datetime.now().strftime('%d/%m/%Y %H:%M:%S')
    reports[report_id] = {
        'target': target,
        'type': 'domain',
        'data': result,
        'timestamp': timestamp,
        'id': report_id
    }
    history.insert(0, {
        'id': report_id,
        'target': target,
        'type': 'domain',
        'timestamp': timestamp
    })

    yield format_sse({'type': 'log', 'msg': '', 'color': 'white'})
    yield format_sse({'type': 'log', 'msg': '[✓] Scan complete.', 'color': 'green'})
    time.sleep(0.5)
    yield format_sse({'type': 'done', 'redirect': f'/report/{report_id}'})


def stream_ip(target):
    yield format_sse({'type': 'log', 'msg': f'[*] Target: {target}', 'color': 'white'})
    time.sleep(0.3)
    yield format_sse({'type': 'log', 'msg': '[*] Geolocating IP...', 'color': 'yellow'})
    time.sleep(0.3)

    import requests
    import socket

    geo = {}
    try:
        response = requests.get(f"http://ip-api.com/json/{target}", timeout=10)
        data = response.json()
        geo = {
            'country': data.get('country'),
            'region': data.get('regionName'),
            'city': data.get('city'),
            'isp': data.get('isp'),
            'org': data.get('org'),
            'lat': data.get('lat'),
            'lon': data.get('lon'),
            'timezone': data.get('timezone')
        }
        yield format_sse({'type': 'log', 'msg': f'[+] Country: {geo["country"]}', 'color': 'green'})
        yield format_sse({'type': 'log', 'msg': f'[+] City: {geo["city"]}', 'color': 'green'})
        yield format_sse({'type': 'log', 'msg': f'[+] ISP: {geo["isp"]}', 'color': 'green'})
        time.sleep(0.2)
    except Exception as e:
        yield format_sse({'type': 'log', 'msg': f'[-] Geolocation failed: {str(e)}', 'color': 'red'})

    yield format_sse({'type': 'log', 'msg': '[*] Reverse DNS lookup...', 'color': 'yellow'})
    time.sleep(0.3)

    reverse_dns = ''
    try:
        reverse_dns = socket.gethostbyaddr(target)[0]
        yield format_sse({'type': 'log', 'msg': f'[+] Hostname: {reverse_dns}', 'color': 'green'})
    except:
        yield format_sse({'type': 'log', 'msg': '[-] No reverse DNS found', 'color': 'red'})

    network = {}
    try:
        response = requests.get(f"https://ipinfo.io/{target}/json", timeout=10)
        data = response.json()
        network = {
            'hostname': data.get('hostname'),
            'org': data.get('org'),
            'postal': data.get('postal'),
            'asn': data.get('org')
        }
        yield format_sse({'type': 'log', 'msg': f'[+] ASN: {network["asn"]}', 'color': 'green'})
    except Exception as e:
        yield format_sse({'type': 'log', 'msg': f'[-] Network info failed: {str(e)}', 'color': 'red'})

    result = {'geolocation': geo, 'reverse_dns': reverse_dns, 'network': network}

    report_id = str(uuid.uuid4())[:8]
    timestamp = datetime.now().strftime('%d/%m/%Y %H:%M:%S')
    reports[report_id] = {
        'target': target, 'type': 'ip',
        'data': result, 'timestamp': timestamp, 'id': report_id
    }
    history.insert(0, {'id': report_id, 'target': target, 'type': 'ip', 'timestamp': timestamp})

    yield format_sse({'type': 'log', 'msg': '', 'color': 'white'})
    yield format_sse({'type': 'log', 'msg': '[✓] Scan complete.', 'color': 'green'})
    time.sleep(0.5)
    yield format_sse({'type': 'done', 'redirect': f'/report/{report_id}'})


def stream_username(target):
    yield format_sse({'type': 'log', 'msg': f'[*] Target username: {target}', 'color': 'white'})
    time.sleep(0.3)
    yield format_sse({'type': 'log', 'msg': '[*] Checking platforms...', 'color': 'yellow'})
    time.sleep(0.3)

    import requests

    found = []
    not_found = []
    headers = {'User-Agent': 'Mozilla/5.0'}

    for platform, url_template in PLATFORMS.items():
        url = url_template.format(target)
        try:
            response = requests.get(url, headers=headers, timeout=5)
            if response.status_code == 200:
                found.append({'platform': platform, 'url': url})
                yield format_sse({'type': 'log', 'msg': f'[+] Found: {platform} -> {url}', 'color': 'green'})
            else:
                not_found.append(platform)
                yield format_sse({'type': 'log', 'msg': f'[-] Not found: {platform}', 'color': 'red'})
        except:
            not_found.append(platform)
        time.sleep(0.1)

    result = {
        'found': found,
        'not_found': not_found,
        'summary': {
            'total_checked': len(PLATFORMS),
            'found_count': len(found),
            'not_found_count': len(not_found)
        }
    }

    report_id = str(uuid.uuid4())[:8]
    timestamp = datetime.now().strftime('%d/%m/%Y %H:%M:%S')
    reports[report_id] = {
        'target': target, 'type': 'username',
        'data': result, 'timestamp': timestamp, 'id': report_id
    }
    history.insert(0, {'id': report_id, 'target': target, 'type': 'username', 'timestamp': timestamp})

    yield format_sse({'type': 'log', 'msg': '', 'color': 'white'})
    yield format_sse({'type': 'log', 'msg': f'[✓] Done. {len(found)}/{len(PLATFORMS)} profiles found.', 'color': 'green'})
    time.sleep(0.5)
    yield format_sse({'type': 'done', 'redirect': f'/report/{report_id}'})


def stream_email(target):
    yield format_sse({'type': 'log', 'msg': f'[*] Target email: {target}', 'color': 'white'})
    time.sleep(0.3)
    yield format_sse({'type': 'log', 'msg': '[*] Validating format...', 'color': 'yellow'})
    time.sleep(0.3)

    result = scan_email(target)

    if result.get('format', {}).get('valid'):
        yield format_sse({'type': 'log', 'msg': '[+] Format valid', 'color': 'green'})
    else:
        yield format_sse({'type': 'log', 'msg': '[-] Invalid format', 'color': 'red'})

    yield format_sse({'type': 'log', 'msg': f'[+] Provider: {result.get("provider", "Unknown")}', 'color': 'green'})
    time.sleep(0.3)

    yield format_sse({'type': 'log', 'msg': '[*] Checking MX records...', 'color': 'yellow'})
    time.sleep(0.3)

    if result.get('email_deliverable'):
        yield format_sse({'type': 'log', 'msg': '[+] Email is deliverable', 'color': 'green'})
    else:
        yield format_sse({'type': 'log', 'msg': '[-] Email not deliverable', 'color': 'red'})

    risk = calculate_risk('email', result)
    result['risk'] = risk

    report_id = str(uuid.uuid4())[:8]
    timestamp = datetime.now().strftime('%d/%m/%Y %H:%M:%S')
    reports[report_id] = {
        'target': target, 'type': 'email',
        'data': result, 'timestamp': timestamp, 'id': report_id
    }
    history.insert(0, {'id': report_id, 'target': target, 'type': 'email', 'timestamp': timestamp})

    yield format_sse({'type': 'log', 'msg': '', 'color': 'white'})
    yield format_sse({'type': 'log', 'msg': '[✓] Scan complete.', 'color': 'green'})
    time.sleep(0.5)
    yield format_sse({'type': 'done', 'redirect': f'/report/{report_id}'})


def stream_shodan(target):
    yield format_sse({'type': 'log', 'msg': f'[*] Target: {target}', 'color': 'white'})
    time.sleep(0.3)
    yield format_sse({'type': 'log', 'msg': '[*] Connecting to Shodan...', 'color': 'yellow'})
    time.sleep(0.5)

    result = scan_shodan(target)
    risk = calculate_risk('shodan', result)
    result['risk'] = risk

    if 'error' in result:
        yield format_sse({'type': 'log', 'msg': f'[-] Shodan error: {result["error"]}', 'color': 'red'})
    else:
        yield format_sse({'type': 'log', 'msg': f'[+] Organization: {result.get("org")}', 'color': 'green'})
        yield format_sse({'type': 'log', 'msg': f'[+] Country: {result.get("country")}', 'color': 'green'})
        yield format_sse({'type': 'log', 'msg': f'[+] OS: {result.get("os")}', 'color': 'green'})
        yield format_sse({'type': 'log', 'msg': f'[+] ISP: {result.get("isp")}', 'color': 'green'})
        time.sleep(0.3)

        yield format_sse({'type': 'log', 'msg': '', 'color': 'white'})
        yield format_sse({'type': 'log', 'msg': f'[*] Scanning ports... ({result.get("total_ports", 0)} found)', 'color': 'yellow'})
        time.sleep(0.3)

        for port in result.get('ports', []):
            service = port.get('service', 'unknown')
            product = port.get('product', '')
            version = port.get('version', '')
            info = f"{product} {version}".strip() or service
            yield format_sse({
                'type': 'log',
                'msg': f'[+] {port["port"]}/{port["protocol"]} - {info}',
                'color': 'cyan'
            })
            time.sleep(0.1)

        if result.get('vulns'):
            yield format_sse({'type': 'log', 'msg': '', 'color': 'white'})
            yield format_sse({'type': 'log', 'msg': f'[!] {len(result["vulns"])} CVE(s) detected!', 'color': 'red'})
            for vuln in result['vulns']:
                yield format_sse({'type': 'log', 'msg': f'    -> {vuln}', 'color': 'red'})

        if result.get('tags'):
            yield format_sse({'type': 'log', 'msg': '', 'color': 'white'})
            yield format_sse({'type': 'log', 'msg': f'[*] Tags: {", ".join(result["tags"])}', 'color': 'yellow'})

    yield format_sse({'type': 'log', 'msg': '', 'color': 'white'})
    yield format_sse({'type': 'log', 'msg': f'[*] Risk Score: {risk["score"]}/100 - {risk["level"]}', 'color': 'yellow'})

    report_id = str(uuid.uuid4())[:8]
    timestamp = datetime.now().strftime('%d/%m/%Y %H:%M:%S')
    reports[report_id] = {
        'target': target, 'type': 'shodan',
        'data': result, 'timestamp': timestamp, 'id': report_id
    }
    history.insert(0, {'id': report_id, 'target': target, 'type': 'shodan', 'timestamp': timestamp})

    yield format_sse({'type': 'log', 'msg': '', 'color': 'white'})
    yield format_sse({'type': 'log', 'msg': '[✓] Shodan scan complete.', 'color': 'green'})
    time.sleep(0.5)
    yield format_sse({'type': 'done', 'redirect': f'/report/{report_id}'})

def get_stats():
    total = len(history)
    by_type = {}
    risk_levels = {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0}
    risk_scores = []
    top_techs = {}

    for report_id, report in reports.items():
        scan_type = report.get('type', 'unknown')
        by_type[scan_type] = by_type.get(scan_type, 0) + 1

        risk = report.get('data', {}).get('risk', {})
        if risk.get('level'):
            level = risk['level']
            if level in risk_levels:
                risk_levels[level] += 1
        if risk.get('score') is not None:
            risk_scores.append(risk['score'])

        techs = report.get('data', {}).get('technologies', {}).get('technologies', [])
        for tech in techs:
            top_techs[tech] = top_techs.get(tech, 0) + 1

    avg_risk = round(sum(risk_scores) / len(risk_scores)) if risk_scores else 0
    top_techs_sorted = sorted(top_techs.items(), key=lambda x: x[1], reverse=True)[:5]

    return {
        'total': total,
        'by_type': by_type,
        'risk_levels': risk_levels,
        'avg_risk': avg_risk,
        'top_techs': top_techs_sorted,
        'recent': history[:5]
    }

@app.route('/')
def index():
    stats = get_stats()
    return render_template('index.html', stats=stats)

@app.route('/scan', methods=['POST'])
def scan():
    scan_type = request.form.get('scan_type')
    target = request.form.get('target').strip()
    if not target or not scan_type:
        return jsonify({'error': 'Cible ou type manquant'}), 400
    return jsonify({'redirect': f'/terminal?target={target}&type={scan_type}'})

@app.route('/terminal')
def terminal():
    target = request.args.get('target', '')
    scan_type = request.args.get('type', '')
    return render_template('terminal.html', target=target, scan_type=scan_type)

@app.route('/stream')
def stream():
    target = request.args.get('target', '')
    scan_type = request.args.get('type', '')

    def generate():
        if scan_type == 'domain':
            yield from stream_domain(target)
        elif scan_type == 'ip':
            yield from stream_ip(target)
        elif scan_type == 'username':
            yield from stream_username(target)
        elif scan_type == 'email':
            yield from stream_email(target)
        elif scan_type == 'shodan':
            yield from stream_shodan(target)

    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no'
        }
    )

@app.route('/report/<report_id>')
def report(report_id):
    data = reports.get(report_id)
    if not data:
        return render_template('index.html'), 404
    return render_template('report.html', report=data)

@app.route('/history')
def history_page():
    return render_template('history.html', history=history)

if __name__ == '__main__':
    app.run(debug=True)
