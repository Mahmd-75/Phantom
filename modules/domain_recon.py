import whois
import dns.resolver
import requests
import socket

def scan_domain(domain):
    result = {}

    # WHOIS
    try:
        w = whois.whois(domain)
        result['whois'] = {
            'registrar': w.registrar,
            'creation_date': str(w.creation_date),
            'expiration_date': str(w.expiration_date),
            'name_servers': w.name_servers,
            'country': w.country
        }
    except Exception as e:
        result['whois'] = {'error': str(e)}

    # DNS Records
    try:
        dns_records = {}
        for record_type in ['A', 'MX', 'TXT', 'NS']:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                dns_records[record_type] = [str(r) for r in answers]
            except:
                dns_records[record_type] = []
        result['dns'] = dns_records
    except Exception as e:
        result['dns'] = {'error': str(e)}

    # Sous-domaines via crt.sh
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            subdomains = list(set([
                entry['name_value']
                for entry in data
                if '*' not in entry['name_value']
            ]))[:20]  # On limite à 20
            result['subdomains'] = subdomains
        else:
            result['subdomains'] = []
    except Exception as e:
        result['subdomains'] = {'error': str(e)}

    # IP du domaine
    try:
        ip = socket.gethostbyname(domain)
        result['ip'] = ip
    except Exception as e:
        result['ip'] = {'error': str(e)}

    # Headers HTTP
    try:
        response = requests.get(f"http://{domain}", timeout=5)
        result['headers'] = dict(response.headers)
    except Exception as e:
        result['headers'] = {'error': str(e)}

    return result
