import shodan
import os
from dotenv import load_dotenv

load_dotenv()

def scan_shodan(ip):
    result = {}
    api_key = os.getenv('SHODAN_API_KEY')

    if not api_key:
        return {'error': 'Pas de clé API Shodan'}

    try:
        api = shodan.Shodan(api_key)
        host = api.host(ip)

        result['ip'] = host.get('ip_str')
        result['org'] = host.get('org', 'Unknown')
        result['os'] = host.get('os', 'Unknown')
        result['country'] = host.get('country_name', 'Unknown')
        result['city'] = host.get('city', 'Unknown')
        result['isp'] = host.get('isp', 'Unknown')
        result['last_update'] = host.get('last_update', 'Unknown')
        result['hostnames'] = host.get('hostnames', [])
        result['tags'] = host.get('tags', [])

        # Ports et services
        ports = []
        for item in host.get('data', []):
            port_info = {
                'port': item.get('port'),
                'protocol': item.get('transport', 'tcp'),
                'service': item.get('_shodan', {}).get('module', 'unknown'),
                'banner': item.get('data', '')[:100].strip(),
                'product': item.get('product', ''),
                'version': item.get('version', ''),
                'cpe': item.get('cpe', [])
            }
            ports.append(port_info)

        result['ports'] = sorted(ports, key=lambda x: x['port'])
        result['total_ports'] = len(ports)

        # Vulnérabilités si disponibles
        vulns = host.get('vulns', {})
        if vulns:
            result['vulns'] = list(vulns.keys())[:10]
        else:
            result['vulns'] = []

    except shodan.APIError as e:
        result['error'] = str(e)
    except Exception as e:
        result['error'] = str(e)

    return result
