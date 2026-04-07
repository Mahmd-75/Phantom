import requests
import socket

def scan_ip(ip):
    result = {}

    # Géolocalisation
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
        if response.status_code == 200:
            data = response.json()
            result['geolocation'] = {
                'country': data.get('country'),
                'region': data.get('regionName'),
                'city': data.get('city'),
                'isp': data.get('isp'),
                'org': data.get('org'),
                'lat': data.get('lat'),
                'lon': data.get('lon'),
                'timezone': data.get('timezone')
            }
    except Exception as e:
        result['geolocation'] = {'error': str(e)}

    # Reverse DNS
    try:
        hostname = socket.gethostbyaddr(ip)
        result['reverse_dns'] = hostname[0]
    except Exception as e:
        result['reverse_dns'] = {'error': str(e)}

    # Infos réseau via ipinfo.io
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=10)
        if response.status_code == 200:
            data = response.json()
            result['network'] = {
                'hostname': data.get('hostname'),
                'org': data.get('org'),
                'postal': data.get('postal'),
                'asn': data.get('org')
            }
    except Exception as e:
        result['network'] = {'error': str(e)}

    return result
