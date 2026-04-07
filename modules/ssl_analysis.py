import ssl
import socket
from datetime import datetime

def analyze_ssl(domain):
    result = {}

    try:
        context = ssl.create_default_context()
        conn = context.wrap_socket(
            socket.socket(socket.AF_INET),
            server_hostname=domain
        )
        conn.settimeout(10)
        conn.connect((domain, 443))
        cert = conn.getpeercert()
        cipher = conn.cipher()
        version = conn.version()
        conn.close()

        # Dates
        not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        now = datetime.utcnow()
        days_left = (not_after - now).days

        result['valid'] = True
        result['not_before'] = not_before.strftime('%d/%m/%Y')
        result['not_after'] = not_after.strftime('%d/%m/%Y')
        result['days_left'] = days_left
        result['expired'] = days_left < 0
        result['expiring_soon'] = 0 <= days_left <= 30

        # Version TLS
        result['tls_version'] = version
        result['tls_secure'] = version in ['TLSv1.2', 'TLSv1.3']

        # Cipher
        result['cipher_name'] = cipher[0]
        result['cipher_bits'] = cipher[2]

        # Issuer
        issuer = dict(x[0] for x in cert.get('issuer', []))
        result['issuer'] = issuer.get('organizationName', 'Unknown')

        # Subject
        subject = dict(x[0] for x in cert.get('subject', []))
        result['common_name'] = subject.get('commonName', 'Unknown')

        # Wildcard
        result['wildcard'] = result['common_name'].startswith('*.')

        # SANs
        sans = []
        for san_type, san_value in cert.get('subjectAltName', []):
            if san_type == 'DNS':
                sans.append(san_value)
        result['sans'] = sans[:10]
        result['san_count'] = len(sans)

        # Score SSL
        ssl_score = 100
        if not result['tls_secure']:
            ssl_score -= 40
        if result['expired']:
            ssl_score -= 50
        elif result['expiring_soon']:
            ssl_score -= 20
        if result['cipher_bits'] and result['cipher_bits'] < 128:
            ssl_score -= 20

        result['ssl_score'] = max(0, ssl_score)

    except ssl.SSLError as e:
        result['valid'] = False
        result['error'] = f'SSL Error: {str(e)}'
    except socket.timeout:
        result['valid'] = False
        result['error'] = 'Connection timeout'
    except ConnectionRefusedError:
        result['valid'] = False
        result['error'] = 'Port 443 closed'
    except Exception as e:
        result['valid'] = False
        result['error'] = str(e)

    return result
