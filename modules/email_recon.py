import requests
import dns.resolver
import re

def scan_email(email):
    result = {}

    # Validation format email
    try:
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        is_valid = bool(re.match(pattern, email))
        result['format'] = {
            'valid': is_valid,
            'email': email
        }

        if is_valid:
            parts = email.split('@')
            result['format']['username'] = parts[0]
            result['format']['domain'] = parts[1]
    except Exception as e:
        result['format'] = {'error': str(e)}

    # Vérification MX records du domaine
    try:
        domain = email.split('@')[1]
        mx_records = dns.resolver.resolve(domain, 'MX')
        result['mx_records'] = [str(r.exchange) for r in mx_records]
        result['email_deliverable'] = True
    except Exception as e:
        result['mx_records'] = []
        result['email_deliverable'] = False

    # Détection du provider
    try:
        domain = email.split('@')[1].lower()
        providers = {
            'gmail.com': 'Google Gmail',
            'yahoo.com': 'Yahoo Mail',
            'hotmail.com': 'Microsoft Hotmail',
            'outlook.com': 'Microsoft Outlook',
            'protonmail.com': 'ProtonMail',
            'icloud.com': 'Apple iCloud',
            'tutanota.com': 'Tutanota'
        }
        result['provider'] = providers.get(domain, f'Custom domain — {domain}')
    except Exception as e:
        result['provider'] = {'error': str(e)}

    # HaveIBeenPwned (optionnel si clé API dispo)
    try:
        from dotenv import load_dotenv
        import os
        load_dotenv()
        api_key = os.getenv('HIBP_API_KEY')

        if api_key:
            headers = {
                'hibp-api-key': api_key,
                'User-Agent': 'Phantom-OSINT'
            }
            response = requests.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                headers=headers,
                timeout=10
            )
            if response.status_code == 200:
                breaches = response.json()
                result['hibp'] = {
                    'pwned': True,
                    'breach_count': len(breaches),
                    'breaches': [b['Name'] for b in breaches]
                }
            elif response.status_code == 404:
                result['hibp'] = {'pwned': False}
        else:
            result['hibp'] = {'status': 'Pas de clé API HIBP configurée'}
    except Exception as e:
        result['hibp'] = {'error': str(e)}

    return result
