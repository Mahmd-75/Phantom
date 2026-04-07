def calculate_risk(report_type, data):
    score = 0
    findings = []
    positive = []

    if report_type == 'domain':
        whois = data.get('whois', {})
        headers = data.get('headers', {})
        subdomains = data.get('subdomains', [])
        techs = data.get('technologies', {}).get('technologies', [])
        dns = data.get('dns', {})

        # WHOIS checks
        if not whois or 'error' in whois:
            score += 15
            findings.append('WHOIS inaccessible ou masqué')
        else:
            if not whois.get('registrar'):
                score += 10
                findings.append('Registrar inconnu')
            if not whois.get('country'):
                score += 5
                findings.append('Pays du registrant inconnu')

        # Headers de sécurité
        headers_lower = {k.lower(): v for k, v in headers.items()}

        if 'strict-transport-security' not in headers_lower:
            score += 10
            findings.append('HSTS absent — pas de forçage HTTPS')
        else:
            positive.append('HSTS présent')

        if 'x-frame-options' not in headers_lower:
            score += 8
            findings.append('X-Frame-Options absent — risque clickjacking')
        else:
            positive.append('X-Frame-Options présent')

        if 'x-content-type-options' not in headers_lower:
            score += 5
            findings.append('X-Content-Type-Options absent')
        else:
            positive.append('X-Content-Type-Options présent')

        if 'content-security-policy' not in headers_lower:
            score += 10
            findings.append('Content-Security-Policy absent')
        else:
            positive.append('CSP présent')

        if 'x-xss-protection' not in headers_lower:
            score += 5
            findings.append('X-XSS-Protection absent')

        # Technologies risquées
        risky_techs = ['WordPress', 'Joomla', 'Drupal']
        for tech in risky_techs:
            if tech in techs:
                score += 10
                findings.append(f'{tech} détecté — CMS souvent ciblé')

        # Sous-domaines exposés
        if len(subdomains) > 10:
            score += 8
            findings.append(f'{len(subdomains)} sous-domaines exposés')
        elif len(subdomains) > 5:
            score += 4
            findings.append(f'{len(subdomains)} sous-domaines trouvés')

        # DNS checks
        txt_records = dns.get('TXT', [])
        has_spf = any('spf' in r.lower() for r in txt_records)
        has_dmarc = any('dmarc' in r.lower() for r in txt_records)

        if not has_spf:
            score += 8
            findings.append('SPF absent — domaine vulnérable au spoofing')
        else:
            positive.append('SPF configuré')

        if not has_dmarc:
            score += 8
            findings.append('DMARC absent — pas de protection anti-spoofing email')
        else:
            positive.append('DMARC configuré')

    elif report_type == 'shodan':
        ports = data.get('ports', [])
        vulns = data.get('vulns', [])
        tags = data.get('tags', [])

        # Ports dangereux
        dangerous_ports = {
            21: 'FTP ouvert',
            22: 'SSH exposé publiquement',
            23: 'Telnet ouvert — protocole non chiffré',
            25: 'SMTP ouvert',
            3389: 'RDP exposé — risque brute force',
            3306: 'MySQL exposé publiquement',
            5432: 'PostgreSQL exposé publiquement',
            6379: 'Redis exposé — souvent non authentifié',
            27017: 'MongoDB exposé publiquement',
            9200: 'Elasticsearch exposé',
        }

        for port_info in ports:
            port_num = port_info.get('port')
            if port_num in dangerous_ports:
                score += 12
                findings.append(f'Port {port_num} — {dangerous_ports[port_num]}')

        # CVEs
        if vulns:
            score += len(vulns) * 8
            findings.append(f'{len(vulns)} CVE(s) détectée(s) par Shodan')

        # Tags Shodan
        risky_tags = ['self-signed', 'expired-cert', 'default-login', 'honeypot']
        for tag in tags:
            if tag in risky_tags:
                score += 10
                findings.append(f'Tag Shodan: {tag}')

        if not ports:
            positive.append('Aucun port dangereux détecté')

    elif report_type == 'email':
        if not data.get('email_deliverable'):
            score += 20
            findings.append('Email non délivrable')
        else:
            positive.append('Email délivrable')

        if not data.get('format', {}).get('valid'):
            score += 30
            findings.append('Format email invalide')

    # Cap à 100
    score = min(score, 100)

    # Niveau de risque
    if score >= 70:
        level = 'CRITICAL'
        color = '#ff0033'
    elif score >= 45:
        level = 'HIGH'
        color = '#ff6600'
    elif score >= 25:
        level = 'MEDIUM'
        color = '#ffcc00'
    else:
        level = 'LOW'
        color = '#00ff44'

    return {
        'score': score,
        'level': level,
        'color': color,
        'findings': findings,
        'positive': positive
    }
