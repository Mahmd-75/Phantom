import dns.resolver

def check_spoofing(domain):
    result = {
        'domain': domain,
        'spf': None,
        'dmarc': None,
        'dkim_hint': None,
        'spoofable': False,
        'risk_level': None,
        'details': []
    }

    # SPF Check
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        spf_record = None
        for r in answers:
            txt = str(r).strip('"')
            if txt.startswith('v=spf1'):
                spf_record = txt
                break

        if spf_record:
            result['spf'] = {
                'found': True,
                'record': spf_record,
                'strict': '-all' in spf_record,
                'soft': '~all' in spf_record,
                'neutral': '?all' in spf_record or '+all' in spf_record
            }
            if '-all' in spf_record:
                result['details'].append(('green', 'SPF strict (-all) — emails non autorisés rejetés'))
            elif '~all' in spf_record:
                result['details'].append(('yellow', 'SPF soft (~all) — emails non autorisés marqués spam'))
            elif '+all' in spf_record:
                result['details'].append(('red', 'SPF +all — TOUT le monde peut envoyer depuis ce domaine !'))
            else:
                result['details'].append(('yellow', 'SPF neutre — protection partielle'))
        else:
            result['spf'] = {'found': False}
            result['details'].append(('red', 'SPF absent — domaine spoofable par email'))

    except Exception as e:
        result['spf'] = {'found': False, 'error': str(e)}
        result['details'].append(('red', f'SPF lookup failed: {str(e)}'))

    # DMARC Check
    try:
        dmarc_answers = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
        dmarc_record = None
        for r in dmarc_answers:
            txt = str(r).strip('"')
            if txt.startswith('v=DMARC1'):
                dmarc_record = txt
                break

        if dmarc_record:
            policy = 'none'
            if 'p=reject' in dmarc_record:
                policy = 'reject'
            elif 'p=quarantine' in dmarc_record:
                policy = 'quarantine'
            elif 'p=none' in dmarc_record:
                policy = 'none'

            result['dmarc'] = {
                'found': True,
                'record': dmarc_record,
                'policy': policy
            }

            if policy == 'reject':
                result['details'].append(('green', 'DMARC policy=reject — emails spoofés rejetés'))
            elif policy == 'quarantine':
                result['details'].append(('yellow', 'DMARC policy=quarantine — emails spoofés mis en quarantaine'))
            elif policy == 'none':
                result['details'].append(('red', 'DMARC policy=none — aucune action sur les emails spoofés'))
        else:
            result['dmarc'] = {'found': False}
            result['details'].append(('red', 'DMARC absent — pas de politique anti-spoofing'))

    except Exception as e:
        result['dmarc'] = {'found': False, 'error': str(e)}
        result['details'].append(('red', 'DMARC absent ou inaccessible'))

    # DKIM hint
    common_selectors = ['default', 'google', 'mail', 'dkim', 'key1', 'selector1', 'selector2']
    dkim_found = False
    for selector in common_selectors:
        try:
            dns.resolver.resolve(f'{selector}._domainkey.{domain}', 'TXT')
            dkim_found = True
            result['dkim_hint'] = selector
            result['details'].append(('green', f'DKIM trouvé (selector: {selector})'))
            break
        except:
            continue

    if not dkim_found:
        result['dkim_hint'] = None
        result['details'].append(('yellow', 'DKIM non détecté avec les sélecteurs communs'))

    # Verdict final
    spf_ok = result['spf'].get('found') and result['spf'].get('strict')
    dmarc_ok = result['dmarc'].get('found') and result['dmarc'].get('policy') in ['reject', 'quarantine']

    if not spf_ok and not dmarc_ok:
        result['spoofable'] = True
        result['risk_level'] = 'CRITICAL'
        result['verdict'] = 'Domaine hautement spoofable — aucune protection efficace'
    elif not spf_ok or not dmarc_ok:
        result['spoofable'] = True
        result['risk_level'] = 'HIGH'
        result['verdict'] = 'Domaine partiellement protege — spoofing possible'
    elif spf_ok and dmarc_ok and dkim_found:
        result['spoofable'] = False
        result['risk_level'] = 'LOW'
        result['verdict'] = 'Domaine bien protege — SPF + DMARC + DKIM configures'
    else:
        result['spoofable'] = False
        result['risk_level'] = 'MEDIUM'
        result['verdict'] = 'Protection partielle — DKIM manquant'

    return result
