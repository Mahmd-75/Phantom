import requests
import re

TECH_SIGNATURES = {
    # Servers
    'Nginx': {'headers': {'Server': 'nginx'}},
    'Apache': {'headers': {'Server': 'Apache'}},
    'IIS': {'headers': {'Server': 'Microsoft-IIS'}},
    'LiteSpeed': {'headers': {'Server': 'LiteSpeed'}},
    'Caddy': {'headers': {'Server': 'Caddy'}},

    # CDN / Protection
    'Cloudflare': {'headers': {'Server': 'cloudflare', 'CF-RAY': ''}},
    'Fastly': {'headers': {'X-Served-By': 'fastly'}},
    'Akamai': {'headers': {'X-Check-Cacheable': ''}},
    'AWS CloudFront': {'headers': {'X-Amz-Cf-Id': ''}},
    'Sucuri': {'headers': {'X-Sucuri-ID': ''}},

    # Languages / Frameworks
    'PHP': {'headers': {'X-Powered-By': 'PHP'}},
    'ASP.NET': {'headers': {'X-Powered-By': 'ASP.NET', 'X-AspNet-Version': ''}},
    'Ruby on Rails': {'headers': {'X-Powered-By': 'Phusion Passenger'}},

    # CMS
    'WordPress': {'body': ['wp-content', 'wp-includes', 'WordPress']},
    'Joomla': {'body': ['/components/com_', 'Joomla']},
    'Drupal': {'body': ['Drupal.settings', '/sites/default/files']},
    'Shopify': {'body': ['cdn.shopify.com', 'Shopify']},
    'Wix': {'body': ['wix.com', 'wixstatic.com']},
    'Squarespace': {'body': ['squarespace.com', 'squarespace-cdn']},

    # JS Frameworks
    'React': {'body': ['react.js', 'react.min.js', '__REACT', 'data-reactroot']},
    'Vue.js': {'body': ['vue.js', 'vue.min.js', '__vue__']},
    'Angular': {'body': ['ng-version', 'angular.js', 'angular.min.js']},
    'jQuery': {'body': ['jquery.js', 'jquery.min.js', 'jQuery v']},
    'Next.js': {'body': ['__NEXT_DATA__', '_next/static']},
    'Nuxt.js': {'body': ['__NUXT__', '_nuxt/']},

    # Analytics / Marketing
    'Google Analytics': {'body': ['google-analytics.com', 'ga(\'create\'', 'gtag(']},
    'Google Tag Manager': {'body': ['googletagmanager.com']},
    'Hotjar': {'body': ['hotjar.com', 'hj(\'trigger\'']},
    'Intercom': {'body': ['intercom.io', 'Intercom(']},

    # Security
    'reCAPTCHA': {'body': ['google.com/recaptcha', 'grecaptcha']},
    'Cloudflare Turnstile': {'body': ['challenges.cloudflare.com']},

    # Misc
    'Bootstrap': {'body': ['bootstrap.css', 'bootstrap.min.css', 'bootstrap.js']},
    'Tailwind CSS': {'body': ['tailwind.css', 'tailwindcss']},
    'Font Awesome': {'body': ['font-awesome', 'fontawesome']},
}

def detect_technologies(domain):
    result = {
        'technologies': [],
        'headers_raw': {},
        'error': None
    }

    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }

        response = requests.get(f"https://{domain}", headers=headers, timeout=10, allow_redirects=True)
        body = response.text.lower()
        resp_headers = {k.lower(): v.lower() for k, v in response.headers.items()}
        result['headers_raw'] = dict(response.headers)
        result['status_code'] = response.status_code
        result['final_url'] = response.url

        for tech, signatures in TECH_SIGNATURES.items():
            detected = False

            # Check headers
            if 'headers' in signatures:
                for header_key, header_val in signatures['headers'].items():
                    hk = header_key.lower()
                    if hk in resp_headers:
                        if header_val == '' or header_val.lower() in resp_headers[hk]:
                            detected = True
                            break

            # Check body
            if not detected and 'body' in signatures:
                for pattern in signatures['body']:
                    if pattern.lower() in body:
                        detected = True
                        break

            if detected:
                result['technologies'].append(tech)

    except requests.exceptions.SSLError:
        # Retry with HTTP
        try:
            response = requests.get(f"http://{domain}", headers=headers, timeout=10)
            body = response.text.lower()
            resp_headers = {k.lower(): v.lower() for k, v in response.headers.items()}

            for tech, signatures in TECH_SIGNATURES.items():
                detected = False
                if 'headers' in signatures:
                    for header_key, header_val in signatures['headers'].items():
                        hk = header_key.lower()
                        if hk in resp_headers:
                            if header_val == '' or header_val.lower() in resp_headers[hk]:
                                detected = True
                                break
                if not detected and 'body' in signatures:
                    for pattern in signatures['body']:
                        if pattern.lower() in body:
                            detected = True
                            break
                if detected:
                    result['technologies'].append(tech)
        except Exception as e:
            result['error'] = str(e)

    except Exception as e:
        result['error'] = str(e)

    return result
