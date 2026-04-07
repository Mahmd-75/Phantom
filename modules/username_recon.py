import requests

# Liste des plateformes à checker
PLATFORMS = {
    'GitHub': 'https://github.com/{}',
    'Twitter': 'https://twitter.com/{}',
    'Instagram': 'https://www.instagram.com/{}',
    'Reddit': 'https://www.reddit.com/user/{}',
    'TikTok': 'https://www.tiktok.com/@{}',
    'Pinterest': 'https://www.pinterest.com/{}',
    'Twitch': 'https://www.twitch.tv/{}',
    'YouTube': 'https://www.youtube.com/@{}',
    'LinkedIn': 'https://www.linkedin.com/in/{}',
    'Snapchat': 'https://www.snapchat.com/add/{}',
    'Telegram': 'https://t.me/{}',
    'Medium': 'https://medium.com/@{}',
    'Dev.to': 'https://dev.to/{}',
    'HackTheBox': 'https://app.hackthebox.com/profile/{}',
    'TryHackMe': 'https://tryhackme.com/p/{}',
    'Steam': 'https://steamcommunity.com/id/{}',
    'Pastebin': 'https://pastebin.com/u/{}',
    'Keybase': 'https://keybase.io/{}',
    'Gitlab': 'https://gitlab.com/{}',
    'Dockerhub': 'https://hub.docker.com/u/{}'
}

def scan_username(username):
    result = {
        'found': [],
        'not_found': []
    }

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    }

    for platform, url_template in PLATFORMS.items():
        url = url_template.format(username)
        try:
            response = requests.get(url, headers=headers, timeout=5)
            if response.status_code == 200:
                result['found'].append({
                    'platform': platform,
                    'url': url
                })
            else:
                result['not_found'].append(platform)
        except Exception:
            result['not_found'].append(platform)

    result['summary'] = {
        'total_checked': len(PLATFORMS),
        'found_count': len(result['found']),
        'not_found_count': len(result['not_found'])
    }

    return result
