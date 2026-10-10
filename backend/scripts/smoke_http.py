"""Local HTTP integration check. Requires AI disabled; prints no tokens or source."""
import argparse
import json
import re
import time

import httpx


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--base', default='http://127.0.0.1:18000')
    args = parser.parse_args()
    if not re.fullmatch(r'http://127\.0\.0\.1:[0-9]{1,5}', args.base):
        parser.error('Use a local IPv4 loopback URL with a port.')
    with httpx.Client(base_url=args.base, timeout=20, trust_env=False, follow_redirects=False) as client:
        home = client.get('/')
        assert home.status_code == 200 and 'CodeAudit' in home.text
        asset = re.search(r'src="(/assets/[^\"]+\.js)"', home.text)
        assert asset and client.get(asset.group(1)).status_code == 200
        limits = client.get('/api/limits')
        limits.raise_for_status()
        assert not limits.json()['ai_configured'], 'This smoke test requires AI disabled.'
        response = client.post('/api/audits', json={'repository_url': 'https://github.com/KickboxerJ0322/rain-map'})
        assert response.status_code == 202
        ticket = response.json()
        path = '/api/audits/' + ticket['id']
        headers = {'Authorization': 'Bearer ' + ticket['view_token']}
        assert client.get(path).status_code == 404
        assert client.get(path, headers={'Authorization': 'Bearer invalid'}).status_code == 404
        deadline = time.monotonic() + limits.json()['timeout_seconds'] + 30
        while time.monotonic() < deadline:
            status = client.get(path, headers=headers)
            status.raise_for_status()
            if status.json()['status'] in {'completed', 'partial', 'failed'}:
                break
            time.sleep(2)
        else:
            raise RuntimeError('Audit did not finish within the deadline.')
        report = client.get(path + '/report', headers=headers)
        report.raise_for_status()
        data = report.json()
        assert data['status'] == 'partial', 'AI-disabled audit must never be marked complete.'
        for format in ('json', 'markdown'):
            assert client.get(path + '/download', params={'format': format}).status_code == 404
            download = client.get(path + '/download', params={'format': format}, headers=headers)
            assert download.status_code == 200 and 'attachment' in download.headers['Content-Disposition']
            assert ticket['view_token'] not in download.text
        print(json.dumps({'http_ui': 'ok', 'authorization': 'ok', 'downloads': 'ok', 'status': data['status'], 'sha': data['commit_sha'], 'files': data['analyzed_file_count'], 'excluded': data['excluded_file_count'], 'tools': [{k: t[k] for k in ('tool', 'status')} for t in data['tools']], 'findings': len(data['findings'])}, indent=2))


if __name__ == '__main__':
    main()
