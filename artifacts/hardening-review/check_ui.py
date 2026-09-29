"""Render the production build with real demo scan JSON and mocked API transport."""
import json
from pathlib import Path
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).parent
record = json.loads((ROOT / 'demo-scan.json').read_text())


def respond(route):
    path = route.request.url.split('/api/v1')[-1].split('?')[0]
    if path == '/session':
        body = {'authenticated': True, 'user': {'id': 'ui-test', 'username': 'Demo analyst', 'role': 'user'}}
    elif path == '/uploads':
        body = [record]
    elif path == '/uploads/config':
        body = {'max_upload_bytes': 500 * 1024 * 1024}
    elif path == '/uploads/capabilities':
        body = {'capabilities': {'Python AST': 'SUPPORTED', 'Java AST': 'SUPPORTED', 'Runtime cryptography': 'OUT OF SCOPE'}}
    elif path.startswith('/uploads/'):
        body = record
    else:
        body = []
    route.fulfill(status=200, content_type='application/json', body=json.dumps(body))


with sync_playwright() as p:
    executable = Path.home() / 'AppData/Local/ms-playwright/chromium-1223/chrome-win64/chrome.exe'
    browser = p.chromium.launch(executable_path=str(executable), headless=True)
    page = browser.new_page(viewport={'width': 1440, 'height': 1000})
    errors = []
    page.on('pageerror', lambda error: errors.append(str(error)))
    page.route('**/api/v1/**', respond)
    page.goto('http://127.0.0.1:4178/scans')
    page.get_by_text('Required protection lifetime X (years)', exact=False).wait_for()
    page.get_by_label('Application / system name').fill('Payment Gateway')
    page.screenshot(path=str(ROOT / 'upload-desktop.png'), full_page=True, animations='disabled')
    page.goto('http://127.0.0.1:4178/scans/' + record['id'])
    page.get_by_role('heading', name='PQC posture').wait_for()
    page.locator('details.finding').first.locator('summary').click()
    page.get_by_role('heading', name='Why this finding?').first.wait_for()
    page.get_by_role('heading', name='Security and transition status').first.wait_for()
    page.evaluate('window.scrollTo(0, 0)')
    page.screenshot(path=str(ROOT / 'result-desktop.png'), full_page=True, animations='disabled')
    for width in [390, 768]:
        page.set_viewport_size({'width': width, 'height': 844})
        page.evaluate('window.scrollTo(0, 0)')
        page.wait_for_timeout(300)
        page.screenshot(path=str(ROOT / f'result-{width}.png'), full_page=True, animations='disabled')
        assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth'), f'Overflow at {width}px'
    assert not errors, errors
    print('PASS production-build rendering: upload fields, posture, evidence, 390/768/1440px; no page errors. API transport mocked using real demo results.')
    browser.close()
