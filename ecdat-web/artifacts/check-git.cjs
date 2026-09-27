const { chromium } = require('C:/Users/AKSHAY KUMAR/AppData/Local/npm-cache/_npx/e41f203b7505f1fb/node_modules/playwright');
const fs = require('node:fs');
const crypto = require('node:crypto');
(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage({baseURL: 'http://localhost:3000', viewport: {width: 1440, height: 1000}});
  const errors = []; page.on('pageerror', error => errors.push(error.message));
  try {
    await page.goto('/scans');
    await page.getByRole('radio', {name: /Git repository/}).check({force: true});
    await page.getByLabel('Repository URL').fill('https://github.com/pallets/itsdangerous.git');
    await page.screenshot({path: 'ecdat-web/artifacts/git-form.png', fullPage: true});
    await page.getByRole('button', {name: 'Scan repository', exact: true}).click();
    await page.waitForURL('**/scans/*');
    const id = page.url().split('/').pop();
    fs.writeFileSync('ecdat-web/artifacts/git-verification-id.txt', id);
    await page.getByRole('link', {name: 'Report (JSON)', exact: true}).waitFor({timeout: 240000});
    const result = await (await page.request.get('/api/v1/uploads/' + id)).json();
    if (result.status !== 'completed' || !/^[a-f0-9]{40}$/.test(result.commit) || !result.finding_count) throw Error(JSON.stringify(result));
    const snapshot = await (await page.request.get(`/api/v1/uploads/${id}/artifacts/original`)).body();
    if (crypto.createHash('sha256').update(snapshot).digest('hex') !== result.sha256) throw Error('Snapshot checksum mismatch');
    await page.screenshot({path: 'ecdat-web/artifacts/git-result.png', fullPage: true});
    await page.reload();
    await page.getByRole('link', {name: 'Source snapshot', exact: true}).waitFor();
    await page.setViewportSize({width: 390, height: 844});
    await page.goto('/scans');
    await page.getByRole('radio', {name: /Git repository/}).check({force: true});
    if (await page.evaluate(() => document.documentElement.scrollWidth > innerWidth)) throw Error('Mobile overflow');
    await page.screenshot({path: 'ecdat-web/artifacts/git-mobile.png', fullPage: true});
    if (errors.length) throw Error(errors.join('\n'));
    console.log(JSON.stringify({id, status: result.status, findings: result.finding_count, commit: result.commit, snapshotChecksum: 'passed', mobile: 'passed', runtimeErrors: errors}));
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exit(1); });
