const { chromium } = require('C:/Users/AKSHAY KUMAR/AppData/Local/npm-cache/_npx/e41f203b7505f1fb/node_modules/playwright');
const fs = require('node:fs');
(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage({baseURL: 'http://localhost:3000', viewport: {width: 1440, height: 1000}});
  const errors = []; page.on('pageerror', error => errors.push(error.message));
  try {
    await page.goto('/scans');
    if (await page.getByRole('button', {name: /Copilot/}).count()) throw Error('Chatbot still present');
    await page.getByLabel('Data lifetime X (years)').fill('20');
    await page.getByLabel('Business criticality').selectOption('critical');
    await page.getByLabel('Migration priority').selectOption('latency');
    await page.getByLabel('Choose file', {exact:true}).setInputFiles({name:'quantum-assessment.js', mimeType:'text/javascript', buffer:Buffer.from('const algorithms = ["RSA", "ECDH", "AES-256-GCM"];')});
    await page.getByRole('button', {name:'Scan file', exact:true}).click();
    await page.waitForURL('**/scans/*');
    await page.getByRole('link', {name:'CycloneDX CBOM', exact:true}).waitFor();
    const id = page.url().split('/').pop();
    const result = await (await page.request.get('/api/v1/uploads/'+id)).json();
    if(result.assessment.act_now !== 2) throw Error(JSON.stringify(result));
    await page.locator('.finding summary').first().click();
    await page.screenshot({path:'ecdat-web/artifacts/assessment-desktop.png',fullPage:true});
    for(const name of ['report','cbom','sarif']) {
      const response = await page.request.get(`/api/v1/uploads/${id}/artifacts/${name}`);
      if(!response.ok()) throw Error('Download failed: '+name);
      fs.writeFileSync(`ecdat-web/artifacts/assessment-${name}.json`, await response.body());
    }
    await page.reload();
    await page.getByRole('link', {name:'CycloneDX CBOM',exact:true}).waitFor();
    await page.setViewportSize({width:390,height:844});
    await page.goto('/scans');
    if(await page.evaluate(()=>document.documentElement.scrollWidth > innerWidth)) throw Error('Mobile overflow');
    await page.screenshot({path:'ecdat-web/artifacts/assessment-mobile.png',fullPage:true});
    if(errors.length) throw Error(errors.join('\n'));
    console.log(JSON.stringify({id, findings:result.finding_count, actNow:result.assessment.act_now, errors}));
  } finally { await browser.close(); }
})().catch(error=>{console.error(error);process.exit(1)});
