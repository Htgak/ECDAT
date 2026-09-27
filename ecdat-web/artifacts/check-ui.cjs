const { chromium } = require('C:/Users/AKSHAY KUMAR/AppData/Local/npm-cache/_npx/e41f203b7505f1fb/node_modules/playwright');
(async()=>{
const browser=await chromium.launch({headless:true});
const page=await browser.newPage({viewport:{width:1440,height:1080}});
const errors=[];page.on('pageerror',e=>errors.push(e.message));
await page.goto('http://127.0.0.1:5173');await page.getByRole('alert').waitFor();
await page.screenshot({path:'ecdat-web/artifacts/overview-live-error.png',fullPage:true});
await page.route('**/api/v1/assets?*',route=>route.fulfill({json:{items:[{id:'test-asset',algorithm:'RSA',key_size:2048,asset_type:'ALGORITHM',stable_id:'test-rsa',confidence:'CONFIRMED',mosca_verdict:'act_now',qars_score:82,repository:'payment-gateway-service'},{id:'test-safe',algorithm:'AES',key_size:256,asset_type:'ALGORITHM',stable_id:'test-aes',confidence:'HIGH',mosca_verdict:'safe',repository:'core-crypto-vault'}],pages:1,page:1,page_size:100,total:2}}));
await page.reload();await page.getByText(/Updated .*Refreshes/).waitFor();
await page.screenshot({path:'ecdat-web/artifacts/overview-desktop-fixture.png',fullPage:true});
await page.getByRole('searchbox').count();
await page.getByRole('textbox',{name:'Search crypto inventory'}).fill('RSA');await page.getByRole('textbox',{name:'Search crypto inventory'}).press('Enter');
await page.waitForURL('**/assets?q=RSA');await page.waitForTimeout(500);
console.log('Search URL:',page.url());
for(const route of ['scans','policies','advisories','exports','audit']) {await page.goto('http://127.0.0.1:5173/'+route); await page.waitForTimeout(350);}
await page.getByRole('button',{name:'New scan',exact:true}).click();await page.getByRole('dialog').waitFor();await page.keyboard.press('Escape');if(await page.getByRole('dialog').isVisible())throw Error('Dialog did not close');
await page.setViewportSize({width:390,height:844});await page.goto('http://127.0.0.1:5173');await page.getByText(/Updated .*Refreshes/).waitFor();
await page.screenshot({path:'ecdat-web/artifacts/overview-mobile.png',fullPage:true});
await page.getByRole('button',{name:'Open navigation'}).click();await page.getByRole('link',{name:'Crypto Inventory',exact:true}).click();await page.waitForTimeout(300);
console.log('Mobile menu closes:',await page.getByRole('button',{name:'Open navigation'}).isVisible());
for(const route of ['','assets','scans','policies','advisories','exports','audit']) {await page.goto('http://127.0.0.1:5173/'+route);await page.waitForTimeout(300);console.log(route||'overview','overflow',await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth));}
console.log('Runtime errors:',JSON.stringify(errors));await browser.close();
})();
