const { chromium } = require('C:/Users/AKSHAY KUMAR/AppData/Local/npm-cache/_npx/e41f203b7505f1fb/node_modules/playwright');
(async()=>{
 const browser=await chromium.launch({headless:true});const page=await browser.newPage();const errors=[];page.on('pageerror',e=>errors.push(e.message));
 const assets=await (await page.request.get('http://localhost:3000/api/v1/workspace/assets')).json();
 const scans=await (await page.request.get('http://localhost:3000/api/v1/uploads')).json();
 const routes=['/','/scans','/assets','/policies','/advisories','/exports','/audit'];
 if(assets.items?.length) routes.push('/assets/'+assets.items[0].id);
 if(scans.length) routes.push('/scans/'+scans[0].id);
 const results=[];
 for(const width of [390,768,1440,1920]){
  await page.setViewportSize({width,height:1000});
  for(const route of routes){const response=await page.goto('http://localhost:3000'+route);await page.waitForTimeout(350);const overflow=await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth+1);results.push({width,route,status:response.status(),overflow});}
  await page.goto('http://localhost:3000/advisories');await page.waitForTimeout(400);await page.screenshot({path:'artifacts/audit-suggestions-'+width+'.png',fullPage:true});
 }
 console.log(JSON.stringify({assets:assets.total,scans:scans.length,errors,results},null,2));await browser.close();
 if(errors.length||results.some(r=>r.status!==200||r.overflow))process.exitCode=1;
})();
