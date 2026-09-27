const {chromium}=require('C:/Users/AKSHAY KUMAR/AppData/Local/npm-cache/_npx/e41f203b7505f1fb/node_modules/playwright');
const fs=require('node:fs');const crypto=require('node:crypto');
(async()=>{
 const browser=await chromium.launch({headless:true});
 const page=await browser.newPage({baseURL:'http://localhost:3000',viewport:{width:1365,height:1024}});
 const errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.goto('http://localhost:3000');
 await page.getByRole('heading',{name:"Check your file's cryptography."}).waitFor();
 await page.screenshot({path:'ecdat-web/artifacts/upload-desktop.png',fullPage:true});
 const records=[];
 for(const [label,path] of [
  ['Source code','ecdat-web/artifacts/upload-fixtures/verification-source.py'],
  ['Android app','ecdat-web/artifacts/upload-fixtures/verification-android.apk'],
  ['Windows app','ecdat-backend/.venv/Scripts/python.exe']
 ]){
  await page.goto('http://localhost:3000');
  await page.getByRole('radio',{name:new RegExp(label)}).check({force:true});
  await page.getByLabel('Choose file',{exact:true}).setInputFiles(path);
  await page.getByRole('button',{name:'Scan file',exact:true}).click();
  await page.waitForURL('**/scan/*');
  await page.getByRole('link',{name:'Report (JSON)',exact:true}).waitFor({timeout:60000});
  const id=page.url().split('/').pop();
  const result=await(await page.request.get('/api/v1/uploads/'+id)).json();
  if(result.status!=='completed')throw Error(JSON.stringify(result));
  const original=await page.request.get('/api/v1/uploads/'+id+'/artifacts/original');
  const received=crypto.createHash('sha256').update(await original.body()).digest('hex');
  const expected=crypto.createHash('sha256').update(fs.readFileSync(path)).digest('hex');
  if(received!==expected)throw Error('Original artifact mismatch');
  const report=await(await page.request.get('/api/v1/uploads/'+id+'/artifacts/report')).json();
  if(report.sha256!==expected)throw Error('Report checksum mismatch');
  await page.reload();await page.getByRole('link',{name:'Report (JSON)',exact:true}).waitFor();
  records.push({id,kind:result.kind,count:result.finding_count});
  console.log(label,'completed',result.finding_count,'findings; saved artifacts verified');
 }
 await page.goto('http://localhost:3000/scan/'+records[0].id);
 await page.getByRole('link',{name:'Report (JSON)',exact:true}).waitFor();
 await page.locator('.finding summary').first().click();
 await page.screenshot({path:'ecdat-web/artifacts/upload-results-desktop.png',fullPage:true});
 await page.setViewportSize({width:390,height:844});
 await page.screenshot({path:'ecdat-web/artifacts/upload-results-mobile.png',fullPage:true});
 if(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth))throw Error('Mobile result overflow');
 await page.goto('http://localhost:3000');await page.screenshot({path:'ecdat-web/artifacts/upload-mobile.png',fullPage:true});
 if(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth))throw Error('Mobile upload overflow');
 await page.getByLabel('Choose file',{exact:true}).setInputFiles({name:'wrong.txt',mimeType:'text/plain',buffer:Buffer.from('test')});
 await page.getByRole('alert').waitFor();
 if(await page.getByRole('button',{name:'Scan file',exact:true}).isEnabled())throw Error('Invalid file was accepted');
 console.log('Mobile layouts and invalid-file feedback passed. Runtime errors:',errors);
 fs.writeFileSync('ecdat-web/artifacts/upload-verification.json',JSON.stringify(records,null,2));
 await browser.close();if(errors.length)process.exitCode=1;
})().catch(e=>{console.error(e);process.exit(1)});
