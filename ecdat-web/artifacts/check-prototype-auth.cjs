const {chromium}=require('C:/Users/AKSHAY KUMAR/AppData/Local/npm-cache/_npx/e41f203b7505f1fb/node_modules/playwright');
const {spawn}=require('node:child_process');const fs=require('node:fs');const os=require('node:os');const path=require('node:path');const http=require('node:http');
(async()=>{
const temp=fs.mkdtempSync(path.join(os.tmpdir(),'ecdat-auth-browser-'));
const child=spawn('../ecdat-backend/.venv/Scripts/python.exe',['-c',"from ecdat.apps.api.auth.store import create_user; create_user('browseradmin','browser test only passphrase'); import uvicorn; uvicorn.run('ecdat.apps.api.main:app',host='127.0.0.1',port=18000,log_level='error')"],{cwd:path.resolve('../ecdat-backend'),env:{...process.env,EVIDENCE_STORE_PATH:temp,ENVIRONMENT:'development',AUTH_USERNAME:'browseradmin',AUTH_PASSWORD:'browser test only passphrase',AUTH_USERS:'',CORS_ORIGINS:'["http://127.0.0.1:18173"]'},stdio:'ignore'});
const server=http.createServer((req,res)=>{
 if(req.url.startsWith('/api/')){const upstream=http.request({host:'127.0.0.1',port:18000,path:req.url,method:req.method,headers:{...req.headers,host:'127.0.0.1'}},r=>{res.writeHead(r.statusCode,r.headers);r.pipe(res)});upstream.on('error',()=>{res.statusCode=502;res.end()});req.pipe(upstream);return;}
 let target=path.join(path.resolve('dist'),req.url.split('?')[0]);if(!fs.existsSync(target)||fs.statSync(target).isDirectory())target=path.resolve('dist/index.html');res.setHeader('Content-Type',target.endsWith('.js')?'text/javascript':target.endsWith('.css')?'text/css':target.endsWith('.png')?'image/png':'text/html');fs.createReadStream(target).pipe(res);
});
let browser;
try{
 await new Promise(resolve=>server.listen(18173,'127.0.0.1',resolve));
 for(let i=0;i<60;i++){try{if((await fetch('http://127.0.0.1:18000/health')).ok)break}catch{} await new Promise(r=>setTimeout(r,250));}
 browser=await chromium.launch({headless:true});const page=await browser.newPage();const errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.goto('http://127.0.0.1:18173');await page.getByRole('heading',{name:'Sign in to ECDAT'}).waitFor();
 await page.route('**/api/v1/session',route=>route.request().method()==='POST'?route.fulfill({status:502,contentType:'text/html',body:'<html>Bad gateway</html>'}):route.continue());
 await page.getByLabel('Username',{exact:true}).fill('browseradmin');await page.getByLabel('Password',{exact:true}).fill('test');await page.getByRole('button',{name:'Sign in',exact:true}).click();await page.getByRole('alert').filter({hasText:'The API is unavailable'}).waitFor();await page.unroute('**/api/v1/session');
 await page.getByLabel('Username',{exact:true}).fill('browseradmin');await page.getByLabel('Password',{exact:true}).fill('wrong');await page.getByRole('button',{name:'Sign in',exact:true}).click();await page.getByRole('alert').filter({hasText:'Invalid username or password'}).waitFor();
 await page.getByLabel('Password',{exact:true}).fill('browser test only passphrase');await page.getByRole('button',{name:'Sign in',exact:true}).click();await page.getByRole('button',{name:'Sign out (browseradmin)'}).waitFor();await page.reload();await page.getByRole('button',{name:'Sign out (browseradmin)'}).waitFor();
 await page.goto('http://127.0.0.1:18173/users');await page.waitForURL('**/admin/users');
 await page.getByRole('heading',{name:'Users',exact:true}).waitFor();
 if(await page.getByRole('button',{name:'New scan',exact:true}).count())throw Error('Admin still has scan controls');if(await page.getByRole('link',{name:'Discovery scans',exact:true}).count())throw Error('Admin still has scan navigation');await page.getByRole('button',{name:/Switch to .* theme/}).waitFor();
 await page.getByLabel('Username',{exact:true}).fill('browsernormal');
 await page.getByLabel(/^Password /).fill('normal browser test passphrase');
 await page.getByRole('button',{name:'Create user',exact:true}).click();
 await page.getByText('User created. Share the credentials privately with that user.',{exact:true}).waitFor();
 await page.screenshot({path:'artifacts/admin-users-desktop.png',fullPage:true});
 const uploaded=await page.request.post('http://127.0.0.1:18173/api/v1/uploads',{multipart:{kind:'source',file:{name:'browser-fixture.js',mimeType:'text/javascript',buffer:Buffer.from('RSA MD5')}}});if(uploaded.status()!==202)throw Error(await uploaded.text());const id=(await uploaded.json()).id;
 for(let i=0;i<50;i++){const report=await (await page.request.get('http://127.0.0.1:18173/api/v1/uploads/'+id)).json();if(report.status==='completed')break;await page.waitForTimeout(100);}
 const assets=await(await page.request.get('http://127.0.0.1:18173/api/v1/workspace/assets')).json();if(!assets.items?.length)throw Error('Scan produced no assets');
 for(const format of ['cyclonedx','sarif','csv']){const r=await page.request.get('http://127.0.0.1:18173/api/v1/workspace/export/'+format);if(!r.ok()||!(await r.body()).length)throw Error('Export failed '+format);}
 for(const theme of ['light','dark']){await page.evaluate(theme=>{document.documentElement.dataset.theme=theme;localStorage.setItem('ecdat-theme',theme)},theme);
 for(const width of [390,1440]){await page.setViewportSize({width,height:900});for(const route of ['/','/scans/'+id,'/assets','/policies','/advisories','/exports','/admin/users','/admin','/users','/dashboard','/audit','/scan/'+id,'/assets/'+assets.items[0].id,'/scans']){await page.goto('http://127.0.0.1:18173'+route);await page.getByRole('button',{name:'Sign out (browseradmin)'}).waitFor();if(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth+1))throw Error('Overflow '+route);}}
 await page.screenshot({path:`artifacts/workspace-${theme}.png`,fullPage:true});}
 await page.getByRole('button',{name:'Switch to light theme'}).click();await page.reload();if(await page.evaluate(()=>document.documentElement.dataset.theme)!=='light')throw Error('Theme did not persist');
 await page.getByRole('button',{name:'Sign out (browseradmin)'}).click();await page.getByRole('heading',{name:'Sign in to ECDAT'}).waitFor();if((await page.request.get('http://127.0.0.1:18173/api/v1/uploads')).status()!==401)throw Error('Logout did not revoke');await page.screenshot({path:'artifacts/prototype-auth-login.png'});
 await page.getByLabel('Username',{exact:true}).fill('browsernormal');await page.getByLabel('Password',{exact:true}).fill('normal browser test passphrase');await page.getByRole('button',{name:'Sign in',exact:true}).click();await page.getByRole('button',{name:'Sign out (browsernormal)'}).waitFor();
 await page.goto('http://127.0.0.1:18173/users');await page.waitForURL('**/admin/users');await page.getByRole('heading',{name:'Administrator access required'}).waitFor();
 const denied=await page.request.get('http://127.0.0.1:18173/api/v1/admin/users');if(denied.status()!==403)throw Error('Normal user received admin access');
 const own=await(await page.request.get('http://127.0.0.1:18173/api/v1/uploads')).json();if(own.length)throw Error('Normal user saw admin scans');
if(errors.length)throw Error(errors.join('\n'));console.log('PASS: wrong password, login, refresh, isolated scan, 56 route/width/theme checks, HTML gateway failure, exports and theme persistence, admin creates user, normal user denied admin and other scans, logout and API denial.');
}finally{if(browser)await browser.close();server.close();child.kill();}
})();
