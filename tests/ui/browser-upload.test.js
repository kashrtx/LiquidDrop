// Optional real-browser regression suite. Install Playwright outside the checkout
// and set LD_PLAYWRIGHT to its module path. Uses system Chromium by default.
// LD_PLAYWRIGHT=/path/to/playwright node tests/ui/browser-upload.test.js target/release/liquiddrop
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const { spawn } = require('node:child_process');
const { randomBytes, createHash } = require('node:crypto');
const { chromium } = require(process.env.LD_PLAYWRIGHT || 'playwright');
const benchmarkMiB = Number(process.env.LD_BENCHMARK_MIB || 128);
assert.ok(Number.isInteger(benchmarkMiB) && benchmarkMiB > 0 && benchmarkMiB <= 1024);
const hash = b => createHash('sha256').update(b).digest('hex');
(async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'ld-browser-'));
  const socket = net.createServer();
  await new Promise(r => socket.listen(0, '127.0.0.1', r));
  const port = socket.address().port;
  await new Promise(r => socket.close(r));
  const child = spawn(path.resolve(process.argv[2] || 'target/release/liquiddrop'),
    ['--no-browser','--no-tray','--bind','127.0.0.1','--port',String(port),'--dir',dir], {stdio:'ignore'});
  let browser;
  try {
    const deadline = Date.now() + 20000;
    let token;
    while (Date.now() < deadline) {
      try {
        token = (await fs.readFile(path.join(dir,'.token'),'utf8')).trim();
        if ((await fetch(`http://127.0.0.1:${port}/${token}/status`)).ok) break;
      } catch (_) {}
      await new Promise(r => setTimeout(r, 50));
    }
    assert.ok(token, 'server started');
    browser = await chromium.launch({executablePath:process.env.LD_CHROMIUM || '/usr/bin/chromium',headless:true});
    const page = await browser.newPage();
    const errors = [];
    page.on('pageerror', e => errors.push(e.message));
    await page.addInitScript(() => { window.LD_UPLOAD_TIMING = {requestMs:700,stallMs:1500,pollMs:100,slowMs:400,bundleMs:700,packageMs:700}; });
    for (const mode of (process.env.LD_BENCHMARK ? ['throughput'] : ['normal-mp4','mixed','lost-start','lost-put-reply','lost-complete','native-stall','storage-full'])) {
      await page.goto(`http://127.0.0.1:${port}/${token}/`);
      let injected = false, puts = 0;
      if (mode === 'throughput') await page.evaluate(() => Object.assign(UT,{pollMs:60000,stallMs:120000}));
      await page.route('**/uploads**', async route => {
        const req = route.request(), url = new URL(req.url());
        if (req.method() === 'PUT') puts++;
        if (mode === 'throughput' && req.method() === 'PUT') {
          // Delay dispatch without replaying the body through Playwright.
          // Replaying large bodies adds serialization overhead and can fail
          // independently of the application's native upload path.
          await new Promise(r => setTimeout(r,150));
          await route.continue();
          return;
        }
        if (mode === 'storage-full' && req.method() === 'PUT') {
          await route.fulfill({status:507,contentType:'application/json',body:JSON.stringify({error:'Disk full'})});
          return;
        }
        if (mode === 'native-stall' && req.method() === 'PUT' && !injected) {
          injected = true;
          return; // native File request never reaches the computer; must switch to buffers
        }
        const target = mode === 'lost-start' ? req.method()==='POST' && url.pathname.endsWith('/uploads')
          : mode === 'lost-put-reply' ? req.method()==='PUT'
          : mode === 'lost-complete' ? url.pathname.endsWith('/complete') : false;
        if (target && !injected) {
          injected = true;
          await route.fetch(); // server receives and commits; browser never sees reply
          if (mode === 'lost-complete') {
            assert.notEqual(await page.locator('#uploadPct').textContent(), '100%');
          }
          return; // client must recover without tapping the progress bar
        }
        await route.continue();
      });
      const suffixes = mode === 'mixed' ? ['txt','pdf','doc','ipa','mp4','mp4'] : ['mp4'];
      const files = suffixes.map((ext,i) => ({name:`${mode}-${i}.${ext}`,mimeType:ext==='mp4'?'video/mp4':'application/octet-stream',buffer:randomBytes(mode==='throughput'?benchmarkMiB*1024*1024:ext==='mp4'?17*1024*1024+173:10043)}));
      let input = files;
      if (mode === 'throughput') {
        await fs.mkdir(path.join(dir,'.benchmark'),{recursive:true});
        const inputPath = path.join(dir,'.benchmark','throughput-0.mp4');
        await fs.writeFile(inputPath,files[0].buffer);
        input = inputPath;
      }
      const started = Date.now();
      await page.locator('#fileInput').setInputFiles(input);
      if (files.length >= 3) await page.locator('#btnSeparate').click();
      await page.waitForFunction(() => uploadState.batches === 0, null, {timeout:30000});
      if (mode === 'storage-full') {
        assert.equal(await page.locator('#uploadPct').textContent(), '1 failed');
        await assert.rejects(fs.stat(path.join(dir,files[0].name)), {code:'ENOENT'});
        await page.unroute('**/uploads**');
        console.log('PASS real browser: disk full reports failure, without false 100% success');
        continue;
      }
      assert.equal(await page.locator('#uploadPct').textContent(), '100%');
      for (const f of files) assert.equal(hash(await fs.readFile(path.join(dir,f.name))), hash(f.buffer));
      if (mode.startsWith('lost-') || mode === 'native-stall') assert.ok(injected);
      await page.unroute('**/uploads**');
      console.log('PASS real browser: '+mode+'; all file hashes match; '+puts+' PUTs; '+((Date.now()-started)/1000).toFixed(2)+'s');
      if (mode === 'normal-mp4' || mode === 'throughput' && !process.env.LD_ALLOW_CHUNKED) assert.equal(puts,1,'healthy video should stream in a single request');
      if (mode === 'native-stall') assert.equal(puts,4,'failed native request should switch to three bounded buffers');
    }

    if (!process.env.LD_BENCHMARK) {
      function unzipStored(data) {
        const end=data.lastIndexOf(Buffer.from([0x50,0x4b,0x05,0x06]));
        assert.ok(end>=0);
        let at=data.readUInt32LE(end+16);
        const result=new Map();
        for(let i=0;i<data.readUInt16LE(end+10);i++){
          assert.equal(data.readUInt32LE(at),0x02014b50);
          const size=data.readUInt32LE(at+24), n=data.readUInt16LE(at+28);
          const name=data.subarray(at+46,at+46+n).toString();
          const local=data.readUInt32LE(at+42);
          const start=local+30+data.readUInt16LE(local+26)+data.readUInt16LE(local+28);
          result.set(name,data.subarray(start,start+size));
          at+=46+n+data.readUInt16LE(at+30)+data.readUInt16LE(at+32);
        }
        return result;
      }
      await page.goto(`http://127.0.0.1:${port}/${token}/`);
      const project=path.join(dir,'.input','Project');
      await fs.mkdir(path.join(project,'nested'),{recursive:true});
      const expected=new Map();
      // More than a directory-reader page; also verify duplicate leaf names.
      for(let i=0;i<130;i++){
        const name=`file-${i}.txt`,data=Buffer.from(`content ${i}`);
        await fs.writeFile(path.join(project,name),data);
        expected.set('Project/'+name,data);
      }
      await fs.writeFile(path.join(project,'nested','file-0.txt'),'different content');
      expected.set('Project/nested/file-0.txt',Buffer.from('different content'));
      let lost=false;
      await page.route('**/bundle',async route=>{
        if(!lost){lost=true;await route.fetch();return;}
        await route.continue();
      });
      const before=(await fs.readdir(dir)).filter(n=>n.endsWith('.zip'));
      await page.locator('#folderInput').setInputFiles(project);
      await page.waitForFunction(()=>uploadState.batches===0,null,{timeout:60000});
      assert.equal(await page.locator('#uploadPct').textContent(),'100%');
      const contents=unzipStored(await fs.readFile(path.join(dir,'Project.zip')));
      assert.equal(contents.size,expected.size);
      for(const [name,data] of expected) assert.equal(hash(contents.get(name)),hash(data));
      const after=(await fs.readdir(dir)).filter(n=>n.endsWith('.zip'));
      assert.equal(after.length,before.length+1,'lost bundle reply must create exactly one archive');
      assert.ok(!(await fs.readdir(dir)).some(n=>n.startsWith('file-')),'no loose folder files');
      assert.ok(!(await fs.readdir(path.join(dir,'.partial'))).some(n=>n.startsWith('staged-')));
      await page.unroute('**/bundle');
      console.log('PASS real browser: folder picker, 131 files, nested duplicate names, lost bundle reply, no loose files');

      // A native Apple RTFD directory becomes a valid package with readable text.
      const rtfd=path.join(dir,'.input','Memo.rtfd');
      await fs.mkdir(rtfd,{recursive:true});
      await fs.writeFile(path.join(rtfd,'TXT.rtf'),String.raw`{\rtf1\ansi Hello from Notes\par Second line}`);
      const attachment=randomBytes(333);
      await fs.writeFile(path.join(rtfd,'image.png'),attachment);
      await page.locator('#folderInput').setInputFiles(rtfd);
      await page.waitForFunction(()=>uploadState.batches===0,null,{timeout:30000});
      const packageBytes=await fs.readFile(path.join(dir,'Memo.rtfd.zip'));
      const packageFiles=unzipStored(packageBytes);
      assert.equal(hash(packageFiles.get('Memo.rtfd/image.png')),hash(attachment));
      const preview=await page.request.get(`http://127.0.0.1:${port}/${token}/document-preview/Memo.rtfd.zip`);
      assert.equal(preview.status(),200);
      assert.equal((await preview.json()).text,'Hello from Notes\nSecond line');
      assert.equal(await page.evaluate(()=>getFileKind('Memo.rtfd.zip')),'document');
      console.log('PASS real browser: real RTFD package upload, text preview, attachments preserved');

      // Browser-generated multipart has real bytes even when JS File.size says 0.
      // Chromium models that metadata mismatch; WebKit also packages directories
      // during FormData serialization. Do not replace or slice the original File.
      let packageRequests=0, packagePosts=0;
      await page.route('**/package',async route=>{
        packageRequests++;
        if(route.request().method()==='POST') packagePosts++;
        if(packageRequests===1){await route.fetch();return;}
        await route.continue();
      });
      const nativeNames=await page.evaluate(async token=>{
        const bytes=await (await fetch('/'+token+'/download/Memo.rtfd.zip')).arrayBuffer();
        const file=new File([bytes],'Native.rtfd.zip',{type:'application/zip'});
        Object.defineProperty(file,'size',{value:0});
        return uploadFiles([file]);
      },token);
      assert.deepEqual(nativeNames,['Native.rtfd.zip']);
      assert.ok(packageRequests>=2,'lost multipart reply must be reconciled');
      assert.equal(packagePosts,1,'a saved file must not be reread after a lost reply');
      assert.equal(hash(await fs.readFile(path.join(dir,'Native.rtfd.zip'))),hash(packageBytes));
      assert.ok(!(await fs.readdir(dir)).some(n=>n.startsWith('Native (')),'no duplicate package after lost reply');
      await page.unroute('**/package');
      console.log('PASS real browser: zero reported size, real multipart bytes, lost reply, original package preserved');

      const packedNames=await page.evaluate(async token=>{
        const bytes=await (await fetch('/'+token+'/download/Memo.rtfd.zip')).arrayBuffer();
        const file=new File([bytes],'Nested.rtfd.zip',{type:'application/zip'});
        Object.defineProperty(file,'size',{value:0});
        return uploadFiles([file],{bundle:true,name:'Apple-batch.zip'});
      },token);
      assert.deepEqual(packedNames,['Apple-batch.zip']);
      const appleBatch=unzipStored(await fs.readFile(path.join(dir,'Apple-batch.zip')));
      assert.equal(hash(appleBatch.get('Nested.rtfd.zip')),hash(packageBytes));
      console.log('PASS real browser: Zip & Send uses actual received package size, with private staging');

      const selectedPath=path.join(dir,'.input','Selected.rtfd.zip');
      await fs.writeFile(selectedPath,packageBytes);
      await page.evaluate(()=>document.querySelector('#fileInput').addEventListener('change',event=>{
        window.__sourcePicker=event.target;
        Object.defineProperty(event.target.files[0],'size',{value:0});
      },{capture:true,once:true}));
      let selectionRetained=false;
      await page.route('**/package',async route=>{
        if(route.request().method()==='POST'){
          selectionRetained=await page.evaluate(()=>window.__sourcePicker.isConnected&&window.__sourcePicker.files.length===1);
          assert.ok(selectionRetained,'retain the original picker until serialization and sending finish');
        }
        await route.continue();
      });
      await page.locator('#fileInput').setInputFiles(selectedPath);
      await page.waitForFunction(()=>uploadState.batches===0,null,{timeout:30000});
      await page.waitForFunction(()=>document.querySelector('#fileInput').files.length===0);
      assert.ok(selectionRetained);
      assert.equal(hash(await fs.readFile(path.join(dir,'Selected.rtfd.zip'))),hash(packageBytes));
      await page.unroute('**/package');
      console.log('PASS real browser: real picker selection survives until the file is saved');



      // A package exported by the picker with no bytes must not become a success.
      await page.locator('#fileInput').setInputFiles([{name:'Broken.rtfd.zip',mimeType:'application/zip',buffer:Buffer.alloc(0)}]);
      await page.waitForFunction(()=>uploadState.batches===0);
      assert.equal(await page.locator('#uploadPct').textContent(),'1 failed');
      await assert.rejects(fs.stat(path.join(dir,'Broken.rtfd.zip')),{code:'ENOENT'});
      console.log('PASS real browser: empty RTFD export rejected, without changing valid empty text files');

      // Zip & Send must handle identically named selected files without losing either.
      const duplicated=[{name:'same.txt',mimeType:'text/plain',buffer:Buffer.from('first')},
        {name:'same.txt',mimeType:'text/plain',buffer:Buffer.from('second')},
        {name:'other.txt',mimeType:'text/plain',buffer:Buffer.from('third')}];
      const zipsBefore=new Set((await fs.readdir(dir)).filter(n=>n.endsWith('.zip')));
      await page.locator('#fileInput').setInputFiles(duplicated);
      assert.equal(await page.locator('#fileInput').evaluate(input=>input.files.length),3,'keep selection while ZIP choice is pending');
      await page.locator('#btnZip').click();
      await page.waitForFunction(()=>uploadState.batches===0,null,{timeout:30000});
      const created=(await fs.readdir(dir)).filter(n=>n.endsWith('.zip')&&!zipsBefore.has(n));
      assert.equal(created.length,1);
      const zipped=unzipStored(await fs.readFile(path.join(dir,created[0])));
      assert.equal(zipped.get('same.txt').toString(),'first');
      assert.equal(zipped.get('same (1).txt').toString(),'second');
      assert.equal(zipped.get('other.txt').toString(),'third');
      console.log('PASS real browser: Zip & Send preserves duplicate filenames without loose output');

      const visibleBefore=new Set((await fs.readdir(dir)).filter(n=>!n.startsWith('.')));
      let rejected=false;
      await page.route('**/uploads/**',async route=>{
        if(route.request().method()==='PUT'&&!rejected){rejected=true;await route.fulfill({status:507,contentType:'application/json',body:'{"error":"Disk full"}'});return;}
        await route.continue();
      });
      await page.locator('#fileInput').setInputFiles(['a','b','c'].map(n=>({name:`partial-${n}.txt`,mimeType:'text/plain',buffer:Buffer.from(n)})));
      await page.locator('#btnZip').click();
      await page.waitForFunction(()=>uploadState.batches===0,null,{timeout:30000});
      assert.equal(await page.locator('#uploadPct').textContent(),'1 failed');
      assert.deepEqual(new Set((await fs.readdir(dir)).filter(n=>!n.startsWith('.'))),visibleBefore,'failed batch must not publish a partial ZIP or loose files');
      await page.unroute('**/uploads/**');
      console.log('PASS real browser: a failed ZIP batch publishes neither a partial archive nor loose files');

      await page.evaluate(()=>{
        const children=Array.from({length:130},(_,i)=>({name:`entry-${i}.txt`,isDirectory:false,file:resolve=>resolve(new File([`data ${i}`],`entry-${i}.txt`))}));
        children.push({name:'empty',isDirectory:true,createReader:()=>({readEntries:resolve=>resolve([])})});
        const root={name:'Dropped',isDirectory:true,createReader:()=>{
          let offset=0;
          return {readEntries:resolve=>{const page=children.slice(offset,offset+100);offset+=100;resolve(page);}};
        }};
        const event=new Event('drop',{bubbles:true,cancelable:true});
        Object.defineProperty(event,'dataTransfer',{value:{files:[],items:[{webkitGetAsEntry:()=>root}]}});
        document.querySelector('#dropzone').dispatchEvent(event);
      });
      await page.waitForFunction(()=>Array.from(document.querySelectorAll('.file-name')).some(e=>e.textContent==='Dropped.zip'),null,{timeout:60000});
      const dropped=unzipStored(await fs.readFile(path.join(dir,'Dropped.zip')));
      assert.equal(dropped.size,132); // root directory, 130 files, and an empty subfolder
      assert.ok(dropped.has('Dropped/empty/'));
      assert.equal(dropped.get('Dropped/entry-129.txt').toString(),'data 129');
      console.log('PASS real browser: directory drag and drop reads every browser page and preserves empty folders');

    }

    if(!process.env.LD_BENCHMARK){
      const clip=await browser.newPage();
      clip.on('pageerror',e=>errors.push(e.message));
      await clip.context().grantPermissions(['clipboard-read','clipboard-write']);
      await clip.goto(`http://127.0.0.1:${port}/${token}/`);
      const text='Hello from my phone 👋\n中文 café\n\t<script>literal text</script>\n';
      await clip.evaluate(t=>navigator.clipboard.writeText(t),text);
      await clip.locator('#pasteText').click();
      await clip.waitForFunction(t=>document.querySelector('#textContent').value===t,text);
      assert.ok(!(await fs.readdir(dir)).some(n=>n.startsWith('Clipboard-')),'opening clipboard editor must not share text');
      await clip.locator('#textFilename').fill('Pasted note');
      await clip.locator('#textSubmit').click();
      await clip.waitForFunction(()=>!document.querySelector('#textDialog').open);
      assert.equal(await fs.readFile(path.join(dir,'Pasted note.txt'),'utf8'),text);
      const card=clip.locator('.file-card').filter({hasText:'Pasted note.txt'});
      await card.locator('.file-copy').click();
      await clip.waitForFunction(()=>!document.querySelector('#textSubmit').disabled);
      await clip.evaluate(()=>navigator.clipboard.writeText('replace me'));
      await clip.locator('#textSubmit').click();
      assert.equal(await clip.evaluate(()=>navigator.clipboard.readText()),text);
      await clip.locator('#textCancel').click();
      console.log('PASS real browser: explicit clipboard read, UTF-8 .txt transfer, received-text copy');

      // LAN HTTP does not generally grant clipboard reads. Manual paste must
      // remain usable without a permission prompt or an automatic read.
      await clip.evaluate(()=>Object.defineProperty(window,'isSecureContext',{configurable:true,value:false}));
      await clip.locator('#pasteText').click();
      assert.equal(await clip.locator('#textReadClipboard').isDisabled(),true);
      assert.equal(await clip.locator('#textSubmit').isDisabled(),true);
      await clip.locator('#textFilename').fill('../escape.txt');
      await clip.locator('#textContent').fill('  manual paste\nsecond line 🐈\t');
      assert.equal(await clip.locator('#textSubmit').isDisabled(),true);
      await clip.locator('#textFilename').fill('Manual.txt');
      await clip.locator('#textCancel').click();
      await clip.locator('#pasteText').click();
      assert.equal(await clip.locator('#textContent').inputValue(),'  manual paste\nsecond line 🐈\t');
      assert.equal(await clip.locator('#textFilename').inputValue(),'Manual.txt');
      await clip.route('**/uploads',route=>route.fulfill({status:400,contentType:'application/json',body:'{"error":"test failure"}'}));
      await clip.locator('#textSubmit').click();
      await clip.waitForFunction(()=>document.querySelector('#textDialogStatus').textContent.includes('not sent'));
      assert.equal(await clip.locator('#textContent').inputValue(),'  manual paste\nsecond line 🐈\t');
      await assert.rejects(fs.stat(path.join(dir,'Manual.txt')),{code:'ENOENT'});
      await clip.unroute('**/uploads');
      await clip.locator('#textSubmit').click();
      await clip.waitForFunction(()=>!document.querySelector('#textDialog').open);
      assert.equal(await fs.readFile(path.join(dir,'Manual.txt'),'utf8'),'  manual paste\nsecond line 🐈\t');
      await clip.locator('.file-card').filter({hasText:'Manual.txt'}).locator('.file-copy').click();
      await clip.waitForFunction(()=>!document.querySelector('#textSubmit').disabled);
      await clip.locator('#textSubmit').click();
      assert.equal(await clip.evaluate(()=>navigator.clipboard.readText()),'  manual paste\nsecond line 🐈\t');
      await clip.locator('#textCancel').click();
      console.log('PASS real browser: HTTP manual paste, cancel retains draft, failed send retry, HTTP copy fallback');

      await clip.locator('#pasteText').click();
      await clip.locator('#textContent').fill('x'.repeat(2*1024*1024+1));
      assert.equal(await clip.locator('#textSubmit').isDisabled(),true);
      assert.ok((await clip.locator('#textDialogStatus').textContent()).includes('too large'));
      await clip.locator('#textClear').click();
      await clip.locator('#textCancel').click();
      await clip.evaluate(()=>{
        const data=new DataTransfer();data.setData('text/plain','Pasted outside the editor');
        document.body.dispatchEvent(new ClipboardEvent('paste',{clipboardData:data,bubbles:true,cancelable:true}));
      });
      assert.equal(await clip.locator('#textContent').inputValue(),'Pasted outside the editor');
      await clip.locator('#textFilename').fill('Pasted note.txt');
      await clip.locator('#textSubmit').click();
      await clip.waitForFunction(()=>!document.querySelector('#textDialog').open);
      assert.equal(await fs.readFile(path.join(dir,'Pasted note (1).txt'),'utf8'),'Pasted outside the editor');
      console.log('PASS real browser: oversized draft blocked, page paste opens review, duplicate filenames preserved');

      // Permission rejection must preserve the manual editor.
      await clip.reload();
      await clip.evaluate(()=>Object.defineProperty(navigator,'clipboard',{configurable:true,value:{readText:()=>Promise.reject(new DOMException('denied','NotAllowedError'))}}));
      await clip.locator('#pasteText').click();
      await clip.waitForFunction(()=>document.querySelector('#textDialogStatus').textContent.includes('unavailable'));
      assert.equal(await clip.locator('#textContent').isEditable(),true);
      await clip.locator('#textContent').fill('draft to keep');
      await clip.locator('#textCancel').click();
      await clip.locator('#pasteText').click();
      assert.equal(await clip.locator('#textContent').inputValue(),'draft to keep');
      await clip.locator('#textClear').click();
      await clip.locator('#textCancel').click();
      console.log('PASS real browser: denied clipboard permission leaves an editable, preserved draft');
      await clip.evaluate(()=>Object.defineProperty(navigator,'clipboard',{configurable:true,value:{readText:()=>new Promise(resolve=>window.__clipboardResolve=resolve)}}));
      await clip.locator('#pasteText').click();
      await clip.locator('#textContent').fill('keep my edits');
      await clip.evaluate(()=>window.__clipboardResolve('older clipboard text'));
      await clip.waitForFunction(()=>document.querySelector('#textDialogStatus').textContent.includes('edits were kept'));
      assert.equal(await clip.locator('#textContent').inputValue(),'keep my edits');
      await clip.locator('#textClear').click();
      await clip.locator('#textCancel').click();
      // Restore a fast permission failure for the mobile layout check.
      await clip.evaluate(()=>Object.defineProperty(navigator,'clipboard',{configurable:true,value:{readText:()=>Promise.reject(new DOMException('denied','NotAllowedError'))}}));
      console.log('PASS real browser: a delayed clipboard response never overwrites user edits');

      await clip.setViewportSize({width:390,height:844});
      await clip.locator('#pasteText').click();
      const dialogBounds=await clip.locator('#textDialog').boundingBox();
      assert.ok(dialogBounds.x>=8&&dialogBounds.x+dialogBounds.width<=382,'text editor fits mobile viewport');
      await clip.locator('#textContent').fill('A quick note from my phone 👋\n\nPaste text here, then send it as a .txt file.');
      await clip.locator('#textFilename').fill('Quick note.txt');
      if(process.env.LD_SCREENSHOT_DIR) await clip.locator('#textDialog').screenshot({path:path.join(process.env.LD_SCREENSHOT_DIR,'clipboard-mobile.png')});
      await clip.locator('#textClear').click();
      await clip.locator('#textCancel').click();
      await clip.close();
    }
    await page.setViewportSize({width:390,height:844});
    await page.evaluate(()=>toast('Package upload failed. This is a long message that must remain readable on a phone rather than extending off the screen.','error'));
    const toastBounds=await page.locator('#toast').boundingBox();
    assert.ok(toastBounds.x>=8&&toastBounds.x+toastBounds.width<=382,'mobile error must fit on screen: '+JSON.stringify(toastBounds));
    console.log('PASS real browser: long error messages fit the phone viewport');
    assert.deepEqual(errors, []);
  } finally {
    if (browser) await browser.close();
    child.kill();
    await new Promise(r => child.exitCode !== null ? r() : child.once('exit',r));
    await fs.rm(dir,{recursive:true,force:true});
  }
})().catch(e => { console.error(e); process.exitCode=1; });
