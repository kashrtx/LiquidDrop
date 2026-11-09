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
    await page.addInitScript(() => { window.LD_UPLOAD_TIMING = {requestMs:700,stallMs:1500,pollMs:100,slowMs:400}; });
    for (const mode of ['normal-mp4','mixed','lost-start','lost-put-reply','lost-complete','storage-full']) {
      await page.goto(`http://127.0.0.1:${port}/${token}/`);
      let injected = false;
      await page.route('**/uploads**', async route => {
        const req = route.request(), url = new URL(req.url());
        if (mode === 'storage-full' && req.method() === 'PUT') {
          await route.fulfill({status:507,contentType:'application/json',body:JSON.stringify({error:'Disk full'})});
          return;
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
      const files = suffixes.map((ext,i) => ({name:`${mode}-${i}.${ext}`,mimeType:ext==='mp4'?'video/mp4':'application/octet-stream',buffer:randomBytes(ext==='mp4'?17*1024*1024+173:10043)}));
      await page.locator('#fileInput').setInputFiles(files);
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
      if (mode.startsWith('lost-')) assert.ok(injected);
      await page.unroute('**/uploads**');
      console.log('PASS real browser: '+mode+'; all file hashes match');
    }
    assert.deepEqual(errors, []);
  } finally {
    if (browser) await browser.close();
    child.kill();
    await new Promise(r => child.exitCode !== null ? r() : child.once('exit',r));
    await fs.rm(dir,{recursive:true,force:true});
  }
})().catch(e => { console.error(e); process.exitCode=1; });
