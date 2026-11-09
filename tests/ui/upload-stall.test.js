// Runs the real ui/app.js upload engine against a fake server that silently
// hangs a chunk (no progress, no error) the way the iPhone did.
const fs = require('fs');
const src = fs.readFileSync(process.argv[2], 'utf8');

const stub = new Proxy(function () {}, {
  get: (t, k) => {
    if (k === 'then') return undefined;
    if (k === Symbol.toPrimitive) return () => '';
    if (k === 'length' || k === 'size') return 0;
    if (k === 'children') return [];
    if (k === 'dataset') return {};
    if (k === 'classList') return { add() {}, remove() {}, toggle() {}, contains() { return false; } };
    return stub;
  },
  set: () => true,
  apply: () => stub,
});
global.window = global;
global.document = { querySelector: () => stub, querySelectorAll: () => [], createElement: () => stub,
  addEventListener() {}, body: stub, head: stub, hidden: false, execCommand() {} };
global.location = { pathname: '/TOKEN/', href: 'http://x/TOKEN/' };
global.localStorage = { getItem() { return null; }, setItem() {} };
global.navigator = {};
global.addEventListener = () => {};
global.EventSource = undefined;

// ---- fake server ----
const server = { files: {}, parts: {}, meta: {}, hangPlan: new Set(), puts: 0, log: [] };
function json(status, obj) { return { ok: status < 400, status, json: async () => obj }; }
global.fetch = async (url, opts = {}) => {
  const m = (opts.method || 'GET').toUpperCase();
  const u = new URL(url, 'http://x');
  const parts = u.pathname.split('/').filter(Boolean); // TOKEN, route, ...
  const route = parts[1];
  if (route === 'uploads' && m === 'POST' && parts.length === 2) {
    const b = JSON.parse(opts.body);
    if (!server.meta[b.id] || server.meta[b.id].size !== b.size) { server.meta[b.id] = b; server.parts[b.id] = Buffer.alloc(0); }
    return json(200, { id: b.id, offset: server.parts[b.id].length, size: b.size, chunk: 8 * 1024 * 1024 });
  }
  if (route === 'uploads' && m === 'GET') { const id = parts[2]; return json(200, { offset: server.parts[id].length, size: server.meta[id].size }); }
  if (route === 'uploads' && m === 'POST' && parts[3] === 'complete') {
    const id = parts[2], meta = server.meta[id];
    if (!meta) return json(404, { error: 'Unknown upload.' });
    if (server.parts[id].length !== meta.size) return json(409, { error: 'incomplete' });
    server.files[meta.name] = server.parts[id]; delete server.meta[id];
    return json(200, { status: 'ok', name: meta.name, size: meta.size });
  }
  if (route === 'files') return json(200, []);
  return json(200, {});
};
class FakeXHR {
  constructor() { this.upload = {}; this.status = 0; this.responseText = ''; this.aborted = false; }
  open(m, url) { this.url = new URL(url, 'http://x'); }
  abort() { if (this.done) return; this.aborted = true; this.done = true; server.log.push('abort'); setTimeout(() => this.onabort && this.onabort(), 0); }
  send(data) {
    const id = this.url.pathname.split('/')[3];
    const offset = Number(this.url.searchParams.get('offset'));
    const n = ++server.puts;
    const buf = Buffer.from(data);
    if (!(data instanceof ArrayBuffer)) server.log.push('NOT-ARRAYBUFFER');
    if (server.hangPlan.has(n)) { server.log.push('hang#' + n); return; } // silent dead connection
    let sent = 0; const step = 1024 * 1024;
    const tick = () => {
      if (this.aborted) return;
      sent = Math.min(buf.length, sent + step);
      this.upload.onprogress && this.upload.onprogress({ loaded: sent, lengthComputable: true, total: buf.length });
      if (sent < buf.length) return setTimeout(tick, 2);
      const cur = server.parts[id];
      if (offset > cur.length) { this.status = 409; this.responseText = JSON.stringify({ offset: cur.length }); }
      else { server.parts[id] = Buffer.concat([cur.subarray(0, offset), buf]); this.status = 200; this.responseText = JSON.stringify({ offset: server.parts[id].length }); }
      this.done = true; this.upload.onload && this.upload.onload(); this.onload && this.onload();
    };
    setTimeout(tick, 2);
  }
}
global.XMLHttpRequest = FakeXHR;
let toasts = [];

// load the real app code; expose what we need
const runner = new Function(src + '\n;return {uploadFiles, uploadState, setToast:(f)=>{toast=f;}};');
const api = runner();
api.setToast((m) => toasts.push(m));

(async () => {
  const crypto = require('crypto');
  const video = crypto.randomBytes(25 * 1024 * 1024 + 12345);
  const photo1 = crypto.randomBytes(2_200_000), photo2 = crypto.randomBytes(2_800_000);
  const files = [new File([photo1], 'IMG_0501.JPG'), new File([photo2], 'IMG_0502.JPG'), new File([video], 'IMG_0503.MOV')];
  // Recreate the iPhone failure: the video's 2nd chunk hangs silently, twice.
  // PUT order: photo1(1) photo2(1) video chunk1 = #3, video chunk2 = #4 (hang), retry #5 (hang), retry #6 ok
  server.hangPlan = new Set((process.argv[3] || "4,5").split(",").map(Number));
  const t0 = Date.now();
  const names = await api.uploadFiles(files);
  const secs = ((Date.now() - t0) / 1000).toFixed(1);
  const ok = names.length === 3 &&
    server.files['IMG_0501.JPG'].equals(photo1) &&
    server.files['IMG_0502.JPG'].equals(photo2) &&
    server.files['IMG_0503.MOV'].equals(video);
  console.log('uploaded:', names, 'in', secs + 's');
  console.log('server log:', server.log.join(' '));
  console.log('toasts:', toasts);
  console.log(ok ? 'PASS: all files arrived byte-for-byte despite silent hangs on requests ' + [...server.hangPlan].join(',') : 'FAIL');
  process.exit(ok ? 0 : 1);
})().catch((e) => { console.error('FAIL', e); process.exit(1); });
