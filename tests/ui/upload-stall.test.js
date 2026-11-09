// Runs the real ui/app.js upload engine against a fake LiquidDrop server.
// Scenarios model what iPhones actually do:
//   quiet   - Safari sends data but reports NO upload progress (must not be cancelled)
//   dead    - the connection silently dies part-way (must resume, no tapping)
//   error   - the connection errors part-way (must resume from the saved offset)
// Usage: node upload-stall.test.js ui/app.js
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
global.LD_UPLOAD_TIMING = { stallMs: 1500, pollMs: 150, slowMs: 600 };
global.document = { querySelector: () => stub, querySelectorAll: () => [], createElement: () => stub,
  addEventListener() {}, body: stub, head: stub, hidden: false, execCommand() {} };
global.location = { pathname: '/TOKEN/', href: 'http://x/TOKEN/', reload() {} };
global.localStorage = { getItem() { return null; }, setItem() {} };
global.navigator = {};
global.addEventListener = () => {};
global.EventSource = undefined;

let server;
function freshServer(plan) { server = { files: {}, parts: {}, meta: {}, plan, puts: 0, log: [] }; }
function json(status, obj) { return { ok: status < 400, status, json: async () => obj }; }
global.fetch = async (url, opts = {}) => {
  const m = (opts.method || 'GET').toUpperCase();
  const parts = new URL(url, 'http://x').pathname.split('/').filter(Boolean);
  const route = parts[1];
  if (route === 'uploads' && m === 'POST' && parts.length === 2) {
    const b = JSON.parse(opts.body);
    if (!server.meta[b.id] || server.meta[b.id].size !== b.size) { server.meta[b.id] = b; server.parts[b.id] = Buffer.alloc(0); }
    return json(200, { id: b.id, offset: server.parts[b.id].length, size: b.size });
  }
  if (route === 'uploads' && m === 'GET') { const id = parts[2]; return json(200, { offset: server.parts[id].length }); }
  if (route === 'uploads' && m === 'POST' && parts[3] === 'complete') {
    const id = parts[2], meta = server.meta[id];
    if (!meta) return json(404, { error: 'Unknown upload.' });
    if (server.parts[id].length !== meta.size) return json(409, { error: 'incomplete', offset: server.parts[id].length });
    server.files[meta.name] = server.parts[id]; delete server.meta[id];
    return json(200, { status: 'ok', name: meta.name, size: meta.size });
  }
  return json(200, []);
};
class FakeXHR {
  constructor() { this.upload = {}; this.status = 0; this.responseText = ''; }
  open(m, url) { this.url = new URL(url, 'http://x'); }
  abort() { if (this.done) return; this.done = true; server.log.push('abort#' + this.n); setTimeout(() => this.onabort && this.onabort(), 0); }
  async send(body) {
    const id = this.url.pathname.split('/')[3];
    const offset = Number(this.url.searchParams.get('offset'));
    this.n = ++server.puts;
    const after = server.plan.after;
    const mode = server.plan[this.n] || (after && this.n > after.n ? after.mode : 'ok');
    server.log.push(this.n + ':' + mode + '@' + offset);
    const buf = Buffer.from(body instanceof ArrayBuffer ? body : await body.arrayBuffer());
    if (server.parts[id].length > offset) server.parts[id] = server.parts[id].subarray(0, offset);
    let sent = 0;
    const step = 256 * 1024;
    const deadAt = mode.startsWith('dead') ? Math.floor(buf.length / 3) : Infinity;
    const errAt = mode === 'error' ? Math.floor(buf.length / 2) : Infinity;
    const tick = () => {
      if (this.done) return;
      if (sent >= deadAt) return; // silent dead connection: nothing ever happens again
      if (sent >= errAt) { this.done = true; return this.onerror && this.onerror(); }
      const n = Math.min(step, buf.length - sent);
      server.parts[id] = Buffer.concat([server.parts[id], buf.subarray(sent, sent + n)]);
      sent += n;
      if (mode !== 'quiet' && this.upload.onprogress) this.upload.onprogress({ loaded: sent, total: buf.length });
      if (sent < buf.length) return setTimeout(tick, mode === 'quiet' ? Number(process.env.QUIET_DELAY || 40) : 2);
      this.done = true; this.status = 200;
      this.responseText = JSON.stringify({ offset: server.parts[id].length });
      this.onload && this.onload();
    };
    setTimeout(tick, 2);
  }
}
global.XMLHttpRequest = FakeXHR;
const toasts = [];
const api = new Function(src + '\n;return {uploadFiles, setToast:(f)=>{toast=f;}};')();
api.setToast((m) => toasts.push(m));

const crypto = require('crypto');
async function scenario(name, plan) {
  const guard = setTimeout(() => { console.log('TIMEOUT ' + name + ' requests: ' + server.log.join(' ') + ' toasts: ' + toasts.join(' | ')); process.exit(2); }, Number(process.env.GUARD_MS || 25000));
  freshServer(plan);
  toasts.length = 0;
  const photos = Array.from({ length: 11 }, (_, i) => crypto.randomBytes(1_500_000 + i * 1000));
  const video = crypto.randomBytes(25 * 1024 * 1024 + 4321);
  const files = photos.map((b, i) => new File([b], 'IMG_' + (500 + i) + '.JPG'));
  files.push(new File([video], 'IMG_0599.MOV'));
  const t0 = Date.now();
  const names = await api.uploadFiles(files);
  const secs = ((Date.now() - t0) / 1000).toFixed(1);
  const ok = names.length === 12 &&
    photos.every((b, i) => server.files['IMG_' + (500 + i) + '.JPG'].equals(b)) &&
    server.files['IMG_0599.MOV'].equals(video);
  console.log((ok ? 'PASS ' : 'FAIL ') + name + ' — 12 files in ' + secs + 's; requests: ' + server.log.join(' '));
  clearTimeout(guard);
  if (!ok) { console.log('toasts:', toasts); process.exit(1); }
}

(async () => {
  const all = [
    ['normal', {}],
    ['video: Safari reports no upload progress at all (iPhone quirk)', { 12: 'quiet', after: { n: 12, mode: 'quiet' } }],
    ['video connection dies silently, twice', { 12: 'dead', 13: 'dead' }],
    ['video connection errors mid-way', { 12: 'error' }],
    ['photo and video both die', { 3: 'dead', 12: 'dead' }],
  ];
  const only = process.env.SCENARIO;
  for (const [i, [name, plan]] of all.entries()) {
    if (only !== undefined && String(i) !== only) continue;
    await scenario(name, plan);
  }
  console.log('ALL PASS');
  process.exit(0);
})().catch((e) => { console.error('FAIL', e); process.exit(1); });
