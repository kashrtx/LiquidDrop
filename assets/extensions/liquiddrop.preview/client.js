(function () {
  const api = window.LiquidDropExtensions;
  if (!api) return;

  const imageExts = new Set(['jpg', 'jpeg', 'png', 'gif', 'webp', 'heic', 'svg', 'bmp', 'ico', 'avif']);
  const videoExts = new Set(['mp4', 'mov', 'm4v', 'webm', 'avi', 'mkv']);
  const audioExts = new Set(['mp3', 'wav', 'm4a', 'aac', 'flac', 'ogg', 'oga', 'opus', 'weba', 'aiff']);
  const pdfExts = new Set(['pdf']);
  const documentExts = new Set([
    'docx', 'txt', 'text', 'md', 'markdown', 'csv', 'tsv', 'json', 'jsonl', 'xml', 'html', 'htm', 'css',
    'js', 'mjs', 'cjs', 'ts', 'tsx', 'jsx', 'py', 'rb', 'go', 'rs', 'java', 'c', 'cpp', 'h', 'hpp', 'cs',
    'php', 'swift', 'kt', 'kts', 'sh', 'bash', 'zsh', 'ps1', 'bat', 'cmd', 'sql', 'yaml', 'yml', 'toml',
    'ini', 'cfg', 'conf', 'log', 'env', 'gitignore', 'rtf', 'srt', 'vtt'
  ]);
  const documentNames = new Set(['dockerfile', 'makefile', 'license', 'readme', '.env']);
  const pdfSources = [
    {
      script: 'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.min.js',
      worker: 'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js'
    },
    {
      script: 'https://cdn.jsdelivr.net/npm/pdfjs-dist@3.11.174/build/pdf.min.js',
      worker: 'https://cdn.jsdelivr.net/npm/pdfjs-dist@3.11.174/build/pdf.worker.min.js'
    }
  ];

  let overlay = null;
  let content = null;
  let title = null;
  let download = null;
  let zoomLabel = null;
  let activeMedia = null;
  let zoom = 1;
  let mediaFrame = null;
  let visualizerStop = null;
  let requestSeq = 0;
  let pdfJsPromise = null;
  const pointers = new Map();
  let dragState = null;
  let pinchState = null;

  function ext(name) { return String(name || '').includes('.') ? String(name).split('.').pop().toLowerCase() : ''; }
  function basename(name) { return String(name || '').split(/[\\/]/).pop().toLowerCase(); }
  function kind(name) {
    const e = ext(name);
    if (imageExts.has(e)) return 'image';
    if (videoExts.has(e)) return 'video';
    if (audioExts.has(e)) return 'audio';
    if (pdfExts.has(e)) return 'pdf';
    if (documentExts.has(e) || documentNames.has(basename(name))) return 'document';
    return '';
  }
  function esc(value) {
    if (api.escapeHtml) return api.escapeHtml(value);
    return String(value == null ? '' : value).replace(/[&<>"']/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
  }

  function ensure() {
    if (overlay) return;
    const style = document.createElement('style');
    style.textContent = `
.ld-preview-overlay{position:fixed;inset:0;z-index:1100;background:rgba(4,6,18,.82);backdrop-filter:blur(18px);-webkit-backdrop-filter:blur(18px);display:flex;flex-direction:column;padding:env(safe-area-inset-top,18px) 14px env(safe-area-inset-bottom,18px);opacity:0;pointer-events:none;transition:opacity .18s ease}
.ld-preview-overlay.show{opacity:1;pointer-events:auto}
.ld-preview-bar{height:54px;display:flex;align-items:center;gap:8px;max-width:1280px;width:100%;margin:0 auto;flex-shrink:0}
.ld-preview-title{flex:1;min-width:0;color:#f7f7fb;font-size:14px;font-weight:800;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.ld-preview-btn{min-width:42px;height:42px;border-radius:14px;border:1px solid rgba(255,255,255,.14);background:rgba(255,255,255,.08);color:#f7f7fb;display:flex;align-items:center;justify-content:center;text-decoration:none;font:inherit;font-size:12px;font-weight:900;cursor:pointer;padding:0 10px}
.ld-preview-btn:hover{background:rgba(255,255,255,.14)}
.ld-preview-btn[disabled]{opacity:.35;pointer-events:none}
.ld-preview-stage{position:relative;min-height:0;flex:1;max-width:1280px;width:100%;margin:0 auto;display:flex;align-items:center;justify-content:center;border-radius:18px;overflow:hidden;background:rgba(5,8,22,.72);border:1px solid rgba(255,255,255,.12);box-shadow:0 24px 80px rgba(0,0,0,.48);overscroll-behavior:contain}
.ld-preview-stage.zoomed{overflow:auto}
.ld-preview-stage.media{display:block;align-items:stretch;justify-content:flex-start;overflow:auto;touch-action:none;-webkit-overflow-scrolling:auto;scrollbar-gutter:stable;cursor:default}
.ld-preview-stage.media.zoomed{cursor:grab}
.ld-preview-stage.media.dragging{cursor:grabbing;user-select:none}
.ld-media-canvas{position:relative;min-width:100%;min-height:100%;width:100%;height:100%;touch-action:none}
.ld-media-canvas>img,.ld-media-canvas>video{position:absolute;display:block;max-width:none;max-height:none;width:auto;height:auto;object-fit:contain;transition:none;transform:none;transform-origin:center center;user-select:none;-webkit-user-drag:none}
.ld-media-canvas>video{background:#000}
.ld-preview-stage.document{align-items:flex-start;justify-content:flex-start;overflow:auto;padding:18px;touch-action:pan-x pan-y;-webkit-overflow-scrolling:touch}
.ld-preview-stage.pdf{display:block;overflow-y:auto;overflow-x:auto;text-align:center;touch-action:pan-x pan-y;-webkit-overflow-scrolling:touch;overscroll-behavior:contain}
.ld-preview-stage:not(.media) img,.ld-preview-stage:not(.media) video{display:block;max-width:100%;max-height:100%;width:auto;height:auto;object-fit:contain;transition:transform .16s ease;transform-origin:center center}
.ld-preview-stage:not(.media)>video{width:100%;height:100%;background:#000}
.ld-preview-doc{width:min(940px,100%);min-height:100%;background:#fbfbff;color:#111827;border-radius:12px;padding:22px;box-shadow:0 18px 54px rgba(0,0,0,.24);line-height:1.55;font-size:14px;transition:transform .16s ease;transform-origin:top left;flex:0 0 auto}
.ld-preview-doc h3{margin:0 0 6px;font-size:18px;line-height:1.25;color:#0f172a;overflow-wrap:anywhere}
.ld-preview-doc-meta{margin:0 0 18px;color:#64748b;font-size:12px;font-weight:800;text-transform:uppercase;letter-spacing:.08em}
.ld-preview-doc pre{margin:0;white-space:pre-wrap;overflow-wrap:anywhere;font:inherit;font-family:'SF Mono',Consolas,ui-monospace,monospace;color:#111827}
.ld-pdf-pages{display:inline-flex;flex-direction:column;gap:14px;width:min(920px,100%);max-width:none;margin:0 auto;vertical-align:top;transition:transform .16s ease;transform-origin:top center}
.ld-pdf-status{width:100%;border-radius:14px;padding:10px 12px;text-align:left;background:rgba(255,255,255,.08);border:1px solid rgba(255,255,255,.12);color:#f7f7fb;font-size:12px;font-weight:800}
.ld-pdf-page{position:relative;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 16px 46px rgba(0,0,0,.32);border:1px solid rgba(255,255,255,.18)}
.ld-pdf-page canvas{display:block;width:100%;height:auto;background:#fff}
.ld-pdf-page-label{position:absolute;left:10px;top:10px;border-radius:999px;padding:5px 8px;background:rgba(8,10,20,.64);color:#fff;font-size:10px;font-weight:900;letter-spacing:.04em;backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px)}
.ld-preview-loading,.ld-preview-error{width:min(520px,calc(100% - 28px));border-radius:16px;padding:18px 20px;text-align:center;font-weight:800;color:#f7f7fb;background:rgba(255,255,255,.08);border:1px solid rgba(255,255,255,.12)}
.ld-preview-error{color:#fecaca;background:rgba(248,113,113,.1);border-color:rgba(248,113,113,.28)}
.ld-audio-shell{width:min(920px,calc(100% - 28px));display:flex;flex-direction:column;gap:18px;align-items:stretch}
.ld-audio-viz-wrap{position:relative;width:100%;height:380px;border-radius:18px;overflow:hidden;border:1px solid rgba(255,255,255,.08);background:radial-gradient(circle at 50% 50%,#0a0a1c 0%,#05050e 70%)}
.ld-audio-viz,.ld-audio-particles{position:absolute;inset:0;width:100%;height:100%;border-radius:inherit}
.ld-audio-particles{pointer-events:none}
.ld-audio-shell audio{width:100%;filter:drop-shadow(0 2px 8px rgba(129,140,248,.18))}
@media(max-width:560px){.ld-preview-overlay{padding-left:4px;padding-right:4px}.ld-preview-bar{height:auto;min-height:50px;flex-wrap:wrap}.ld-preview-title{flex-basis:100%;order:-1}.ld-preview-btn{height:38px;min-width:38px}.ld-preview-stage{border-radius:14px}.ld-preview-stage.document,.ld-preview-stage.pdf{padding:8px}.ld-preview-doc{padding:14px;border-radius:10px;font-size:13px}.ld-pdf-pages{gap:10px}.ld-pdf-page{border-radius:10px}.ld-audio-shell{width:calc(100% - 8px)}.ld-audio-viz-wrap{height:300px;border-radius:12px}}
`;
    document.head.appendChild(style);
    overlay = document.createElement('div');
    overlay.className = 'ld-preview-overlay';
    overlay.innerHTML = '<div class="ld-preview-bar"><div class="ld-preview-title"></div><button class="ld-preview-btn" type="button" data-zoom-out title="Zoom out">Z-</button><button class="ld-preview-btn" type="button" data-zoom-fit title="Reset zoom">100%</button><button class="ld-preview-btn" type="button" data-zoom-in title="Zoom in">Z+</button><a class="ld-preview-btn" title="Download" download>DL</a><button class="ld-preview-btn" type="button" title="Close">X</button></div><div class="ld-preview-stage"></div>';
    title = overlay.querySelector('.ld-preview-title');
    download = overlay.querySelector('a');
    content = overlay.querySelector('.ld-preview-stage');
    zoomLabel = overlay.querySelector('[data-zoom-fit]');
    overlay.querySelector('[data-zoom-out]').addEventListener('click', () => setZoom(zoom / 1.25));
    overlay.querySelector('[data-zoom-in]').addEventListener('click', () => setZoom(zoom * 1.25));
    zoomLabel.addEventListener('click', () => setZoom(1));
    overlay.querySelector('button[title="Close"]').addEventListener('click', close);
    overlay.addEventListener('click', e => { if (e.target === overlay) close(); });
    content.addEventListener('wheel', e => {
      if (!activeMedia || activeMedia.tagName === 'AUDIO') return;
      if (e.ctrlKey || e.metaKey) {
        e.preventDefault();
        const step = Math.exp(-e.deltaY * 0.0018);
        setZoom(zoom * step, { clientX: e.clientX, clientY: e.clientY });
      }
    }, { passive: false });
    content.addEventListener('pointerdown', onMediaPointerDown);
    content.addEventListener('pointermove', onMediaPointerMove);
    content.addEventListener('pointerup', onMediaPointerEnd);
    content.addEventListener('pointercancel', onMediaPointerEnd);
    document.addEventListener('keydown', e => {
      if (!overlay.classList.contains('show')) return;
      if (e.key === 'Escape') close();
      if ((e.ctrlKey || e.metaKey) && e.key === '=') { e.preventDefault(); setZoom(zoom * 1.25); }
      if ((e.ctrlKey || e.metaKey) && e.key === '-') { e.preventDefault(); setZoom(zoom / 1.25); }
      if ((e.ctrlKey || e.metaKey) && e.key === '0') { e.preventDefault(); setZoom(1); }
    });
    window.addEventListener('resize', () => {
      if (overlay.classList.contains('show') && isMediaZoomMode()) updateMediaLayout(anchorFromStageCenter());
    });
    document.body.appendChild(overlay);
  }

  function clamp(value, min, max) { return Math.max(min, Math.min(max, Number(value) || min)); }
  function isMediaZoomMode() { return !!(mediaFrame && activeMedia && activeMedia.dataset.zoomMode === 'media'); }
  function stageCenterPoint() {
    const rect = content.getBoundingClientRect();
    return { clientX: rect.left + rect.width / 2, clientY: rect.top + rect.height / 2 };
  }
  function mediaPointFromClient(clientX, clientY) {
    if (!mediaFrame || !mediaFrame.media) return { mx: .5, my: .5 };
    const rect = mediaFrame.media.getBoundingClientRect();
    return {
      mx: clamp((clientX - rect.left) / Math.max(1, rect.width), 0, 1),
      my: clamp((clientY - rect.top) / Math.max(1, rect.height), 0, 1)
    };
  }
  function normalizeMediaAnchor(anchor) {
    const point = anchor || stageCenterPoint();
    const clientX = Number.isFinite(point.clientX) ? point.clientX : stageCenterPoint().clientX;
    const clientY = Number.isFinite(point.clientY) ? point.clientY : stageCenterPoint().clientY;
    if (Number.isFinite(point.mx) && Number.isFinite(point.my)) {
      return { clientX, clientY, mx: clamp(point.mx, 0, 1), my: clamp(point.my, 0, 1) };
    }
    return { clientX, clientY, ...mediaPointFromClient(clientX, clientY) };
  }
  function anchorFromStageCenter() { return normalizeMediaAnchor(stageCenterPoint()); }
  function mediaSourceSize() {
    if (!mediaFrame || !mediaFrame.media) return { width: 1, height: 1 };
    const m = mediaFrame.media;
    const width = m.naturalWidth || m.videoWidth || mediaFrame.sourceWidth || content.clientWidth || 1;
    const height = m.naturalHeight || m.videoHeight || mediaFrame.sourceHeight || content.clientHeight || 1;
    return { width: Math.max(1, width), height: Math.max(1, height) };
  }
  function updateMediaFit() {
    if (!mediaFrame) return;
    const source = mediaSourceSize();
    mediaFrame.sourceWidth = source.width;
    mediaFrame.sourceHeight = source.height;
    const stageW = Math.max(1, content.clientWidth);
    const stageH = Math.max(1, content.clientHeight);
    let fit = Math.min(stageW / source.width, stageH / source.height);
    if (!mediaFrame.allowUpscale) fit = Math.min(1, fit);
    mediaFrame.baseWidth = Math.max(1, source.width * fit);
    mediaFrame.baseHeight = Math.max(1, source.height * fit);
  }
  function updateMediaLayout(anchor) {
    if (!mediaFrame) return;
    updateMediaFit();
    const normalized = anchor ? normalizeMediaAnchor(anchor) : null;
    const scaledW = Math.max(1, mediaFrame.baseWidth * zoom);
    const scaledH = Math.max(1, mediaFrame.baseHeight * zoom);
    const canvasW = Math.max(content.clientWidth || 1, scaledW);
    const canvasH = Math.max(content.clientHeight || 1, scaledH);
    const left = Math.max(0, (canvasW - scaledW) / 2);
    const top = Math.max(0, (canvasH - scaledH) / 2);
    mediaFrame.canvas.style.width = canvasW + 'px';
    mediaFrame.canvas.style.height = canvasH + 'px';
    mediaFrame.media.style.width = scaledW + 'px';
    mediaFrame.media.style.height = scaledH + 'px';
    mediaFrame.media.style.left = left + 'px';
    mediaFrame.media.style.top = top + 'px';
    content.classList.toggle('zoomed', zoom > 1.01);
    if (normalized) {
      const rect = content.getBoundingClientRect();
      content.scrollLeft = left + normalized.mx * scaledW - (normalized.clientX - rect.left);
      content.scrollTop = top + normalized.my * scaledH - (normalized.clientY - rect.top);
    } else if (zoom <= 1.01) {
      content.scrollLeft = 0;
      content.scrollTop = 0;
    }
  }
  function setupMediaViewer(node, options) {
    const canvas = document.createElement('div');
    canvas.className = 'ld-media-canvas';
    node.dataset.zoomMode = 'media';
    canvas.appendChild(node);
    content.classList.add('media');
    content.appendChild(canvas);
    mediaFrame = { canvas, media: node, allowUpscale: !!(options && options.allowUpscale), baseWidth: 1, baseHeight: 1, sourceWidth: 1, sourceHeight: 1 };
    activeMedia = node;
    updateMediaLayout();
  }
  function resetPointerState() {
    pointers.clear();
    dragState = null;
    pinchState = null;
    if (content) content.classList.remove('dragging');
  }
  function pointerPair() { return [...pointers.values()].slice(0, 2); }
  function distance(a, b) { return Math.hypot(a.clientX - b.clientX, a.clientY - b.clientY); }
  function midpoint(a, b) { return { clientX: (a.clientX + b.clientX) / 2, clientY: (a.clientY + b.clientY) / 2 }; }
  function onMediaPointerDown(e) {
    if (!isMediaZoomMode() || (e.pointerType === 'mouse' && e.button !== 0)) return;
    pointers.set(e.pointerId, { clientX: e.clientX, clientY: e.clientY });
    try { content.setPointerCapture(e.pointerId); } catch (_) { }
    if (pointers.size === 1) {
      dragState = { id: e.pointerId, x: e.clientX, y: e.clientY, scrollLeft: content.scrollLeft, scrollTop: content.scrollTop, moved: false };
    } else if (pointers.size >= 2) {
      const [a, b] = pointerPair();
      const center = midpoint(a, b);
      pinchState = { distance: Math.max(1, distance(a, b)), zoom, anchor: normalizeMediaAnchor(center) };
      dragState = null;
      e.preventDefault();
    }
  }
  function onMediaPointerMove(e) {
    if (!isMediaZoomMode() || !pointers.has(e.pointerId)) return;
    pointers.set(e.pointerId, { clientX: e.clientX, clientY: e.clientY });
    if (pinchState && pointers.size >= 2) {
      const [a, b] = pointerPair();
      const center = midpoint(a, b);
      const next = pinchState.zoom * (distance(a, b) / pinchState.distance);
      setZoom(next, { clientX: center.clientX, clientY: center.clientY, mx: pinchState.anchor.mx, my: pinchState.anchor.my });
      e.preventDefault();
      return;
    }
    if (!dragState || dragState.id !== e.pointerId || zoom <= 1.01) return;
    const dx = e.clientX - dragState.x;
    const dy = e.clientY - dragState.y;
    if (!dragState.moved && Math.abs(dx) + Math.abs(dy) > 3) dragState.moved = true;
    if (dragState.moved) {
      content.scrollLeft = dragState.scrollLeft - dx;
      content.scrollTop = dragState.scrollTop - dy;
      content.classList.add('dragging');
      e.preventDefault();
    }
  }
  function onMediaPointerEnd(e) {
    if (!pointers.has(e.pointerId)) return;
    pointers.delete(e.pointerId);
    try { content.releasePointerCapture(e.pointerId); } catch (_) { }
    if (pointers.size >= 2) {
      const [a, b] = pointerPair();
      const center = midpoint(a, b);
      pinchState = { distance: Math.max(1, distance(a, b)), zoom, anchor: normalizeMediaAnchor(center) };
      dragState = null;
      return;
    }
    pinchState = null;
    if (pointers.size === 1) {
      const remaining = [...pointers.entries()][0];
      dragState = { id: remaining[0], x: remaining[1].clientX, y: remaining[1].clientY, scrollLeft: content.scrollLeft, scrollTop: content.scrollTop, moved: false };
    } else {
      dragState = null;
      content.classList.remove('dragging');
    }
  }

  function setZoom(next, anchor) {
    const target = Math.max(.25, Math.min(8, Number(next) || 1));
    if (isMediaZoomMode()) {
      const normalized = normalizeMediaAnchor(anchor || stageCenterPoint());
      zoom = target;
      updateMediaLayout(normalized);
    } else {
      zoom = target;
      if (activeMedia) {
        const mode = activeMedia.dataset.zoomMode || 'transform';
        activeMedia.style.transform = 'scale(' + zoom + ')';
        if (mode === 'document') {
          activeMedia.style.transformOrigin = 'top left';
        } else if (mode === 'pdf') {
          activeMedia.style.transformOrigin = 'top center';
        } else {
          activeMedia.style.transformOrigin = 'center center';
        }
        content.classList.toggle('zoomed', zoom > 1.01 || zoom < 0.99);
      }
    }
    if (zoomLabel) zoomLabel.textContent = Math.round(zoom * 100) + '%';
  }
  function setZoomEnabled(enabled) {
    overlay.querySelector('[data-zoom-out]').disabled = !enabled;
    overlay.querySelector('[data-zoom-in]').disabled = !enabled;
    zoomLabel.disabled = !enabled;
  }
  function stopMedia() {
    if (visualizerStop) { visualizerStop(); visualizerStop = null; }
    if (content) content.querySelectorAll('video,audio').forEach(m => { try { m.pause(); } catch (_) { } });
  }
  function close() {
    if (!overlay) return;
    requestSeq++;
    stopMedia();
    resetPointerState();
    mediaFrame = null;
    activeMedia = null;
    overlay.classList.remove('show');
    if (content) content.classList.remove('zoomed', 'document', 'pdf', 'media', 'dragging');
    setTimeout(() => { if (content && !overlay.classList.contains('show')) content.innerHTML = ''; }, 180);
  }

  /* =========================================================================
     LIQUIDDROP AUDIO VISUALIZER  -  premium bar spectrum + beat particles

     The clean, dB-scaled linear bar analyzer (no auto-gain, so it never rises
     on silence) PLUS the satisfying beat magic on top:

       * BEAT ENGINE. An adaptive kick detector watches the 40-160 Hz band
         (the punch of a kick drum) against a rolling local average, with a
         refractory window so it fires on real hits, not on the quiet intro.
         Each hit's strength scales everything it drives.

       * RISING EMBERS. Glowing droplet-like particles are emitted continuously
         from the tops of active bars - so the loud frequencies visibly
         sparkle - and a big burst erupts on every beat. Coloured by frequency
         band, additive-blended on the overlay canvas. Sprite blits + a hard
         cap keep it cheap; motion is delta-timed so it's smooth at any fps.

       * BEAT PULSE. On a hit the bars flash a brighter additive bloom, a soft
         droplet-glow swells up from the baseline centre, and a whole-frame
         shimmer pops - all time-decayed for that "breathing with the drop"
         feel. Zero shadowBlur on the hot path.

     Tunables are in the CONFIG block.
     ========================================================================= */
  function startVisualizer(audio, canvas, particleCanvas) {
    const ctx = canvas.getContext('2d', { alpha: false });
    const pCtx = particleCanvas.getContext('2d');
    const TAU = Math.PI * 2;

    // ---------- CONFIG ----------
    const MIN_DB = -88;          // maps to an empty bar (noise floor)
    const MAX_DB = -14;          // maps to a full bar (loud)
    const SMOOTHING = 0.65;      // analyser temporal smoothing
    const GATE = 0.045;          // extra noise gate applied after normalisation
    const GAMMA = 1.18;          // >1 => quiet content stays low (less "sensitive")
    const ATTACK = 24;           // per-second rise responsiveness
    const RELEASE = 7;           // per-second fall (gentle)
    const PEAK_GRAVITY = 0.9;    // peak-cap fall acceleration
    const MINF = 20, MAXF_CAP = 20000;
    const BLEND = 0.55;          // per-band: BLEND*max + (1-BLEND)*avg
    const BEAT_SENS = 1.35;      // kick must exceed local avg * this to count
    const BEAT_FLOOR = 0.16;     // absolute minimum kick energy for a beat
    const BEAT_REFRACTORY = 0.12;// min seconds between beats
    const MAX_PARTICLES = 300;

    // ---------- audio graph ----------
    let analyser = null, freqData = null, audioCtx = null, sampleRate = 44100;
    let kickLo = 2, kickHi = 8;

    // ---------- band state ----------
    let N = 64;
    let levels = new Float32Array(N);
    let peaks = new Float32Array(N);
    let peakVel = new Float32Array(N);
    let bins = null, binsFor = -1;

    // ---------- beat state ----------
    const HIST = 48;
    const bassHist = new Float32Array(HIST);
    let histIdx = 0, histFilled = 0, beatTimer = 0;
    let punch = 0, flash = 0, bloom = 0, drop = 0;

    // ---------- particles ----------
    const particles = [];
    function mkSprite(base) {
      const c = document.createElement('canvas'); c.width = c.height = 64;
      const g = c.getContext('2d');
      const rad = g.createRadialGradient(32, 32, 0, 32, 32, 32);
      rad.addColorStop(0, base + ',1)'); rad.addColorStop(0.28, base + ',0.6)'); rad.addColorStop(1, base + ',0)');
      g.fillStyle = rad; g.fillRect(0, 0, 64, 64); return c;
    }
    // teal -> blue -> violet -> pink (matches the bar ramp), + white sparkle
    const SPRITES = [
      mkSprite('rgba(45,212,191'), mkSprite('rgba(96,165,250'),
      mkSprite('rgba(167,139,250'), mkSprite('rgba(244,114,182'),
      mkSprite('rgba(255,255,255')
    ];
    function spawn(x, y, vx, vy, sprite, size, decay) {
      if (particles.length >= MAX_PARTICLES) return;
      particles.push({ x, y, vx, vy, s: sprite, size, life: 1, decay });
    }

    function alloc(n) {
      if (levels.length === n) return;
      levels = new Float32Array(n); peaks = new Float32Array(n); peakVel = new Float32Array(n);
    }

    function buildBins(binCount) {
      const nyq = sampleRate / 2, maxF = Math.min(MAXF_CAP, nyq);
      bins = new Array(N);
      for (let i = 0; i < N; i++) {
        const f0 = MINF * Math.pow(maxF / MINF, i / N);
        const f1 = MINF * Math.pow(maxF / MINF, (i + 1) / N);
        let b0 = Math.floor(f0 / nyq * binCount);
        let b1 = Math.ceil(f1 / nyq * binCount);
        b0 = Math.max(0, Math.min(binCount - 1, b0));
        b1 = Math.max(b0 + 1, Math.min(binCount, b1));
        bins[i] = [b0, b1];
      }
      kickLo = Math.max(1, Math.round(40 / nyq * binCount));
      kickHi = Math.max(kickLo + 1, Math.round(160 / nyq * binCount));
      binsFor = N;
    }

    function connect() {
      if (analyser || !(window.AudioContext || window.webkitAudioContext)) return;
      try {
        audioCtx = new (window.AudioContext || window.webkitAudioContext)();
        sampleRate = audioCtx.sampleRate || 44100;
        const source = audioCtx.createMediaElementSource(audio);
        analyser = audioCtx.createAnalyser();
        analyser.fftSize = 4096;                 // fine frequency resolution, esp. in the lows
        analyser.smoothingTimeConstant = SMOOTHING;
        analyser.minDecibels = MIN_DB;
        analyser.maxDecibels = MAX_DB;
        freqData = new Uint8Array(analyser.frequencyBinCount);
        source.connect(analyser);
        analyser.connect(audioCtx.destination);
        buildBins(analyser.frequencyBinCount);
      } catch (e) { analyser = null; }
    }

    // ---------- layout cache ----------
    let L = null, cssW = -1, cssH = -1, dprC = -1;
    let running = true, raf = 0, last = performance.now(), idle = 0;

    function relayout(cw, ch, dpr) {
      const w = Math.max(1, Math.floor(cw * dpr)), h = Math.max(1, Math.floor(ch * dpr));
      canvas.width = w; canvas.height = h;
      const pdpr = Math.min(dpr, 1.5);
      particleCanvas.width = Math.max(1, Math.floor(cw * pdpr));
      particleCanvas.height = Math.max(1, Math.floor(ch * pdpr));

      // adaptive bar count for good density across screen sizes
      const n = Math.max(28, Math.min(80, Math.round(cw / 11)));
      if (n !== N) { N = n; alloc(N); if (analyser && freqData) buildBins(analyser.frequencyBinCount); }

      const sidePad = w * 0.03;
      const topPad = h * 0.07;
      const baseline = h * 0.80;
      const plotH = baseline - topPad;
      const reflH = h - baseline;
      const gap = Math.max(1.5 * dpr, (w - sidePad * 2) / N * 0.22);
      const barW = (w - sidePad * 2 - gap * (N - 1)) / N;
      const radius = Math.min(barW * 0.5, 6 * dpr);
      const capH = Math.max(2 * dpr, 3 * dpr);

      const grad = ctx.createLinearGradient(0, topPad, 0, baseline);
      grad.addColorStop(0.00, 'rgb(244,114,182)');
      grad.addColorStop(0.32, 'rgb(167,139,250)');
      grad.addColorStop(0.66, 'rgb(96,165,250)');
      grad.addColorStop(1.00, 'rgb(45,212,191)');

      const bg = ctx.createLinearGradient(0, 0, 0, h);
      bg.addColorStop(0, '#0a0c1a');
      bg.addColorStop(1, '#05060f');

      const fade = ctx.createLinearGradient(0, baseline, 0, baseline + reflH);
      fade.addColorStop(0, 'rgba(5,6,15,0)');
      fade.addColorStop(0.85, 'rgba(5,6,15,0.92)');
      fade.addColorStop(1, 'rgba(5,6,15,1)');

      L = { w, h, dpr, pdpr, sidePad, topPad, baseline, plotH, reflH, gap, barW, radius, capH, grad, bg, fade };
      cssW = cw; cssH = ch; dprC = dpr;
    }

    function addBar(path, x, w, hgt, baseline, r) {
      const top = baseline - hgt;
      const rr = Math.min(r, w * 0.5, hgt);
      path.moveTo(x, baseline);
      path.lineTo(x, top + rr);
      path.quadraticCurveTo(x, top, x + rr, top);
      path.lineTo(x + w - rr, top);
      path.quadraticCurveTo(x + w, top, x + w, top + rr);
      path.lineTo(x + w, baseline);
      path.closePath();
    }

    function draw(now) {
      if (!running) return;
      raf = requestAnimationFrame(draw);
      const t = now || performance.now();
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      const cw = canvas.clientWidth || 1, ch = canvas.clientHeight || 1;
      if (cw !== cssW || ch !== cssH || dpr !== dprC || !L) relayout(cw, ch, dpr);
      const { w, h, pdpr, sidePad, topPad, baseline, plotH, gap, barW, radius, capH, grad, bg, fade } = L;
      const dt = Math.min(0.05, (t - last) / 1000); last = t;
      const f = dt * 60;
      idle += dt;

      // ---- read spectrum ----
      let live = false, bass = 0;
      if (analyser && audioCtx && audioCtx.state === 'running') {
        analyser.getByteFrequencyData(freqData);
        if (!bins || binsFor !== N) buildBins(analyser.frequencyBinCount);
        live = true;
        let bs = 0; for (let i = kickLo; i <= kickHi; i++) bs += freqData[i];
        bass = bs / (kickHi - kickLo + 1) / 255;
      }

      // ---- update bars ----
      const aRise = Math.min(1, ATTACK * dt);
      const aFall = Math.min(1, RELEASE * dt);
      for (let i = 0; i < N; i++) {
        let target = 0;
        if (live && bins) {
          const b = bins[i]; let sum = 0, mx = 0;
          for (let j = b[0]; j < b[1]; j++) { const v = freqData[j]; sum += v; if (v > mx) mx = v; }
          const avg = sum / (b[1] - b[0]);
          let v = (BLEND * mx + (1 - BLEND) * avg) / 255;
          v = (v - GATE) / (1 - GATE);
          if (v < 0) v = 0;
          target = Math.pow(v, GAMMA);
        }
        const lv = levels[i];
        levels[i] = lv + (target - lv) * (target > lv ? aRise : aFall);
        if (levels[i] >= peaks[i]) { peaks[i] = levels[i]; peakVel[i] = 0; }
        else { peakVel[i] += PEAK_GRAVITY * dt; peaks[i] -= peakVel[i] * dt; if (peaks[i] < levels[i]) peaks[i] = levels[i]; }
      }

      // ---- adaptive beat detection ----
      beatTimer -= dt;
      if (live) {
        let avg = 0; const n = histFilled || 1;
        for (let i = 0; i < n; i++) avg += bassHist[i];
        avg /= n;
        if (histFilled > 12 && bass > avg * BEAT_SENS && bass > BEAT_FLOOR && beatTimer <= 0) {
          beatTimer = BEAT_REFRACTORY;
          const power = Math.max(0, Math.min(1, (bass - avg) * 2.4 + bass * 0.4));
          punch = Math.min(1, 0.6 + power * 0.6);
          flash = Math.min(1, 0.35 + power * 0.5);
          bloom = Math.min(1, 0.5 + power * 0.5);
          drop = Math.min(1, 0.7 + power * 0.4);
          // beat burst: embers erupt upward from across the spectrum
          const bursts = 22 + (power * 46 | 0);
          for (let k = 0; k < bursts; k++) {
            const bi = (Math.random() * N) | 0;
            const bx = sidePad + bi * (barW + gap) + barW * 0.5;
            const by = baseline - Math.max(2 * dpr, levels[bi] * plotH);
            const ang = -Math.PI / 2 + (Math.random() - 0.5) * 1.5;
            const sp = (2.2 + Math.random() * 3.8) * dpr * (0.7 + power);
            const sprite = Math.random() < 0.16 ? 4 : Math.min(3, (bi / N * 4) | 0);
            spawn(bx, by, Math.cos(ang) * sp, Math.sin(ang) * sp, sprite, 1.6 + Math.random() * 2.6, 0.008 + Math.random() * 0.014);
          }
        }
        bassHist[histIdx] = bass; histIdx = (histIdx + 1) % HIST; if (histFilled < HIST) histFilled++;
      }
      punch *= Math.exp(-7 * dt);
      flash *= Math.exp(-11 * dt);
      bloom *= Math.exp(-6 * dt);
      drop += ((live ? bass : 0) - drop) * Math.min(1, 8 * dt);

      // ---- continuous embers from active bars ----
      if (live) {
        for (let i = 0; i < N; i++) {
          const lvl = levels[i];
          if (lvl < 0.18) continue;
          if (Math.random() < (lvl - 0.15) * 0.5 * f) {
            const bx = sidePad + i * (barW + gap) + barW * 0.5 + (Math.random() - 0.5) * barW;
            const by = baseline - lvl * plotH;
            const sprite = Math.random() < 0.10 ? 4 : Math.min(3, (i / N * 4) | 0);
            spawn(bx, by, (Math.random() - 0.5) * 0.6 * dpr, -(0.6 + Math.random() * 1.3) * dpr, sprite, 1.1 + Math.random() * 1.8, 0.006 + Math.random() * 0.012);
          }
        }
      }

      // ---- background ----
      ctx.globalCompositeOperation = 'source-over';
      ctx.fillStyle = bg; ctx.fillRect(0, 0, w, h);

      // droplet-glow swelling up from the baseline centre on the beat
      if (bloom > 0.01) {
        const gr = Math.max(w, h) * (0.18 + bloom * 0.32);
        const rg = ctx.createRadialGradient(w / 2, baseline, 0, w / 2, baseline, gr);
        rg.addColorStop(0, 'rgba(150,120,255,' + (bloom * 0.5) + ')');
        rg.addColorStop(0.5, 'rgba(90,120,255,' + (bloom * 0.16) + ')');
        rg.addColorStop(1, 'rgba(0,0,0,0)');
        ctx.save(); ctx.globalCompositeOperation = 'lighter';
        ctx.fillStyle = rg; ctx.beginPath(); ctx.arc(w / 2, baseline, gr, 0, TAU); ctx.fill();
        ctx.restore();
      }

      // faint dB reference lines
      ctx.strokeStyle = 'rgba(255,255,255,0.05)';
      ctx.lineWidth = 1;
      ctx.beginPath();
      for (let g = 1; g <= 4; g++) { const y = topPad + plotH * (g / 5); ctx.moveTo(sidePad, y); ctx.lineTo(w - sidePad, y); }
      ctx.stroke();

      // ---- build bar + cap paths once ----
      const barsPath = new Path2D();
      const capsPath = new Path2D();
      let x = sidePad;
      const minH = 1.5 * dpr;
      for (let i = 0; i < N; i++) {
        const hgt = Math.max(minH, levels[i] * plotH);
        addBar(barsPath, x, barW, hgt, baseline, radius);
        const py = baseline - Math.max(minH, peaks[i] * plotH) - capH;
        if (peaks[i] > 0.012) capsPath.rect(x, py, barW, capH);
        x += barW + gap;
      }

      // ---- reflection ----
      ctx.save();
      ctx.globalAlpha = 0.16;
      ctx.translate(0, baseline * 2);
      ctx.scale(1, -1);
      ctx.fillStyle = grad;
      ctx.fill(barsPath);
      ctx.restore();
      ctx.fillStyle = fade; ctx.fillRect(0, baseline, w, h - baseline);

      // ---- bars ----
      ctx.fillStyle = grad;
      ctx.fill(barsPath);
      // bloom pass (brightens on the beat), additive, no blur
      ctx.save();
      ctx.globalCompositeOperation = 'lighter';
      ctx.globalAlpha = 0.15 + punch * 0.4;
      ctx.fill(barsPath);
      ctx.restore();

      // ---- peak caps ----
      ctx.fillStyle = 'rgba(240,245,255,0.92)';
      ctx.fill(capsPath);

      // ---- baseline glow line ----
      ctx.save();
      ctx.globalCompositeOperation = 'lighter';
      ctx.strokeStyle = 'rgba(120,160,255,' + (0.32 + punch * 0.4) + ')';
      ctx.lineWidth = (1.5 + punch * 2) * dpr;
      ctx.beginPath(); ctx.moveTo(sidePad, baseline); ctx.lineTo(w - sidePad, baseline); ctx.stroke();
      ctx.restore();

      // ---- beat flash ----
      if (flash > 0.01) {
        ctx.save(); ctx.globalCompositeOperation = 'screen';
        ctx.fillStyle = 'rgba(150,130,255,' + (flash * 0.10) + ')'; ctx.fillRect(0, 0, w, h); ctx.restore();
      }

      // ---- particles (overlay canvas, additive) ----
      pCtx.clearRect(0, 0, particleCanvas.width, particleCanvas.height);
      if (particles.length) {
        const sc = pdpr / dpr, fr = Math.pow(0.985, f), rise = 0.03 * dpr * f;
        pCtx.globalCompositeOperation = 'lighter';
        for (let i = particles.length - 1; i >= 0; i--) {
          const p = particles[i];
          p.x += p.vx * f; p.y += p.vy * f; p.vx *= fr; p.vy = p.vy * fr - rise; // buoyant drift up
          p.life -= p.decay * f;
          if (p.life <= 0) { particles.splice(i, 1); continue; }
          const s = p.size * p.life * pdpr * 3.4;
          pCtx.globalAlpha = p.life * p.life * 0.95;
          pCtx.drawImage(SPRITES[p.s], (p.x * sc) - s, (p.y * sc) - s, s * 2, s * 2);
        }
        pCtx.globalAlpha = 1; pCtx.globalCompositeOperation = 'source-over';
      }
    }

    audio.addEventListener('play', () => { connect(); if (audioCtx && audioCtx.state === 'suspended') audioCtx.resume(); });
    audio.addEventListener('volumechange', () => { if (!audio.muted) connect(); });
    raf = requestAnimationFrame(draw);
    return () => { running = false; cancelAnimationFrame(raf); try { if (audioCtx) audioCtx.close(); } catch (_) { } };
  }

  function setLoading(message) {
    content.innerHTML = '<div class="ld-preview-loading">' + esc(message) + '</div>';
  }
  function setError(message) {
    content.innerHTML = '<div class="ld-preview-error">' + esc(message) + '</div>';
  }
  function loadScript(src) {
    return new Promise((resolve, reject) => {
      const existing = document.querySelector('script[data-ld-pdfjs="' + src + '"]');
      if (existing) {
        if (window.pdfjsLib) resolve(window.pdfjsLib);
        else existing.addEventListener('load', () => resolve(window.pdfjsLib), { once: true });
        return;
      }
      const script = document.createElement('script');
      script.src = src;
      script.async = true;
      script.dataset.ldPdfjs = src;
      script.onload = () => window.pdfjsLib ? resolve(window.pdfjsLib) : reject(new Error('PDF renderer did not initialize.'));
      script.onerror = () => reject(new Error('PDF renderer could not load.'));
      document.head.appendChild(script);
    });
  }
  async function loadPdfJs() {
    if (window.pdfjsLib) return window.pdfjsLib;
    if (pdfJsPromise) return pdfJsPromise;
    pdfJsPromise = (async () => {
      let lastError = null;
      for (const source of pdfSources) {
        try {
          const pdfjs = await loadScript(source.script);
          pdfjs.GlobalWorkerOptions.workerSrc = source.worker;
          return pdfjs;
        } catch (err) {
          lastError = err;
        }
      }
      throw lastError || new Error('PDF renderer unavailable.');
    })();
    return pdfJsPromise;
  }
  function renderDocument(name, payload) {
    const doc = document.createElement('article');
    doc.className = 'ld-preview-doc';
    doc.dataset.zoomMode = 'document';
    const label = (payload.kind === 'docx' ? 'DOCX document' : 'Text document') + (payload.truncated ? ' - Preview truncated' : '');
    doc.innerHTML = '<h3>' + esc(name) + '</h3><div class="ld-preview-doc-meta">' + esc(label) + '</div><pre>' + esc(payload.text || '') + '</pre>';
    activeMedia = doc;
    content.innerHTML = '';
    content.appendChild(doc);
    setZoomEnabled(true);
    setZoom(1);
  }
  async function renderPdfPage(pdf, pageNo, viewer, status, seq) {
    const page = await pdf.getPage(pageNo);
    if (seq !== requestSeq) return;
    const baseWidth = Number(viewer.dataset.baseWidth) || Math.max(260, Math.min(920, content.clientWidth - 36 || 920));
    const firstViewport = page.getViewport({ scale: 1 });
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    const scale = (baseWidth / firstViewport.width) * dpr;
    const viewport = page.getViewport({ scale });
    const wrap = document.createElement('div');
    wrap.className = 'ld-pdf-page';
    const label = document.createElement('div');
    label.className = 'ld-pdf-page-label';
    label.textContent = 'Page ' + pageNo;
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    canvas.width = Math.max(1, Math.floor(viewport.width));
    canvas.height = Math.max(1, Math.floor(viewport.height));
    canvas.style.width = baseWidth + 'px';
    canvas.style.height = Math.round(viewport.height / dpr) + 'px';
    wrap.append(canvas, label);
    viewer.appendChild(wrap);
    await page.render({ canvasContext: ctx, viewport }).promise;
    if (status && seq === requestSeq) status.textContent = 'PDF - ' + pdf.numPages + ' page' + (pdf.numPages === 1 ? '' : 's') + ' - rendered ' + pageNo;
  }
  async function renderPdf(name, url, seq) {
    content.classList.add('document', 'pdf');
    setZoomEnabled(false);
    setLoading('Preparing PDF...');
    try {
      const pdfjs = await loadPdfJs();
      if (seq !== requestSeq) return true;
      const loadingTask = pdfjs.getDocument({ url, disableAutoFetch: false, disableStream: false });
      const pdf = await loadingTask.promise;
      if (seq !== requestSeq) return true;
      const viewer = document.createElement('div');
      viewer.className = 'ld-pdf-pages';
      viewer.dataset.zoomMode = 'pdf';
      viewer.dataset.baseWidth = String(Math.max(260, Math.min(920, content.clientWidth - 36 || 920)));
      viewer.style.width = viewer.dataset.baseWidth + 'px';
      const status = document.createElement('div');
      status.className = 'ld-pdf-status';
      status.textContent = 'PDF - ' + pdf.numPages + ' page' + (pdf.numPages === 1 ? '' : 's') + ' - rendering...';
      viewer.appendChild(status);
      content.innerHTML = '';
      content.appendChild(viewer);
      activeMedia = viewer;
      setZoomEnabled(true);
      setZoom(1);
      for (let pageNo = 1; pageNo <= pdf.numPages; pageNo += 1) {
        if (seq !== requestSeq) return true;
        await renderPdfPage(pdf, pageNo, viewer, status, seq);
      }
      if (status && seq === requestSeq) status.textContent = 'PDF - ' + pdf.numPages + ' page' + (pdf.numPages === 1 ? '' : 's');
    } catch (err) {
      if (seq === requestSeq) {
        setZoomEnabled(false);
        setError('PDF preview could not render here. Use Download to open the full file.');
      }
    }
    return true;
  }
  async function open(name) {
    const type = kind(name);
    if (!type) return false;
    ensure();
    const seq = ++requestSeq;
    stopMedia();
    const url = api.apiBase + '/preview/' + encodeURIComponent(name);
    const dl = api.apiBase + '/download/' + encodeURIComponent(name);
    title.textContent = name;
    download.href = dl;
    download.setAttribute('download', name);
    content.innerHTML = '';
    content.classList.remove('zoomed', 'document', 'pdf', 'media', 'dragging');
    activeMedia = null;
    mediaFrame = null;
    resetPointerState();
    setZoom(1);
    overlay.classList.add('show');

    let node;
    if (type === 'image') {
      node = document.createElement('img');
      node.alt = name;
      node.draggable = false;
      node.onload = () => { if (seq === requestSeq) { updateMediaLayout(anchorFromStageCenter()); setZoom(1); } };
      node.src = url;
      setupMediaViewer(node, { allowUpscale: false });
      setZoomEnabled(true);
    } else if (type === 'video') {
      node = document.createElement('video');
      node.src = url;
      node.controls = true;
      node.playsInline = true;
      node.autoplay = true;
      node.addEventListener('loadedmetadata', () => { if (seq === requestSeq) { updateMediaLayout(anchorFromStageCenter()); setZoom(1); } }, { once: true });
      setupMediaViewer(node, { allowUpscale: true });
      setZoomEnabled(true);
    } else if (type === 'audio') {
      const shell = document.createElement('div');
      shell.className = 'ld-audio-shell';
      const vizWrap = document.createElement('div');
      vizWrap.className = 'ld-audio-viz-wrap';
      const canvas = document.createElement('canvas');
      canvas.className = 'ld-audio-viz';
      const particleCanvas = document.createElement('canvas');
      particleCanvas.className = 'ld-audio-particles';
      vizWrap.append(canvas, particleCanvas);
      node = document.createElement('audio');
      node.src = url;
      node.controls = true;
      node.autoplay = true;
      shell.append(vizWrap, node);
      content.appendChild(shell);
      visualizerStop = startVisualizer(node, canvas, particleCanvas);
      setZoomEnabled(false);
    } else if (type === 'pdf') {
      return await renderPdf(name, url, seq);
    } else if (type === 'document') {
      content.classList.add('document');
      setZoomEnabled(false);
      setLoading('Preparing preview...');
      try {
        const r = await fetch(api.apiBase + '/document-preview/' + encodeURIComponent(name));
        let payload = {};
        try { payload = await r.json(); } catch (_) { payload = {}; }
        if (!r.ok) throw new Error(payload.error || ('Preview failed: HTTP ' + r.status));
        if (seq !== requestSeq) return true;
        renderDocument(name, payload);
      } catch (err) {
        if (seq === requestSeq) {
          setZoomEnabled(false);
          setError(err && err.message ? err.message : 'Preview failed.');
        }
      }
    }
    return true;
  }
  document.addEventListener('click', async e => {
    if (e.target.closest('a,button,input,label,.batch-toolbar')) return;
    const card = e.target.closest('.file-card');
    if (!card) return;
    const cb = card.querySelector('.file-select');
    const name = cb && cb.dataset.name;
    if (!name || !kind(name)) return;
    e.preventDefault();
    await open(name);
  });
})();