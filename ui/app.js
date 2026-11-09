const $=s=>document.querySelector(s);
const extListeners={};
function emitExt(type,data){
  (extListeners[type]||[]).slice().forEach(fn=>{try{fn(data);}catch(e){try{console.error('LiquidDrop extension listener error:',e);}catch(_){}}});
}
const TOKEN=location.pathname.split('/')[1];
const API='/'+TOKEN;
const IMAGE_EXTS=['jpg','jpeg','png','gif','webp','heic','svg','bmp','ico','avif'];
const VIDEO_EXTS=['mp4','mov','avi','mkv','webm','m4v'];
const AUDIO_EXTS=['mp3','wav','m4a','aac','flac','ogg','oga','opus','weba','aiff','wma','mid','midi'];
const CODE_EXTS=['py','pyw','js','mjs','cjs','ts','tsx','jsx','java','c','cc','cpp','cxx','h','hpp','cs','go','rs','php','rb','swift','kt','kts','dart','lua','pl','r','sh','bash','zsh','bat','cmd','ps1','sql','html','htm','css','scss','sass','less','json','xml','yaml','yml','toml','ini','cfg','conf','vue','svelte','ipynb'];
const DOC_EXTS=['pdf','doc','docx','txt','rtf','odt','pages','xls','xlsx','csv','tsv','ppt','pptx','key','numbers','md'];

function copyText(text){
  if(navigator.clipboard&&window.isSecureContext) return navigator.clipboard.writeText(text);
  return new Promise((res,rej)=>{
    const ta=document.createElement('textarea');
    ta.value=text;ta.setAttribute('readonly','');ta.style.position='fixed';ta.style.opacity='0';
    document.body.appendChild(ta);ta.select();
    try{document.execCommand('copy')?res():rej(new Error('copy'));}catch(e){rej(e);}
    ta.remove();
  });
}
$('#urlCopy').addEventListener('click',()=>{
  copyText($('#urlCopy').textContent)
    .then(()=>toast('📋 URL copied!','success'))
    .catch(()=>{});
});

function showShutdownScreen(){
  const screen=$('#shutdownScreen');
  if(!screen) return;
  document.body.style.overflow='hidden';
  $('#confirmOverlay').classList.remove('show');
  $('#zipModal').classList.remove('show');
  screen.classList.add('show');
  waitForServerThenReload();
}
/* When LiquidDrop starts again, pages left open reload themselves, so they
   always run the code of the LiquidDrop that is actually running. */
let comebackTimer=null;
function waitForServerThenReload(){
  if(comebackTimer) return;
  comebackTimer=setInterval(async()=>{
    try{
      const r=await fetch(API+'/status',{cache:'no-store'});
      if(r.ok){clearInterval(comebackTimer);location.reload();}
    }catch(_){}
  },3000);
}
const PAGE_BUILD=(document.querySelector('meta[name="liquiddrop-build"]')||{}).content||'';
let reloadPending=false;
function reloadForUpdate(){
  if(uploadState.batches>0){
    if(!reloadPending) toast('LiquidDrop was updated — refreshing after this upload','success');
    reloadPending=true;
    return;
  }
  location.reload();
}

const stopServerBtn=$('#stopServerBtn');
if(stopServerBtn){
  stopServerBtn.addEventListener('click',()=>{
    showConfirm(
      '⏹️',
      'Stop LiquidDrop',
      'This will stop sharing and disconnect every device using this session.',
      'Stop LiquidDrop',
      'danger',
      async()=>{
        stopServerBtn.disabled=true;
        stopServerBtn.textContent='Shutting down...';
        try{
          const r=await fetch(API+'/shutdown',{method:'POST'});
          if(!r.ok) throw new Error('HTTP '+r.status);
          $('#hostStatusNote').textContent='LiquidDrop has safely shut down.';
          showShutdownScreen();
        } catch(e){
          stopServerBtn.disabled=false;
          stopServerBtn.textContent='⏹ Stop LiquidDrop';
          toast('✗ Shutdown failed','error');
        }
      }
    );
  });
}

const dz=$('#dropzone'),fi=$('#fileInput');
dz.addEventListener('click',()=>fi.click());
fi.addEventListener('change',()=>{
  if(fi.files.length) handleFiles(Array.from(fi.files));
  fi.value='';
});
['dragenter','dragover'].forEach(e=>dz.addEventListener(e,ev=>{
  ev.preventDefault();dz.classList.add('drag-over');
}));
['dragleave','drop'].forEach(e=>dz.addEventListener(e,ev=>{
  ev.preventDefault();dz.classList.remove('drag-over');
}));
dz.addEventListener('drop',ev=>{
  const dt=ev.dataTransfer;
  if(!dt||!dt.files.length) return;
  const files=Array.from(dt.files);
  let folders=0;
  if(dt.items&&dt.items.length===files.length){
    const keep=[];
    for(let i=0;i<files.length;i++){
      const it=dt.items[i];
      const entry=it&&it.webkitGetAsEntry?it.webkitGetAsEntry():null;
      if(entry&&entry.isDirectory) folders++;
      else keep.push(files[i]);
    }
    if(folders) toast(folders===1?'Folders can\'t be sent — zip it first':folders+' folders skipped — zip them first','error');
    if(keep.length) handleFiles(keep);
    return;
  }
  handleFiles(files);
});

const ZIP_THRESHOLD=3;
let pendingFiles=null;

function handleFiles(files){
  if(files.length>=ZIP_THRESHOLD){
    pendingFiles=files;
    $('#modalCount').textContent=files.length;
    $('#zipModal').classList.add('show');
  } else {
    uploadFiles(files);
  }
}

$('#btnZip').addEventListener('click',async()=>{
  $('#zipModal').classList.remove('show');
  if(!pendingFiles) return;
  const f=pendingFiles; pendingFiles=null;
  await uploadFiles(f,{bundle:true});
});
$('#btnSeparate').addEventListener('click',()=>{
  $('#zipModal').classList.remove('show');
  if(!pendingFiles) return;
  const f=pendingFiles; pendingFiles=null;
  uploadFiles(f);
});
$('#zipModal').addEventListener('click',e=>{
  if(e.target===$('#zipModal')){$('#zipModal').classList.remove('show');pendingFiles=null;}
});

function fmtSpeed(bps){
  if(bps<1024) return bps.toFixed(0)+' B/s';
  if(bps<1048576) return(bps/1024).toFixed(0)+' KB/s';
  if(bps<1073741824) return(bps/1048576).toFixed(1)+' MB/s';
  return(bps/1073741824).toFixed(2)+' GB/s';
}

function getFileKind(name){
  const ext=name.includes('.') ? name.split('.').pop().toLowerCase() : '';
  if(IMAGE_EXTS.includes(ext)) return 'image';
  if(VIDEO_EXTS.includes(ext)) return 'video';
  if(AUDIO_EXTS.includes(ext)) return 'audio';
  if(CODE_EXTS.includes(ext)) return 'code';
  if(DOC_EXTS.includes(ext)) return 'document';
  return 'other';
}

const THUMB_EXTS=['jpg','jpeg','jfif','png','gif','webp','bmp'];
function filePreviewMarkup(file){
  const kind=getFileKind(file.name);
  const src=API+'/preview/'+encodeURIComponent(file.name);
  if(kind==='image'){
    const ext=file.name.includes('.')?file.name.split('.').pop().toLowerCase():'';
    const thumb=THUMB_EXTS.includes(ext)
      ? API+'/thumb/'+encodeURIComponent(file.name)+'?v='+file.size+'-'+Math.floor(file.modified||0)
      : src;
    return '<div class="file-preview img-type"><img src="'+thumb+'" data-full="'+src+'" loading="lazy" decoding="async" alt=""></div>';
  }
  if(kind==='video'){
    const pkey=escAttr(file.name+'|'+file.size+'|'+file.modified);
    return '<div class="file-preview vid-type" data-poster-src="'+src+'" data-poster-key="'+pkey+'"><span class="vid-icon">🎬</span></div>';
  }
  if(kind==='audio'){
    return '<div class="file-preview placeholder audio-type"><span>🎵</span></div>';
  }
  if(kind==='code'){
    return '<div class="file-preview placeholder code-type">&lt;/&gt;</div>';
  }
  if(kind==='document'){
    return '<div class="file-preview placeholder doc-type">📄</div>';
  }
  return '<div class="file-preview placeholder">📦</div>';
}

/* Video posters: load one video at a time, grab a frame, then release the
   connection. Paused while uploads run so they always have bandwidth. */
const videoPosterCache=new Map();
const posterQueue=[];
let posterBusy=false;
function hydratePreviewMedia(){
  document.querySelectorAll('.file-preview.vid-type[data-poster-src]:not([data-poster-state])').forEach(el=>{
    const cached=videoPosterCache.get(el.dataset.posterKey);
    if(cached){applyPoster(el,cached);return;}
    el.dataset.posterState='queued';
    posterQueue.push(el);
  });
  pumpPosters();
}
function applyPoster(el,url){
  el.dataset.posterState='done';
  if(!url) return;
  el.style.backgroundImage='url("'+url+'")';
  el.classList.add('has-poster');
}
async function pumpPosters(){
  if(posterBusy) return;
  posterBusy=true;
  try{
    while(posterQueue.length){
      if(uploadState.batches>0||document.hidden){await sleep(1500);continue;}
      const el=posterQueue.shift();
      if(!el.isConnected) continue;
      const key=el.dataset.posterKey;
      let url=videoPosterCache.get(key);
      if(url===undefined){
        url=await grabPoster(el.dataset.posterSrc);
        videoPosterCache.set(key,url);
      }
      applyPoster(el,url);
    }
  } finally {posterBusy=false;}
}
function grabPoster(src){
  return new Promise(resolve=>{
    const v=document.createElement('video');
    let finished=false;
    const finish=url=>{
      if(finished) return;
      finished=true;
      clearTimeout(timer);
      try{v.pause();v.removeAttribute('src');v.load();}catch(_){}
      resolve(url||null);
    };
    const timer=setTimeout(()=>finish(null),8000);
    v.muted=true;v.playsInline=true;v.preload='auto';
    v.setAttribute('muted','');v.setAttribute('playsinline','');
    v.addEventListener('loadedmetadata',()=>{
      try{
        const t=v.duration&&Number.isFinite(v.duration)?Math.min(0.15,v.duration/2):0.1;
        v.currentTime=t;
      }catch(_){finish(null);}
    },{once:true});
    v.addEventListener('seeked',()=>{
      try{
        const w=160,h=Math.max(1,Math.round(w*(v.videoHeight||9)/(v.videoWidth||16)));
        const c=document.createElement('canvas');
        c.width=w;c.height=h;
        c.getContext('2d').drawImage(v,0,0,w,h);
        finish(c.toDataURL('image/jpeg',0.72));
      }catch(_){finish(null);}
    },{once:true});
    v.addEventListener('error',()=>finish(null),{once:true});
    v.src=src;
    try{v.load();}catch(_){}
  });
}

/* ===== Upload engine: parallel, chunked, resumable =====
   Each file goes up in chunks to /uploads/{id}. If the connection drops (phone
   sleeps, Wi-Fi hiccup) the upload resumes from the server's offset. Files
   only appear in the list once complete. */
/* Healthy files stream natively. Recovery uses bounded 8 MiB buffers. */
/* Two files at a time: quick for photo batches, gentle on phone Wi-Fi. */
const UPLOAD_PARALLEL=2;
const DEVICE_ID=(()=>{
  try{
    let d=localStorage.getItem('ld-device');
    if(!d){d=Math.random().toString(36).slice(2,10)+Date.now().toString(36);localStorage.setItem('ld-device',d);}
    return d;
  }catch(e){return Math.random().toString(36).slice(2,12);}
})();
const uploadState={batches:0,total:0,doneBytes:0,files:0,done:0,failed:0,current:'',tasks:new Set(),lastBytes:0,lastTime:0,speed:0};
let uploadTimer=null;

function sleep(ms){return new Promise(r=>setTimeout(r,ms));}
/* Every send gets its own upload id. Ids used to be derived from name + size +
   modified date: photos from the iPhone picker get a new date each time, but
   videos and documents keep theirs, so re-sending one reused the id of an
   earlier attempt and collided with what was left of it on the computer. */
function uploadIdFor(file){
  const s=file.name+'|'+file.size;
  let h=0x811c9dc5;
  for(let i=0;i<s.length;i++) h=Math.imul(h^s.charCodeAt(i),16777619)>>>0;
  const r=Array.from(crypto.getRandomValues?crypto.getRandomValues(new Uint32Array(2)):[Math.random()*4294967296>>>0,Date.now()>>>0])
    .map(n=>n.toString(36)).join('');
  return ('u'+DEVICE_ID+'-'+h.toString(36)+'-'+r).replace(/[^A-Za-z0-9_-]/g,'').slice(0,80);
}
// Bound both the request and response-body read. Aborting fetch alone is not
// sufficient: a suspended browser request may never settle its promise.
function withDeadline(work,ms,onTimeout){
  let timer;
  return Promise.race([
    Promise.resolve().then(work),
    new Promise((_,reject)=>{timer=setTimeout(()=>{
      const e=new Error('Request timed out');e.status=408;
      reject(e);
      if(onTimeout) onTimeout();
    },ms);})
  ]).finally(()=>clearTimeout(timer));
}
async function apiJSON(method,url,body){
  const controller=new AbortController();
  const opts={method,cache:'no-store',signal:controller.signal};
  if(body!==undefined){opts.headers={'Content-Type':'application/json'};opts.body=JSON.stringify(body);}
  return withDeadline(async()=>{
    const r=await fetch(url,opts);
    let data={};
    try{data=await r.json();}catch(e){if(r.ok) throw new Error('Invalid server response');}
    if(!r.ok){const err=new Error(data.error||('HTTP '+r.status));err.status=r.status;err.data=data;throw err;}
    return data;
  },url.includes('/uploads')?UT.requestMs:120000,()=>controller.abort());
}
function retryable(e){
  return !e.status||e.status===408||e.status===409||(e.status>=500&&e.status!==507);
}
/* Stream directly from the file on healthy connections: no JavaScript copy
   and no stop-and-wait request per 8 MiB. If Safari's Files provider stalls,
   switch that file to the bounded in-memory path that works around it. */
const UPLOAD_CHUNK=8*1024*1024;
const UT=Object.assign({stallMs:30000,nativeStallMs:8000,pollMs:3000,slowMs:8000,requestMs:15000,readMs:60000},window.LD_UPLOAD_TIMING||{});
const activeXhrs=new Set();
let uploadKick=0;
function waitOrKick(ms){
  const k=uploadKick,t0=Date.now();
  return new Promise(res=>{
    const iv=setInterval(()=>{if(uploadKick!==k||Date.now()-t0>=ms){clearInterval(iv);res();}},200);
  });
}
async function serverOffset(id){
  const st=await apiJSON('GET',API+'/uploads/'+encodeURIComponent(id));
  return Number(st.offset)||0;
}
async function sendFrom(id,file,offset,task){
  const end=task.buffered?Math.min(file.size,offset+UPLOAD_CHUNK):file.size;
  let body=offset===0&&!task.buffered?file:file.slice(offset,end);
  if(task.buffered){
    task.state='reading';
    try{body=await withDeadline(()=>body.arrayBuffer(),UT.readMs);}
    catch(e){e.unreadable=true;throw e;}
  }
  task.state='sending';
  return new Promise((res,rej)=>{
    const xhr=new XMLHttpRequest();
    activeXhrs.add(xhr);
    let settled=false,reason='',lastGrowth=Date.now(),clientLoaded=0,serverSeen=offset,polling=false;
    const succeed=d=>{if(settled) return;settled=true;cleanup();res(d);};
    const fail=e=>{if(settled) return;settled=true;cleanup();rej(e);};
    const pollOffset=async()=>{
      if(polling||settled||document.hidden) return;
      polling=true;
      try{
        const so=await serverOffset(id);
        if(settled) return;
        if(so>=end){succeed({offset:end});xhr.abort();return;}
        if(so>serverSeen){serverSeen=so;lastGrowth=Date.now();task.serverBytes=so-offset;}
      }catch(_){}finally{polling=false;}
    };
    const poll=setInterval(()=>{
      if(document.hidden){lastGrowth=Date.now();return;}
      pollOffset();
      task.quietMs=Date.now()-lastGrowth;
      const deadline=task.buffered?UT.stallMs:Math.min(UT.stallMs,UT.nativeStallMs);
      if(task.quietMs>deadline){reason='stalled';const e=new Error(reason);e.stallReason=reason;fail(e);xhr.abort();}
    },UT.pollMs);
    const cleanup=()=>{clearInterval(poll);activeXhrs.delete(xhr);task.quietMs=0;};
    xhr.open('PUT',API+'/uploads/'+encodeURIComponent(id)+'?offset='+offset);
    xhr.upload.onprogress=e=>{
      if(settled) return;
      if(e.loaded>clientLoaded){clientLoaded=e.loaded;lastGrowth=Date.now();}
      task.clientBytes=e.loaded;
      task.state='sending';
    };
    xhr.upload.onload=()=>pollOffset();
    xhr.onload=()=>{
      let d={};
      try{d=JSON.parse(xhr.responseText||'{}');}catch(e){}
      if(xhr.status===200){
        if(!Number.isSafeInteger(d.offset)||d.offset<=offset||d.offset>end) fail(new Error('Invalid upload offset'));
        else succeed(d);
      }
      else{const err=new Error(d.error||('HTTP '+xhr.status));err.status=xhr.status;err.data=d;fail(err);}
    };
    xhr.onerror=()=>fail(new Error('Network error'));
    xhr.onabort=()=>{const err=new Error(reason||'retry');err.stallReason=reason||'manual';fail(err);};
    try{xhr.send(body);}catch(e){fail(e);}
  });
}
async function uploadOne(file,task){
  const id=uploadIdFor(file);
  task.state='starting';task.attempt=0;
  let start=null,attempt=0;
  while(!start){
    try{start=await apiJSON('POST',API+'/uploads',{id,name:file.name,size:file.size});}
    catch(e){
      if(!retryable(e)||++attempt>8) throw e;
      task.state='reconnecting';task.attempt=attempt;
      await waitOrKick(Math.min(10000,600*2**attempt));
    }
  }
  let offset=Number(start.offset)||0;
  attempt=0;
  while(true){
    while(offset<file.size){
      task.confirmed=offset;task.clientBytes=0;task.serverBytes=0;
      task.state='sending';
      try{
        const d=await sendFrom(id,file,offset,task);
        offset=Number(d.offset);
        attempt=0;task.attempt=0;
      }catch(e){
        if(!retryable(e)) throw e;
        if(++attempt>12) throw e;
        const fallback=!task.buffered&&e.stallReason!=='manual';
        if(fallback) task.buffered=true;
        task.state='reconnecting';task.attempt=attempt;
        if(!fallback&&e.stallReason!=='manual') await waitOrKick(Math.min(8000,400*2**attempt));
        try{offset=await serverOffset(id);}catch(_){}
      }
      task.confirmed=offset;task.clientBytes=0;task.serverBytes=0;
    }
    task.state='finishing';
    try{return await apiJSON('POST',API+'/uploads/'+encodeURIComponent(id)+'/complete');}
    catch(e){
      // The computer is missing part of the file: send the rest.
      if(e.status===409&&e.data&&typeof e.data.offset==='number'&&e.data.offset<file.size){
        offset=e.data.offset;continue;
      }
      if(!retryable(e)||++attempt>12) throw e;
      task.state='reconnecting';task.attempt=attempt;
      await waitOrKick(800*attempt);
    }
  }
}
/* Tap the upload bar to retry anything that looks stuck right now. */
$('#uploadBar').addEventListener('click',()=>{
  if(!uploadState.batches) return;
  uploadKick++;
  let n=0;
  activeXhrs.forEach(x=>{try{x.abort();n++;}catch(_){}} );
  toast(n?'↻ Retrying now':'↻ Reconnecting','success');
});
function uploadedBytes(){
  let s=uploadState.doneBytes;
  uploadState.tasks.forEach(t=>{s+=(t.confirmed||0)+Math.max(t.clientBytes||0,t.serverBytes||0);});
  return s;
}
function renderUploadUI(){
  const pct=$('#uploadPct'),fill=$('#progressFill'),name=$('#uploadName'),spd=$('#uploadSpeed');
  const sent=uploadedBytes(),total=Math.max(1,uploadState.total);
  const p=Math.min(uploadState.batches?99:100,Math.floor(sent/total*100));
  pct.textContent=p+'%';fill.style.width=p+'%';
  const n=uploadState.files;
  name.textContent=n>1?('Sending '+Math.min(uploadState.done+uploadState.failed+1,n)+' of '+n+' · '+uploadState.current):uploadState.current;
  const now=performance.now();
  if(sent!==uploadState.lastSeen){uploadState.lastSeen=sent;uploadState.lastMove=now;}
  const dt=(now-uploadState.lastTime)/1000;
  if(dt>=0.5){
    const inst=Math.max(0,(sent-uploadState.lastBytes)/dt);
    uploadState.speed=uploadState.speed?uploadState.speed*0.6+inst*0.4:inst;
    uploadState.lastBytes=sent;uploadState.lastTime=now;
  }
  /* Never show a silent "0 B/s": say what is happening. */
  let reconnecting=null,finishing=false,reading=false;
  uploadState.tasks.forEach(t=>{
    if(t.state==='reconnecting'&&(!reconnecting||t.attempt>reconnecting.attempt)) reconnecting=t;
    if(t.state==='finishing') finishing=true;
    if(t.state==='reading') reading=true;
  });
  let quiet=0;
  uploadState.tasks.forEach(t=>{quiet=Math.max(quiet,t.quietMs||0);});
  const idleMs=Math.min(now-(uploadState.lastMove||now),quiet||Infinity);
  let t;
  if(reconnecting){
    t='↻ Connection dropped — resuming'+(reconnecting.attempt>1?' (try '+reconnecting.attempt+')':'')+' · tap to retry now';
  } else if(reading&&uploadState.speed<1024){
    t='Reading file on this device…';
  } else if(idleMs>UT.slowMs&&!finishing){
    t='Connection is slow — still trying ('+Math.round(idleMs/1000)+'s) · tap to retry now';
  } else if(finishing&&uploadState.speed<1024){
    t='Saving on the computer…';
  } else if(uploadState.speed>=1024){
    t=fmtSpeed(uploadState.speed);
    const rem=(total-sent)/uploadState.speed;
    if(rem>1&&rem<360000) t+=' · ~'+(rem>90?Math.ceil(rem/60)+'m':Math.ceil(rem)+'s')+' left';
    if(n>1) t+=' · '+fmtSize(sent)+' / '+fmtSize(total);
  } else {
    t='Starting…';
  }
  spd.textContent=t;
  $('#uploadBar').classList.toggle('stalled',!!reconnecting||idleMs>UT.slowMs);
}
function startUploadUI(){
  $('#uploadBar').classList.add('active');
  if(!uploadTimer){
    uploadState.lastTime=performance.now();uploadState.lastBytes=uploadedBytes();uploadState.speed=0;
    uploadState.lastMove=performance.now();uploadState.lastSeen=uploadedBytes();
    $('#uploadSpeed').textContent='Starting...';
    uploadTimer=setInterval(renderUploadUI,250);
  }
  renderUploadUI();
}
function finishUploadUI(){
  if(uploadState.batches>0) return;
  clearInterval(uploadTimer);uploadTimer=null;
  $('#uploadBar').classList.remove('stalled');
  $('#uploadPct').textContent=uploadState.failed?(uploadState.failed+' failed'):'100%';
  $('#progressFill').style.width=uploadState.failed?'0%':'100%';
  $('#uploadSpeed').textContent=uploadState.failed?'Send failed files again':'Saved on the computer';
  setTimeout(()=>{if(uploadState.batches===0) $('#uploadBar').classList.remove('active');},800);
  Object.assign(uploadState,{total:0,doneBytes:0,files:0,done:0,failed:0,current:'',speed:0});
}
async function uploadFiles(files,opts){
  opts=opts||{};
  files=Array.from(files||[]).filter(f=>f&&typeof f.size==='number');
  if(!files.length) return [];
  uploadState.batches++;
  uploadState.total+=files.reduce((a,f)=>a+f.size,0);
  uploadState.files+=files.length;
  uploadState.current=files[0].name;
  startUploadUI();
  const queue=files.slice(),names=[];
  let failed=0;
  const worker=async()=>{
    while(queue.length){
      const file=queue.shift();
      const task={confirmed:0,clientBytes:0,serverBytes:0,quietMs:0};
      uploadState.tasks.add(task);
      uploadState.current=file.name;
      try{
        const res=await uploadOne(file,task);
        names.push(res.name);
        uploadState.done++;
      }catch(e){
        failed++;uploadState.failed++;
        toast(e&&e.unreadable
          ? '✗ '+file.name+' can\'t be read anymore — pick it again'
          : (e&&e.status===507
            ? '✗ Not enough space on the computer for '+file.name
            : '✗ '+file.name+' failed'),'error');
      }
      uploadState.tasks.delete(task);
      uploadState.doneBytes+=file.size;
    }
  };
  const workers=[];
  for(let i=0;i<Math.min(UPLOAD_PARALLEL,files.length);i++) workers.push(worker());
  await Promise.all(workers);
  if(opts.bundle&&names.length>1){
    $('#uploadSpeed').textContent='Bundling into a zip...';
    try{
      await apiJSON('POST',API+'/bundle',{names});
      toast('✓ '+names.length+' files zipped & sent','success');
    }catch(e){toast('✗ Zip failed — files were sent separately','error');}
  } else if(!failed){
    toast(files.length===1?('✓ '+files[0].name+' sent'):('✓ '+files.length+' files sent'),'success');
  } else if(names.length){
    toast('Sent '+names.length+' of '+files.length+' files','error');
  }
  uploadState.batches--;
  finishUploadUI();
  if(reloadPending&&uploadState.batches===0) setTimeout(()=>location.reload(),1200);
  loadFiles();
  return names;
}
window.addEventListener('beforeunload',e=>{
  if(uploadState.batches>0){e.preventDefault();e.returnValue='';}
});

/* ===== File list with selection state preserved across refreshes ===== */
let lastHash='',selectedFiles=new Set(),firstFileRender=true;

function fileCardMarkup(f,delay){
  const dn=f.name.replace(/&/g,'&amp;').replace(/"/g,'&quot;');
  return '<div class="file-card glass" style="animation-delay:'+delay+'s">'+
    '<input type="checkbox" class="file-checkbox file-select" data-name="'+dn+'">'+
    filePreviewMarkup(f)+
    '<div class="file-meta"><div class="file-name">'+esc(f.name)+'</div><div class="file-detail"></div></div>'+
    '<button class="file-delete" data-name="'+dn+'" title="Delete">✕</button>'+
    '<a href="'+API+'/download/'+encodeURIComponent(f.name)+'" download class="file-dl" title="Download">↓</a></div>';
}
function renderFileList(files){
  const list=$('#fileList');
  const empty=list.querySelector('.empty-state');
  if(empty) empty.remove();
  const existing=new Map();
  list.querySelectorAll('.file-card[data-key]').forEach(el=>existing.set(el.dataset.key,el));
  const tmp=document.createElement('div');
  const ordered=files.map((f,i)=>{
    const key=JSON.stringify([f.name,f.size,f.modified]);
    let el=existing.get(key);
    if(el){existing.delete(key);}
    else{
      tmp.innerHTML=fileCardMarkup(f,firstFileRender?Math.min(i,12)*0.06:0);
      el=tmp.firstElementChild;
      el.dataset.key=key;
      el.addEventListener('animationend',()=>el.classList.add('settled'),{once:true});
    }
    el.dataset.size=f.size;el.dataset.modified=f.modified;
    const cb=el.querySelector('.file-select');
    if(cb) cb.checked=selectedFiles.has(f.name);
    const det=el.querySelector('.file-detail');
    if(det) det.textContent=fmtSize(f.size)+' · '+fmtTime(f.modified);
    return el;
  });
  existing.forEach(el=>el.remove());
  ordered.forEach((el,i)=>{
    if(list.children[i]!==el) list.insertBefore(el,list.children[i]||null);
  });
  firstFileRender=false;
}
function refreshFileTimes(){
  document.querySelectorAll('#fileList .file-card[data-key]').forEach(el=>{
    const det=el.querySelector('.file-detail');
    if(det) det.textContent=fmtSize(Number(el.dataset.size))+' · '+fmtTime(Number(el.dataset.modified));
  });
}
let isBusy=false;  /* guard to prevent loadFiles from clobbering mid-action */

async function loadFiles(){
  if(isBusy) return;  /* skip refresh while batch action is in progress */
  try{
    const r=await fetch(API+'/files',{cache:'no-store'});
    if(!r.ok) return;
    const files=await r.json();
    const hash=JSON.stringify(files.map(f=>f.name+f.size+f.modified));
    if(hash===lastHash) return;
    lastHash=hash;

    const list=$('#fileList');

    /* Prune selected names that no longer exist on disk */
    const existingNames=new Set(files.map(f=>f.name));
    for(const n of [...selectedFiles]){
      if(!existingNames.has(n)) selectedFiles.delete(n);
    }

    if(!files.length){
      selectedFiles.clear();
      list.innerHTML='<div class="empty-state"><span>🌊</span>No files yet — drop something!</div>';
      updateBatchUI();
      emitExt('files',files);
      return;
    }
    renderFileList(files);
    hydratePreviewMedia();
    updateBatchUI();
    emitExt('files',files);
  } catch(e){/* network hiccup — silently retry next interval */}
}

/* Thumbnail failed (unsupported or thumbnails disabled): show the original. */
$('#fileList').addEventListener('error',e=>{
  const img=e.target;
  if(img&&img.tagName==='IMG'&&img.dataset.full&&!img.dataset.fellBack){
    img.dataset.fellBack='1';img.src=img.dataset.full;
  }
},true);

/* ===== Event delegation for the file list ===== */
$('#fileList').addEventListener('click',e=>{
  /* Delete button */
  const del=e.target.closest('.file-delete');
  if(del){
    e.preventDefault();e.stopPropagation();
    const n=del.dataset.name;
    showConfirm('🗑️','Delete File','Delete <strong>'+esc(n)+'</strong>?<br>This cannot be undone.','Delete','danger',()=>{
      apiJSON('DELETE',API+'/delete/'+encodeURIComponent(n))
        .then(()=>{toast('🗑️ Deleted','success');selectedFiles.delete(n);lastHash='';loadFiles();})
        .catch(e=>toast('✗ '+(e.status===409?'File is in use on the computer':'Delete failed'),'error'));
    });
    return;
  }
  /* Checkbox toggle */
  const cb=e.target.closest('.file-select');
  if(cb){
    if(cb.checked) selectedFiles.add(cb.dataset.name);
    else selectedFiles.delete(cb.dataset.name);
    updateBatchUI();
    return;
  }
});

$('#selectAll').addEventListener('change',e=>{
  document.querySelectorAll('.file-select').forEach(cb=>{
    cb.checked=e.target.checked;
    if(e.target.checked) selectedFiles.add(cb.dataset.name);
    else selectedFiles.delete(cb.dataset.name);
  });
  updateBatchUI();
});

function updateBatchUI(){
  const boxes=document.querySelectorAll('.file-select');
  const count=selectedFiles.size;
  $('#selectedCount').textContent=count;

  if(boxes.length>0){
    $('#batchToolbar').classList.add('show');
  } else {
    $('#batchToolbar').classList.remove('show');
  }

  /* Sync the "Select All" checkbox — supports indeterminate state */
  const sa=$('#selectAll');
  sa.checked = boxes.length>0 && count===boxes.length;
  sa.indeterminate = count>0 && count<boxes.length;

  const hasSelection = count>0;
  ['#batchDeleteBtn','#batchDownloadBtn'].forEach(s=>{
    $(s).style.opacity=hasSelection?'1':'0.3';
    $(s).style.pointerEvents=hasSelection?'auto':'none';
  });
}

/* ===== Batch delete ===== */
$('#batchDeleteBtn').addEventListener('click',()=>{
  if(!selectedFiles.size) return;
  const c=selectedFiles.size;
  showConfirm(
    '⚠️',
    'Delete '+c+' File'+(c>1?'s':''),
    'Are you sure you want to delete <strong>'+c+'</strong> file'+(c>1?'s':'')+'?<br>This cannot be undone.',
    'Delete All','danger',
    async()=>{
      isBusy=true;
      const names=[...selectedFiles];
      let ok=0;
      const failed=new Set();
      for(const n of names){
        try{
          await apiJSON('DELETE',API+'/delete/'+encodeURIComponent(n));
          ok++;
        } catch(e){failed.add(n);}
      }
      selectedFiles=failed;
      isBusy=false;
      lastHash='';
      loadFiles();
      if(failed.size) toast('Deleted '+ok+' · '+failed.size+' still in use on the computer','error');
      else toast('🗑️ Deleted '+ok+' file'+(ok!==1?'s':''),'success');
    }
  );
});

/* ===== Batch download — intentionally preserves selection afterward ===== */
$('#batchDownloadBtn').addEventListener('click',()=>{
  if(!selectedFiles.size) return;
  const c=selectedFiles.size;
  showConfirm(
    '📥',
    'Download '+c+' File'+(c>1?'s':''),
    'Download <strong>'+c+'</strong> selected file'+(c>1?'s':'')+'?',
    'Download','action',
    async()=>{
      const names=[...selectedFiles];
      const trigger=(href,name)=>{
        const a=document.createElement('a');
        a.href=href;a.download=name||'';
        document.body.appendChild(a);a.click();a.remove();
      };
      if(names.length===1){
        trigger(API+'/download/'+encodeURIComponent(names[0]),names[0]);
        toast('✓ Downloading '+names[0],'success');
        return;
      }
      try{
        const t=await apiJSON('POST',API+'/zip-ticket',{names});
        trigger(t.url,t.name);
        toast('📦 Downloading '+t.count+' files as one zip ('+fmtSize(t.size)+')','success');
      }catch(e){
        toast('✗ Download failed','error');
      }
      /* Selection is intentionally preserved so the user can still
         click Delete to remove the same batch after downloading. */
    }
  );
});

/* ===== Confirm dialog ===== */
let confirmCb=null;
function showConfirm(icon,title,msg,okText,okClass,cb){
  $('#confirmIcon').textContent=icon;
  $('#confirmTitle').textContent=title;
  $('#confirmMessage').innerHTML=msg;
  const ok=$('#confirmOk');
  ok.textContent=okText;
  ok.className='confirm-btn '+okClass;
  confirmCb=cb;
  $('#confirmOverlay').classList.add('show');
}
$('#confirmCancel').addEventListener('click',()=>{
  $('#confirmOverlay').classList.remove('show');confirmCb=null;
});
$('#confirmOk').addEventListener('click',()=>{
  $('#confirmOverlay').classList.remove('show');
  if(confirmCb){const fn=confirmCb;confirmCb=null;fn();}
});
$('#confirmOverlay').addEventListener('click',e=>{
  if(e.target===$('#confirmOverlay')){$('#confirmOverlay').classList.remove('show');confirmCb=null;}
});

/* ===== Utility ===== */
function fmtSize(b){
  if(b<1024) return b+' B';
  if(b<1048576) return(b/1024).toFixed(1)+' KB';
  if(b<1073741824) return(b/1048576).toFixed(1)+' MB';
  return(b/1073741824).toFixed(2)+' GB';
}
function fmtTime(t){
  const d=new Date(t*1000),diff=(Date.now()-d)/1000;
  if(diff<60) return 'Just now';
  if(diff<3600) return Math.floor(diff/60)+'m ago';
  if(diff<86400) return Math.floor(diff/3600)+'h ago';
  return d.toLocaleDateString();
}
function esc(s){const d=document.createElement('div');d.textContent=s;return d.innerHTML;}
function toast(m,t='success'){
  const e=$('#toast');e.textContent=m;
  e.className='toast '+t+' show';
  clearTimeout(e._t);
  e._t=setTimeout(()=>e.classList.remove('show'),2500);
}


/* ===== Extension manager and runtime ===== */
let extensionPayload={extensions:[],can_manage:false,developer_dir:''};
let extensionConfigId=null;
let extensionCreateIdTouched=false;
const loadedExtensionAssets=new Set();
const extensionRuntimeState={};
const extensionAssetToId=new Map();

/* esc() only escapes & < >, so attributes also need both quote characters escaped. */
function escAttr(s){return esc(String(s)).replace(/"/g,'&quot;').replace(/'/g,'&#39;');}

function switchAppTab(tab){
  const showExtensions=tab==='extensions';
  document.querySelectorAll('#appTabs .tab-btn').forEach(btn=>{
    btn.classList.toggle('active',btn.dataset.tab===tab);
  });
  $('#filesTabUpload').classList.toggle('tab-hidden',showExtensions);
  $('#filesTabList').classList.toggle('tab-hidden',showExtensions);
  $('#extensionsTabPanel').classList.toggle('tab-hidden',!showExtensions);
  if(showExtensions) loadExtensions(false);
}

document.querySelectorAll('#appTabs .tab-btn').forEach(btn=>{
  btn.addEventListener('click',()=>switchAppTab(btn.dataset.tab));
});

function markExtensionRuntime(id,status,message){
  if(!id) return;
  extensionRuntimeState[id]={status,message:message||'',at:new Date().toISOString()};
  if((extensionPayload.extensions||[]).length) renderExtensions();
}

function rememberExtensionAsset(url,id){
  if(!url||!id) return;
  extensionAssetToId.set(url,id);
  try{extensionAssetToId.set(new URL(url,location.href).href,id);}catch(e){}
}

function extensionIdForSource(src){
  src=String(src||'');
  if(!src) return '';
  for(const [url,id] of extensionAssetToId.entries()){
    if(src===url||src.endsWith(url)) return id;
  }
  return '';
}

window.addEventListener('error',e=>{
  const id=extensionIdForSource(e.filename||'');
  if(id){
    const bits=[];
    if(e.message) bits.push(e.message);
    if(e.lineno) bits.push('line '+e.lineno+(e.colno?':'+e.colno:''));
    markExtensionRuntime(id,'error',bits.join(' at ')||'Script error');
  }
},true);

window.LiquidDropExtensions={
  version:'1.1.0',
  apiBase:API,
  canManage(){return !!extensionPayload.can_manage;},
  /* Live events: 'files', 'status', 'settings' ({id}), 'state' ({id}),
     'extensions', 'network', 'live' ({connected}). Returns an unsubscribe fn. */
  on(type,fn){
    if(typeof fn!=='function') return ()=>{};
    (extListeners[type]=extListeners[type]||[]).push(fn);
    return ()=>{const l=extListeners[type]||[];const i=l.indexOf(fn);if(i>=0) l.splice(i,1);};
  },
  isLive(){return liveConnected;},
  getStatus(){return lastStatus;},
  downloadUrl(name){return API+'/download/'+encodeURIComponent(name);},
  previewUrl(name){return API+'/preview/'+encodeURIComponent(name);},
  thumbnailUrl(name){return API+'/thumb/'+encodeURIComponent(name);},
  async uploadFiles(files){return await uploadFiles(files);},
  registerPanel(){return null;},
  unregisterPanel(){},
  async getSettings(id){
    const r=await fetch(API+'/extensions/'+encodeURIComponent(id)+'/settings');
    if(!r.ok) throw new Error('Settings failed: '+r.status);
    const data=await r.json();
    return data.settings||{};
  },
  async saveSettings(id,settings){
    const r=await fetch(API+'/extensions/'+encodeURIComponent(id)+'/settings',{
      method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({settings})
    });
    if(!r.ok) throw new Error('Save settings failed: '+r.status);
    const data=await r.json();
    return data.settings||{};
  },
  async getSharedState(id){
    const r=await fetch(API+'/extensions/'+encodeURIComponent(id)+'/state',{cache:'no-store'});
    if(!r.ok) throw new Error('Shared state failed: '+r.status);
    const data=await r.json();
    return data.state||{};
  },
  async setSharedState(id,state){
    const r=await fetch(API+'/extensions/'+encodeURIComponent(id)+'/state',{
      method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({state:state||{}})
    });
    if(!r.ok) throw new Error('Save shared state failed: '+r.status);
    const data=await r.json();
    return data.state||{};
  },
  async uploadAsset(id,file){
    const fd=new FormData();fd.append('file',file);
    const r=await fetch(API+'/extension-asset/'+encodeURIComponent(id),{method:'POST',body:fd});
    if(!r.ok) throw new Error('Asset upload failed: '+r.status);
    return await r.json();
  },
  async uploadFile(file,displayName){
    const names=await uploadFiles([file]);
    lastHash='';
    await loadFiles();
    return names.length>0;
  },
  async listFiles(){
    const r=await fetch(API+'/files');
    if(!r.ok) return [];
    return await r.json();
  },
  getSelectedFiles(){return [...selectedFiles];},
  reportError(id,error){
    const message=(error&&error.message)?error.message:String(error||'Unknown add-on error');
    markExtensionRuntime(id,'error',message);
    try{console.error('LiquidDrop extension error:',id,error);}catch(e){}
  },
  toast,
  escapeHtml:esc,
  formatSize:fmtSize
};

async function loadExtensions(loadAssets){
  try{
    const r=await fetch(API+'/extensions');
    if(!r.ok) throw new Error('HTTP '+r.status);
    extensionPayload=await r.json();
    renderExtensions();
    if(loadAssets) loadEnabledExtensionAssets(extensionPayload.extensions||[]);
  } catch(e){
    $('#extensionList').innerHTML='<div class="extension-empty">Extensions could not be loaded.</div>';
  }
}

function loadEnabledExtensionAssets(exts){
  exts.filter(e=>e.installed&&e.enabled&&e.client).forEach(ext=>{
    if(ext.client.style_url&&!loadedExtensionAssets.has(ext.client.style_url)){
      loadedExtensionAssets.add(ext.client.style_url);
      rememberExtensionAsset(ext.client.style_url,ext.id);
      const link=document.createElement('link');
      link.rel='stylesheet';link.href=ext.client.style_url;
      link.onerror=()=>markExtensionRuntime(ext.id,'error','Stylesheet failed to load');
      document.head.appendChild(link);
    }
    if(ext.client.script_url&&!loadedExtensionAssets.has(ext.client.script_url)){
      loadedExtensionAssets.add(ext.client.script_url);
      rememberExtensionAsset(ext.client.script_url,ext.id);
      markExtensionRuntime(ext.id,'loading','Loading client script');
      const script=document.createElement('script');
      script.src=ext.client.script_url;
      script.defer=true;
      script.onload=()=>{
        const current=extensionRuntimeState[ext.id];
        if(!current||current.status!=='error') markExtensionRuntime(ext.id,'loaded','Client script loaded');
      };
      script.onerror=()=>{
        markExtensionRuntime(ext.id,'error','Client script failed to load');
        toast('Extension failed: '+ext.name,'error');
      };
      document.body.appendChild(script);
    }
  });
}

function shortDate(value){
  if(!value) return '';
  const d=new Date(value);
  if(Number.isNaN(d.getTime())) return String(value).slice(0,10);
  return d.toLocaleDateString(undefined,{year:'numeric',month:'short',day:'numeric'});
}

function extensionStatusBadge(ext){
  const health=ext.health||{};
  const runtime=extensionRuntimeState[ext.id]||{};
  if(runtime.status==='error'||health.status==='error') return '<span class="extension-badge warn">Error</span>';
  if(runtime.status==='loading') return '<span class="extension-badge warn">Loading</span>';
  if(runtime.status==='loaded') return '<span class="extension-badge on">Loaded</span>';
  if(ext.installed&&ext.enabled) return '<span class="extension-badge on">Ready</span>';
  return ext.installed?'<span class="extension-badge off">Off</span>':'<span class="extension-badge off">Not installed</span>';
}

function extensionDiagnostics(ext){
  const health=ext.health||{};
  const runtime=extensionRuntimeState[ext.id]||{};
  const messages=[];
  (health.messages||[]).forEach(m=>messages.push(m));
  if(runtime.status==='error'&&runtime.message) messages.push(runtime.message);
  if(!messages.length&&health.safety&&health.safety.messages&&health.safety.messages[0]) messages.push(health.safety.messages[0]);
  if(!messages.length) return '';
  const cls=(runtime.status==='error'||health.status==='error')?' extension-diagnostics error':' extension-diagnostics';
  return '<div class="'+cls.trim()+'">'+messages.map(esc).join('<br>')+'</div>';
}

function renderExtensions(){
  const list=$('#extensionList');
  const exts=extensionPayload.extensions||[];
  const canManage=!!extensionPayload.can_manage;
  $('#installExtensionBtn').disabled=!canManage;
  $('#createExtensionBtn').disabled=!canManage;
  $('#openExtensionsFolderBtn').disabled=!canManage;
  $('#extensionTrustNote').textContent=canManage
    ? 'Create starter add-ons, open the add-on folder, install trusted JSON files, and manage settings that sync across devices.'
    : 'Extension management is available only from the host computer. Enabled add-ons and shared state still sync to this device.';
  if(!exts.length){
    list.innerHTML='<div class="extension-empty">No extensions found. Add one in '+esc(extensionPayload.developer_dir||'~/LiquidDrop/extensions')+'.</div>';
    return;
  }
  list.innerHTML=exts.map(ext=>{
    const installed=!!ext.installed,enabled=!!ext.enabled,health=ext.health||{};
    const caps=(ext.capabilities||[]).map(c=>'<span class="extension-badge">'+esc(c)+'</span>').join('');
    const sourceBadge=ext.builtin?'<span class="extension-badge">Bundled</span>':'<span class="extension-badge warn">User</span>';
    const safety=health.safety||{};
    const safetyBadge='<span class="extension-badge '+(health.safe?'on':'warn')+'">'+esc(safety.label||'Safety check')+'</span>';
    const version=ext.version?'<span class="extension-badge">v'+esc(ext.version)+'</span>':'';
    const statusBadge=extensionStatusBadge(ext);
    const disabled=canManage?'':'disabled';
    const fatalManifestError=health.status==='error'&&!installed;
    const settingsBtn=installed&&(ext.settings_schema||[]).length?'<button class="ext-btn" data-ext-action="configure" data-ext-id="'+escAttr(ext.id)+'" '+disabled+'>Configure</button>':'';
    const controls=fatalManifestError
      ? '<button class="ext-btn" disabled>Fix Manifest</button>'
      : (installed
        ? '<button class="ext-btn" data-ext-action="toggle" data-ext-id="'+escAttr(ext.id)+'" '+disabled+'>'+(enabled?'Turn Off':'Turn On')+'</button>'+settingsBtn+'<button class="ext-btn danger" data-ext-action="uninstall" data-ext-id="'+escAttr(ext.id)+'" '+disabled+'>Uninstall</button>'
        : '<button class="ext-btn primary" data-ext-action="install" data-ext-id="'+escAttr(ext.id)+'" '+disabled+'>Install</button>');
    const author=ext.author?('By '+ext.author):'Creator unknown';
    const updated=shortDate(ext.updated_at||ext.created_at);
    const created=shortDate(ext.created_at);
    const details=[author,updated?('Updated '+updated):(created?('Created '+created):''),ext.license||'Creator retains rights'].filter(Boolean).map(esc).join(' &middot; ');
    const path=canManage&&ext.path?'<div class="extension-submeta">'+esc(ext.path)+'</div>':'';
    return '<article class="extension-card">'+
      '<div class="extension-card-head"><div><h3>'+esc(ext.name)+'</h3><p>'+esc(ext.description||'No description provided.')+'</p></div>'+statusBadge+'</div>'+
      '<div class="extension-submeta">'+details+'</div>'+path+
      '<div class="extension-meta">'+sourceBadge+version+safetyBadge+caps+'</div>'+extensionDiagnostics(ext)+
      '<div class="extension-actions">'+controls+'</div>'+
      '</article>';
  }).join('');
}

$('#extensionList').addEventListener('click',async e=>{
  const btn=e.target.closest('[data-ext-action]');
  if(!btn||btn.disabled) return;
  const id=btn.dataset.extId;
  const action=btn.dataset.extAction;
  const ext=(extensionPayload.extensions||[]).find(x=>x.id===id);
  if(!ext) return;
  if(action==='configure'){openExtensionConfig(ext);return;}
  const run=async()=>{
    btn.disabled=true;
    try{
      let url=API+'/extensions/'+encodeURIComponent(id)+'/'+action;
      let body={};
      if(action==='toggle'){
        url=API+'/extensions/'+encodeURIComponent(id)+'/enable';
        body={enabled:!ext.enabled};
      }
      const r=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
      if(!r.ok) throw new Error('HTTP '+r.status);
      toast('Extension updated','success');
      setTimeout(()=>location.reload(),450);
    } catch(err){
      btn.disabled=false;
      toast('Extension action failed','error');
    }
  };
  if(action==='uninstall'){
    showConfirm('!','Uninstall Extension','Uninstall <strong>'+esc(ext.name)+'</strong>?', 'Uninstall','danger',run);
  } else {
    run();
  }
});

function openExtensionConfig(ext){
  extensionConfigId=ext.id;
  $('#extensionConfigTitle').textContent='Configure '+ext.name;
  $('#extensionConfigDescription').textContent=ext.description||'Adjust extension settings.';
  const form=$('#extensionConfigForm');
  const settings=ext.settings||{};
  form.innerHTML=(ext.settings_schema||[]).map(field=>settingFieldMarkup(field,settings[field.key],settings)).join('')||'<div class="extension-empty">This extension has no settings.</div>';
  $('#extensionConfigOverlay').classList.add('show');
}

function settingFieldMarkup(field,value,settings){
  const key=escAttr(field.key),label=esc(field.label||field.key),help=field.help?'<small>'+esc(field.help)+'</small>':'';
  if(field.type==='asset'){
    const accept=field.accept?' accept="'+escAttr(field.accept)+'"':'';
    const nameKey=field.name_key||'';
    const currentName=nameKey&&settings&&settings[nameKey]?settings[nameKey]:(value?'Custom file selected':'No file selected');
    return '<div class="extension-field"><label>'+label+'</label><div class="extension-input-row"><input type="file" data-asset-file="'+key+'"'+accept+'><button class="ext-btn primary" type="button" data-asset-upload="'+key+'" data-asset-name-key="'+escAttr(nameKey)+'">Use</button></div><input type="hidden" name="'+key+'" value="'+escAttr(value==null?'':value)+'" data-asset-value="'+key+'"><small data-asset-label="'+key+'">'+esc(currentName)+'</small><div class="extension-actions"><button class="ext-btn danger" type="button" data-asset-clear="'+key+'" data-asset-name-key="'+escAttr(nameKey)+'">Clear</button></div>'+help+'</div>';
  }
  if(field.type==='boolean'){
    const checked=value?'checked':'';
    return '<div class="extension-field"><label class="extension-check"><input type="checkbox" name="'+key+'" '+checked+'> '+label+'</label>'+help+'</div>';
  }
  if(field.type==='text'){
    return '<div class="extension-field"><label>'+label+'</label><textarea name="'+key+'">'+esc(value==null?'':value)+'</textarea>'+help+'</div>';
  }
  if(field.type==='number'){
    const min=field.min!=null?' min="'+escAttr(field.min)+'"':'';
    const max=field.max!=null?' max="'+escAttr(field.max)+'"':'';
    const step=field.step!=null?' step="'+escAttr(field.step)+'"':'';
    return '<div class="extension-field"><label>'+label+'</label><input type="number" name="'+key+'" value="'+escAttr(value==null?'':value)+'"'+min+max+step+'>'+help+'</div>';
  }
  if(field.type==='select'){
    const options=(field.options||[]).map(o=>{
      const selected=String(value)===String(o.value)?' selected':'';
      return '<option value="'+escAttr(o.value)+'"'+selected+'>'+esc(o.label||o.value)+'</option>';
    }).join('');
    return '<div class="extension-field"><label>'+label+'</label><select name="'+key+'">'+options+'</select>'+help+'</div>';
  }
  const type=field.type==='color'?'color':'text';
  return '<div class="extension-field"><label>'+label+'</label><input type="'+type+'" name="'+key+'" value="'+escAttr(value==null?'':value)+'">'+help+'</div>';
}


function extensionDefaults(ext){
  const settings={};
  (ext.settings_schema||[]).forEach(field=>{
    if(field.type==='asset'){
      settings[field.key]=field.default==null?'':field.default;
      if(field.name_key) settings[field.name_key]='';
    } else if(field.default!==undefined){
      settings[field.key]=field.default;
    } else if(field.type==='boolean') settings[field.key]=false;
    else if(field.type==='number') settings[field.key]=0;
    else settings[field.key]='';
  });
  return settings;
}

function closeExtensionConfig(){
  extensionConfigId=null;
  $('#extensionConfigOverlay').classList.remove('show');
}


$('#extensionConfigForm').addEventListener('click',async e=>{
  const upload=e.target.closest('[data-asset-upload]');
  const clear=e.target.closest('[data-asset-clear]');
  if(!upload&&!clear) return;
  e.preventDefault();
  const key=(upload||clear).dataset.assetUpload||(upload||clear).dataset.assetClear;
  const nameKey=(upload||clear).dataset.assetNameKey||'';
  const hidden=$('#extensionConfigForm').querySelector('[data-asset-value="'+key+'"]');
  const label=$('#extensionConfigForm').querySelector('[data-asset-label="'+key+'"]');
  if(!hidden) return;
  if(clear){
    hidden.value='';hidden.dataset.assetName='';
    if(label) label.textContent='No file selected';
    return;
  }
  const input=$('#extensionConfigForm').querySelector('[data-asset-file="'+key+'"]');
  const file=input&&input.files&&input.files[0];
  if(!file){toast('Choose a file first','error');return;}
  upload.disabled=true;
  try{
    const fd=new FormData();fd.append('file',file);
    const r=await fetch(API+'/extension-asset/'+encodeURIComponent(extensionConfigId),{method:'POST',body:fd});
    if(!r.ok) throw new Error('HTTP '+r.status);
    const data=await r.json();
    hidden.value=data.url||'';
    hidden.dataset.assetName=file.name;
    if(label) label.textContent='Selected: '+file.name;
    toast('Asset uploaded','success');
  } catch(err){
    toast('Asset upload failed','error');
  }
  upload.disabled=false;
});

$('#extensionConfigReset').addEventListener('click',async()=>{
  if(!extensionConfigId) return;
  const ext=(extensionPayload.extensions||[]).find(x=>x.id===extensionConfigId);
  if(!ext) return;
  const settings=extensionDefaults(ext);
  try{
    const r=await fetch(API+'/extensions/'+encodeURIComponent(extensionConfigId)+'/settings',{
      method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({settings})
    });
    if(!r.ok) throw new Error('HTTP '+r.status);
    toast('Defaults restored','success');
    closeExtensionConfig();
    setTimeout(()=>location.reload(),300);
  } catch(e){toast('Reset failed','error');}
});
$('#extensionConfigCancel').addEventListener('click',closeExtensionConfig);
$('#extensionConfigOverlay').addEventListener('click',e=>{if(e.target===$('#extensionConfigOverlay')) closeExtensionConfig();});
$('#extensionConfigSave').addEventListener('click',async()=>{
  if(!extensionConfigId) return;
  const ext=(extensionPayload.extensions||[]).find(x=>x.id===extensionConfigId);
  if(!ext) return;
  const form=$('#extensionConfigForm');
  const settings={};
  (ext.settings_schema||[]).forEach(field=>{
    const el=form.elements[field.key];
    if(!el) return;
    if(field.type==='boolean') settings[field.key]=!!el.checked;
    else if(field.type==='number') settings[field.key]=Number(el.value);
    else if(field.type==='asset'){
      settings[field.key]=el.value||'';
      if(field.name_key) settings[field.name_key]=el.dataset.assetName||'';
    } else settings[field.key]=el.value;
  });
  try{
    const r=await fetch(API+'/extensions/'+encodeURIComponent(extensionConfigId)+'/settings',{
      method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({settings})
    });
    if(!r.ok) throw new Error('HTTP '+r.status);
    toast('Settings saved','success');
    closeExtensionConfig();
    setTimeout(()=>location.reload(),350);
  } catch(e){toast('Settings save failed','error');}
});

function suggestedExtensionId(name){
  const slug=String(name||'addon').toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-+|-+$/g,'')||'addon';
  return ('community.'+slug).slice(0,64).replace(/[._-]+$/,'')||'community.addon';
}

function openExtensionCreate(){
  extensionCreateIdTouched=false;
  $('#extensionCreateName').value='My LiquidDrop Add-on';
  $('#extensionCreateId').value='community.my-addon';
  $('#extensionCreateAuthor').value='';
  $('#extensionCreateDescription').value='A community add-on created with the LiquidDrop starter.';
  $('#extensionCreateOverlay').classList.add('show');
}

function closeExtensionCreate(){
  $('#extensionCreateOverlay').classList.remove('show');
}

$('#extensionCreateName').addEventListener('input',e=>{
  if(!extensionCreateIdTouched) $('#extensionCreateId').value=suggestedExtensionId(e.target.value);
});
$('#extensionCreateId').addEventListener('input',()=>{extensionCreateIdTouched=true;});
$('#extensionCreateCancel').addEventListener('click',closeExtensionCreate);
$('#extensionCreateOverlay').addEventListener('click',e=>{if(e.target===$('#extensionCreateOverlay')) closeExtensionCreate();});
$('#extensionCreateSave').addEventListener('click',async()=>{
  const btn=$('#extensionCreateSave');
  const form=$('#extensionCreateForm');
  const payload={
    name:form.elements.name.value,
    id:form.elements.id.value,
    author:form.elements.author.value,
    description:form.elements.description.value
  };
  btn.disabled=true;
  try{
    const r=await fetch(API+'/extensions/create',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({extension:payload})});
    if(!r.ok) throw new Error('HTTP '+r.status);
    const data=await r.json();
    toast('Starter add-on created','success');
    closeExtensionCreate();
    await loadExtensions(false);
    switchAppTab('extensions');
  } catch(e){
    toast('Create add-on failed','error');
  }
  btn.disabled=false;
});

$('#openExtensionsFolderBtn').addEventListener('click',async()=>{
  try{
    const r=await fetch(API+'/extensions/open-folder',{method:'POST'});
    if(!r.ok) throw new Error('HTTP '+r.status);
    toast('Add-on folder opened','success');
  } catch(e){toast('Open folder failed','error');}
});

$('#createExtensionBtn').addEventListener('click',openExtensionCreate);
$('#refreshExtensionsBtn').addEventListener('click',()=>loadExtensions(false));
$('#installExtensionBtn').addEventListener('click',()=>$('#extensionFileInput').click());
$('#extensionFileInput').addEventListener('change',async()=>{
  const input=$('#extensionFileInput');
  const file=input.files&&input.files[0];
  input.value='';
  if(!file) return;
  try{
    const manifest=JSON.parse(await file.text());
    const r=await fetch(API+'/extensions/install',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({manifest})});
    if(!r.ok) throw new Error('HTTP '+r.status);
    toast('Extension installed. Turn it on when ready.','success');
    await loadExtensions(false);
    switchAppTab('extensions');
  } catch(e){
    toast('Install failed: invalid extension','error');
  }
});

/* ===== Live connection (replaces polling) ===== */
let liveConnected=false,lastStatus=null,filesTimer=null,liveSource=null;
function scheduleFiles(){
  clearTimeout(filesTimer);
  filesTimer=setTimeout(loadFiles,120);
}
function setLive(on){
  liveConnected=on;
  const pill=$('.files-status');
  if(pill){pill.textContent=on?'Live':'Reconnecting…';pill.classList.toggle('offline',!on);}
  emitExt('live',{connected:on});
}
function parseData(e){try{return JSON.parse(e.data||'{}');}catch(_){return {};}}
function connectLive(){
  if(!window.EventSource){setLive(false);return;}
  const es=new EventSource(API+'/events');
  liveSource=es;
  es.addEventListener('hello',e=>{
    const wasDown=!liveConnected;
    setLive(true);
    const d=parseData(e);
    if(d.status){lastStatus=d.status;emitExt('status',d.status);}
    if(d.build&&PAGE_BUILD&&d.build!==PAGE_BUILD){reloadForUpdate();return;}
    if(wasDown) scheduleFiles();
  });
  es.addEventListener('files',scheduleFiles);
  es.addEventListener('status',e=>{lastStatus=parseData(e);emitExt('status',lastStatus);});
  es.addEventListener('settings',e=>emitExt('settings',parseData(e)));
  es.addEventListener('state',e=>emitExt('state',parseData(e)));
  es.addEventListener('extensions',()=>{
    emitExt('extensions',{});
    if(!$('#extensionsTabPanel').classList.contains('tab-hidden')) loadExtensions(false);
  });
  es.addEventListener('network',()=>{refreshNetwork();emitExt('network',{});});
  es.addEventListener('shutdown',()=>{es.close();liveSource=null;setLive(false);showShutdownScreen();});
  es.onerror=()=>{
    setLive(false);
    if(es.readyState===EventSource.CLOSED&&liveSource===es){liveSource=null;setTimeout(connectLive,3000);}
  };
}

/* ===== Network picker (host) and QR refresh ===== */
const NET_KIND={wifi:'Wi-Fi',ethernet:'Ethernet',virtual:'Virtual / VPN',other:'Network'};
async function refreshNetwork(){
  try{
    const n=await apiJSON('GET',API+'/network');
    if(n.base_url) $('#urlCopy').textContent=n.base_url;
    const pu=$('#pinUrl');
    if(pu&&n.pin_url) pu.textContent=n.pin_url;
    const img=$('#qrImage');
    if(img) img.src=API+'/qr.png?v='+encodeURIComponent(n.selected||'')+'-'+Date.now();
    const box=$('#hostNetwork'),sel=$('#hostNetworkSelect');
    if(!box||!sel) return;
    const list=n.interfaces||[];
    if(!list.length){box.hidden=true;return;}
    box.hidden=false;
    sel.innerHTML=list.map(i=>'<option value="'+escAttr(i.ip)+'"'+(i.ip===n.selected?' selected':'')+'>'+
      esc(i.ip+' — '+(NET_KIND[i.kind]||'Network')+' ('+i.name+')')+'</option>').join('');
    sel.disabled=list.length<2;
    const hints=[];
    if(list.length>1) hints.push('Pick the network your phone is on.');
    if(n.mdns_url) hints.push('Also reachable at '+n.mdns_url+' on most devices.');
    $('#hostNetworkHint').textContent=hints.join(' ');
  }catch(e){}
}
const hostNetworkSelect=$('#hostNetworkSelect');
if(hostNetworkSelect){
  hostNetworkSelect.addEventListener('change',async()=>{
    try{
      await apiJSON('POST',API+'/network',{ip:hostNetworkSelect.value});
      toast('📶 QR code updated','success');
      refreshNetwork();
    }catch(e){toast('✗ Could not switch network','error');}
  });
}

loadExtensions(true);
loadFiles();
connectLive();
refreshNetwork();
/* Safety nets: poll only while the live connection is down, and refresh
   relative times ("2m ago") periodically. */
setInterval(()=>{if(!liveConnected) loadFiles();},4000);
setInterval(refreshFileTimes,30000);
document.addEventListener('visibilitychange',()=>{if(!document.hidden){loadFiles();pumpPosters();}});
