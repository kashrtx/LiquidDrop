(function(){
  const id='liquiddrop.background';
  const api=window.LiquidDropExtensions;
  if(!api) return;
  let imageLayer=null,veilLayer=null,styleEl=null,lastJson='',inFlight=false;

  function clamp(value,min,max){return Math.max(min,Math.min(max,Number(value)||0));}
  function normalizeUrl(url){
    if(!url) return '';
    const marker='/extension-data/';
    const idx=String(url).indexOf(marker);
    return idx>=0 ? api.apiBase+String(url).slice(idx) : String(url);
  }
  function hexToRgb(hex){
    const m=String(hex||'#050816').match(/^#([0-9a-f]{6})$/i);
    const raw=m?m[1]:'050816';
    return [parseInt(raw.slice(0,2),16),parseInt(raw.slice(2,4),16),parseInt(raw.slice(4,6),16)];
  }
  function ensureLayers(){
    if(!styleEl){
      styleEl=document.createElement('style');
      styleEl.textContent='.custom-background-active .glass{background:rgba(9,12,28,.78);border-color:rgba(255,255,255,.18);box-shadow:0 10px 34px rgba(0,0,0,.42),inset 0 1px 0 rgba(255,255,255,.1)}.custom-background-active .file-card,.custom-background-active .extension-card{background:rgba(10,13,30,.76)}.custom-background-active .orb{opacity:.1}.custom-background-active .qr-wrap{box-shadow:0 10px 34px rgba(0,0,0,.46)}';
      document.head.appendChild(styleEl);
    }
    if(!imageLayer){
      imageLayer=document.createElement('div');
      imageLayer.style.cssText='position:fixed;inset:0;z-index:0;pointer-events:none;background-position:center;background-size:cover;background-repeat:no-repeat;opacity:0;transition:opacity .25s ease;';
      document.body.prepend(imageLayer);
    }
    if(!veilLayer){
      veilLayer=document.createElement('div');
      veilLayer.style.cssText='position:fixed;inset:0;z-index:0;pointer-events:none;transition:background .2s ease,backdrop-filter .2s ease;-webkit-backdrop-filter:blur(0);backdrop-filter:blur(0);';
      document.body.insertBefore(veilLayer,imageLayer.nextSibling);
    }
  }
  function apply(settings){
    ensureLayers();
    const url=normalizeUrl(settings.backgroundUrl||'');
    if(!url){
      document.body.classList.remove('custom-background-active');
      imageLayer.style.opacity='0';
      imageLayer.style.backgroundImage='none';
      veilLayer.style.background='transparent';
      veilLayer.style.backdropFilter='blur(0)';
      veilLayer.style.webkitBackdropFilter='blur(0)';
      return;
    }
    const opacity=clamp(settings.overlayOpacity==null?0.72:settings.overlayOpacity,0.35,0.92);
    const blur=clamp(settings.blur==null?12:settings.blur,0,32);
    const rgb=hexToRgb(settings.tint||'#050816');
    imageLayer.style.backgroundImage='url("'+url.replace(/"/g,'%22')+'")';
    imageLayer.style.opacity='1';
    veilLayer.style.background='rgba('+rgb[0]+','+rgb[1]+','+rgb[2]+','+opacity+')';
    veilLayer.style.backdropFilter='blur('+blur+'px) saturate(.9)';
    veilLayer.style.webkitBackdropFilter='blur('+blur+'px) saturate(.9)';
    document.body.classList.add('custom-background-active');
  }
  async function refresh(){
    if(inFlight) return;
    inFlight=true;
    try{
      const settings=await api.getSettings(id);
      const nextJson=JSON.stringify(settings||{});
      if(nextJson!==lastJson){
        lastJson=nextJson;
        apply(settings||{});
      }
    } catch(e){}
    inFlight=false;
  }
  refresh();
  setInterval(refresh,3000);
  window.addEventListener('focus',refresh);
  window.addEventListener('pageshow',refresh);
  document.addEventListener('visibilitychange',()=>{if(!document.hidden) refresh();});
})();
