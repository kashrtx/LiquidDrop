(function(){
  const id='liquiddrop.status-strip';
  const api=window.LiquidDropExtensions;
  if(!api) return;

  let settings=null;
  let strip=null;
  let chips={};
  let weatherCache={at:0,value:'',code:null,unit:''};
  const SHARED_WEATHER_TTL=30*60*1000;
  const SHARED_ERROR_TTL=5*60*1000;

  function fmtSpeed(bps){
    if(!bps||bps<128) return 'Idle';
    if(bps<1024) return Math.round(bps)+' B/s';
    if(bps<1048576) return Math.round(bps/1024)+' KB/s';
    return (bps/1048576).toFixed(1)+' MB/s';
  }
  function weatherInfo(code){
    if(code===0) return {label:'Clear',icon:'sun'};
    if([1,2,3].includes(code)) return {label:'Cloudy',icon:'cloud'};
    if([45,48].includes(code)) return {label:'Fog',icon:'cloud'};
    if((code>=51&&code<=67)||(code>=80&&code<=82)) return {label:'Rain',icon:'rain'};
    if(code>=71&&code<=77) return {label:'Snow',icon:'snow'};
    if(code>=95) return {label:'Storm',icon:'storm'};
    return {label:'Weather',icon:'cloud'};
  }
  function icon(name){
    const attrs='viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"';
    const paths={
      devices:'<rect x="4" y="5" width="9" height="15" rx="2.3"></rect><path d="M8.5 17.2h.01"></path><rect x="14.5" y="8" width="5.5" height="9" rx="1.6"></rect><path d="M16.5 18.8h1.5"></path>',
      speed:'<path d="M7 17V7"></path><path d="M4 10l3-3 3 3"></path><path d="M17 7v10"></path><path d="M14 14l3 3 3-3"></path><path d="M11.5 12h1"></path>',
      sun:'<circle cx="12" cy="12" r="4.2"></circle><path d="M12 2.8v2"></path><path d="M12 19.2v2"></path><path d="M4.2 4.2l1.4 1.4"></path><path d="M18.4 18.4l1.4 1.4"></path><path d="M2.8 12h2"></path><path d="M19.2 12h2"></path><path d="M4.2 19.8l1.4-1.4"></path><path d="M18.4 5.6l1.4-1.4"></path>',
      cloud:'<path d="M7.5 18h9.1a4.2 4.2 0 0 0 .5-8.4 6.1 6.1 0 0 0-11.6 1.8A3.4 3.4 0 0 0 7.5 18z"></path>',
      rain:'<path d="M7.5 16.5h8.8a4 4 0 0 0 .5-8 5.8 5.8 0 0 0-11 1.7 3.2 3.2 0 0 0 1.7 6.3z"></path><path d="M8 19.5l-.8 1.4"></path><path d="M12 19.5l-.8 1.4"></path><path d="M16 19.5l-.8 1.4"></path>',
      snow:'<path d="M7.5 16.5h8.8a4 4 0 0 0 .5-8 5.8 5.8 0 0 0-11 1.7 3.2 3.2 0 0 0 1.7 6.3z"></path><path d="M9 20h.01"></path><path d="M12 21h.01"></path><path d="M15 20h.01"></path>',
      storm:'<path d="M7.5 16.2h8.8a4 4 0 0 0 .5-8 5.8 5.8 0 0 0-11 1.7 3.2 3.2 0 0 0 1.7 6.3z"></path><path d="M13 16l-2.2 4h2.4l-1.4 2.2"></path>'
    };
    return '<svg '+attrs+'>'+((paths[name]||paths.cloud))+'</svg>';
  }
  function ensure(){
    if(strip) return;
    const header=document.querySelector('.app-header')||document.querySelector('.header');
    if(!header) return;
    header.classList.add('ld-status-host');
    const style=document.createElement('style');
    style.textContent=`
.ld-status-host{position:relative}
.ld-status-strip{--ld-status-accent:#6ee7b7;display:flex;flex-wrap:wrap;gap:9px;margin-top:15px;align-items:stretch;max-width:100%;isolation:isolate}
.ld-status-chip{position:relative;display:inline-flex;align-items:center;gap:10px;min-width:124px;min-height:54px;padding:9px 12px;border-radius:18px;background:linear-gradient(135deg,rgba(255,255,255,.13),rgba(255,255,255,.045));border:1px solid rgba(255,255,255,.16);color:#f7f7fb;box-shadow:0 12px 28px rgba(0,0,0,.18),inset 0 1px 0 rgba(255,255,255,.12);overflow:hidden;backdrop-filter:blur(18px);-webkit-backdrop-filter:blur(18px)}
.ld-status-chip::before{content:'';position:absolute;inset:-1px;border-radius:inherit;background:radial-gradient(circle at 18% 20%,color-mix(in srgb,var(--ld-status-accent) 32%,transparent),transparent 44%);opacity:.42;pointer-events:none}
.ld-status-chip.speed-active{border-color:color-mix(in srgb,var(--ld-status-accent) 38%,rgba(255,255,255,.16));box-shadow:0 14px 34px color-mix(in srgb,var(--ld-status-accent) 18%,transparent),inset 0 1px 0 rgba(255,255,255,.14)}
.ld-status-chip.speed{min-width:172px}
.ld-status-icon{position:relative;z-index:1;width:34px;height:34px;border-radius:13px;display:flex;align-items:center;justify-content:center;flex:0 0 auto;background:linear-gradient(135deg,color-mix(in srgb,var(--ld-status-accent) 34%,transparent),rgba(129,140,248,.17));color:var(--ld-status-accent);box-shadow:inset 0 1px 0 rgba(255,255,255,.18)}
.ld-status-icon svg{width:21px;height:21px;filter:drop-shadow(0 0 10px color-mix(in srgb,var(--ld-status-accent) 42%,transparent))}
.ld-status-copy{position:relative;z-index:1;min-width:0;display:flex;flex-direction:column;gap:3px;line-height:1.05}
.ld-status-label{font-size:9px;font-weight:900;letter-spacing:.08em;text-transform:uppercase;color:rgba(255,255,255,.54);white-space:nowrap}
.ld-status-value{font-size:13px;font-weight:900;color:#fff;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:150px;text-shadow:0 1px 12px rgba(0,0,0,.28)}
.ld-status-chip.devices .ld-status-value,.ld-status-chip.weather .ld-status-value{max-width:96px}
@supports not (background:color-mix(in srgb,#fff 50%,#000)){.ld-status-chip::before{background:radial-gradient(circle at 18% 20%,rgba(110,231,183,.18),transparent 44%)}.ld-status-icon{background:rgba(110,231,183,.16)}.ld-status-chip.speed-active{border-color:rgba(110,231,183,.32);box-shadow:0 14px 34px rgba(110,231,183,.12),inset 0 1px 0 rgba(255,255,255,.14)}}
@media(min-width:760px){.app-header.ld-status-host{padding-right:min(560px,61vw)}.app-header.ld-status-host .ld-status-strip{position:absolute;right:28px;top:28px;margin-top:0;max-width:min(520px,calc(100% - 310px));justify-content:flex-end}.app-header.ld-status-host .device-badge{max-width:100%}}
@media(max-width:759px){.ld-status-strip{gap:7px}.ld-status-chip{min-width:0;flex:1 1 130px;min-height:50px;padding:8px 10px;border-radius:16px}.ld-status-chip.speed{flex-basis:190px}.ld-status-icon{width:31px;height:31px;border-radius:12px}.ld-status-icon svg{width:19px;height:19px}.ld-status-value{font-size:12px;max-width:120px}.ld-status-chip.devices .ld-status-value,.ld-status-chip.weather .ld-status-value{max-width:90px}}
@media(max-width:430px){.ld-status-strip{display:grid;grid-template-columns:1fr;gap:7px}.ld-status-chip,.ld-status-chip.speed{width:100%;flex-basis:auto}.ld-status-value,.ld-status-chip.devices .ld-status-value,.ld-status-chip.weather .ld-status-value{max-width:100%}}
`;
    document.head.appendChild(style);
    strip=document.createElement('div');
    strip.className='ld-status-strip';
    strip.setAttribute('aria-label','LiquidDrop status');
    header.appendChild(strip);
  }
  function chip(name){
    ensure();
    if(!strip) return null;
    if(!chips[name]){
      const el=document.createElement('div');
      el.className='ld-status-chip '+name;
      el.innerHTML='<span class="ld-status-icon"></span><span class="ld-status-copy"><span class="ld-status-label"></span><span class="ld-status-value"></span></span>';
      chips[name]=el;
      strip.appendChild(el);
    }
    return chips[name];
  }
  function setChip(name,iconName,label,value,show,active){
    const el=chip(name);
    if(!el) return;
    el.style.display=show?'inline-flex':'none';
    el.classList.toggle('speed-active',!!active);
    el.querySelector('.ld-status-icon').innerHTML=icon(iconName);
    el.querySelector('.ld-status-label').textContent=label;
    el.querySelector('.ld-status-value').textContent=value;
  }
  function isHost(){
    return !!(api.canManage&&api.canManage());
  }
  async function getCoords(){
    if(settings.weatherMode==='off'||!settings.showWeather) return null;
    if(settings.weatherMode==='manual'){
      const lat=Number(settings.latitude),lon=Number(settings.longitude);
      if(Math.abs(lat)>0.0001||Math.abs(lon)>0.0001) return {lat,lon};
      return null;
    }
    if(!isHost()||!navigator.geolocation) return null;
    return await new Promise(resolve=>{
      navigator.geolocation.getCurrentPosition(
        p=>resolve({lat:p.coords.latitude,lon:p.coords.longitude}),
        ()=>resolve(null),
        {enableHighAccuracy:false,timeout:5000,maximumAge:30*60*1000}
      );
    });
  }
  async function fetchWeather(coords){
    const unit=settings.temperatureUnit==='celsius'?'celsius':'fahrenheit';
    const url='https://api.open-meteo.com/v1/forecast?latitude='+encodeURIComponent(coords.lat.toFixed(4))+'&longitude='+encodeURIComponent(coords.lon.toFixed(4))+'&current=temperature_2m,weather_code&temperature_unit='+unit+'&timezone=auto';
    const r=await fetch(url,{cache:'no-store'});
    if(!r.ok) throw new Error('weather');
    const data=await r.json();
    const current=data.current||{};
    const code=Number(current.weather_code);
    const temp=Math.round(Number(current.temperature_2m));
    const unitLabel=unit==='celsius'?'C':'F';
    const info=weatherInfo(code);
    return {status:'ok',at:Date.now(),value:temp+'\u00b0'+unitLabel+' '+info.label,code,unit:settings.temperatureUnit,lat:coords.lat,lon:coords.lon};
  }
  async function publishSharedWeather(weather){
    if(!isHost()||!api.setSharedState) return;
    try{
      const shared=api.getSharedState?await api.getSharedState(id).catch(()=>({})):{};
      shared.weather=weather;
      await api.setSharedState(id,shared);
    } catch(e){}
  }
  function applyWeather(weather){
    const info=weatherInfo(Number(weather.code));
    weatherCache={at:Number(weather.at)||Date.now(),value:weather.value||'Weather',code:Number(weather.code),unit:weather.unit||settings.temperatureUnit};
    setChip('weather',info.icon,'Weather',weatherCache.value,true,false);
  }
  async function applySharedWeather(){
    if(!api.getSharedState) return false;
    try{
      const shared=await api.getSharedState(id);
      const weather=shared&&shared.weather;
      if(!weather||!weather.at) return false;
      const age=Date.now()-Number(weather.at);
      if(weather.status==='ok'&&weather.value&&age<SHARED_WEATHER_TTL){
        applyWeather(weather);
        return true;
      }
      if(weather.status==='needs-location'&&age<SHARED_ERROR_TTL){
        setChip('weather','cloud','Weather','Set on host',true,false);
        return true;
      }
      if(weather.status==='error'&&age<SHARED_ERROR_TTL){
        setChip('weather','cloud','Weather','Unavailable',true,false);
        return true;
      }
    } catch(e){}
    return false;
  }
  async function updateWeather(force){
    if(!settings.showWeather||settings.weatherMode==='off'){
      setChip('weather','cloud','Weather','Off',false,false);
      return;
    }
    const now=Date.now();
    if(!force&&weatherCache.value&&now-weatherCache.at<10*60*1000){
      const info=weatherInfo(weatherCache.code);
      setChip('weather',info.icon,'Weather',weatherCache.value,true,false);
      return;
    }
    if(!isHost()&&await applySharedWeather()) return;
    const coords=await getCoords();
    if(!coords){
      setChip('weather','cloud','Weather',isHost()?'Set location':'Set on host',true,false);
      if(isHost()) publishSharedWeather({status:'needs-location',at:Date.now(),value:'Set location',unit:settings.temperatureUnit});
      return;
    }
    try{
      const weather=await fetchWeather(coords);
      applyWeather(weather);
      publishSharedWeather(weather);
    } catch(e){
      setChip('weather','cloud','Weather','Unavailable',true,false);
      publishSharedWeather({status:'error',at:Date.now(),value:'Unavailable',unit:settings.temperatureUnit});
    }
  }
  async function updateStatus(){
    ensure();
    if(strip&&settings.accentColor) strip.style.setProperty('--ld-status-accent',settings.accentColor);
    try{
      const r=await fetch(api.apiBase+'/status',{cache:'no-store'});
      if(!r.ok) throw new Error('status');
      const s=await r.json();
      const devices=Math.max(1,s.active_devices||1);
      setChip('devices','devices','Devices',devices+' active',!!settings.showDevices,false);
      const up=s.upload_bps||0,down=s.download_bps||0,active=up>256||down>256;
      setChip('speed','speed','Transfer','\u2191 '+fmtSpeed(up)+'  \u2193 '+fmtSpeed(down),!!settings.showTransfer,active);
    } catch(e){
      setChip('devices','devices','Devices','Offline',!!settings.showDevices,false);
      setChip('speed','speed','Transfer','Idle',!!settings.showTransfer,false);
    }
  }
  async function start(){
    settings=await api.getSettings(id).catch(()=>({}));
    settings=Object.assign({showDevices:true,showTransfer:true,showWeather:true,weatherMode:'browser',temperatureUnit:'fahrenheit',accentColor:'#6ee7b7'},settings||{});
    ensure();
    updateStatus();
    updateWeather(true);
    setInterval(updateStatus,2000);
    setInterval(()=>updateWeather(false),60000);
    window.addEventListener('focus',()=>{updateStatus();updateWeather(false);});
    document.addEventListener('visibilitychange',()=>{if(!document.hidden){updateStatus();updateWeather(false);}});
  }
  start().catch(e=>api.reportError&&api.reportError(id,e));
})();
