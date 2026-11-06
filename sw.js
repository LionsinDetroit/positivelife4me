// positiveLife4me: lets the site install like an app and open without a connection
const CACHE="pl4m-v9";
const CORE=["./","index.html","manifest.webmanifest","icon-192.png","icon-512.png","icon-maskable-512.png","apple-touch-icon.png"];
self.addEventListener("install",e=>{e.waitUntil(caches.open(CACHE).then(c=>c.addAll(CORE).then(()=>c.add("flare-forecast").catch(()=>{}))));self.skipWaiting()});
self.addEventListener("activate",e=>{e.waitUntil(caches.keys().then(ks=>Promise.all(ks.filter(k=>k!==CACHE).map(k=>caches.delete(k)))).then(()=>self.clients.claim()))});
self.addEventListener("fetch",e=>{
  const r=e.request;if(r.method!=="GET")return;
  // never cache the private profile and workout helpers
  if(new URL(r.url).pathname.startsWith("/api/"))return;
  // outside services (weather, place search, fonts) go straight to the network, never saved or replaced
  if(new URL(r.url).origin!==self.location.origin)return;
  // /track/lifting style links open the matching page inside the app (#track/lifting), online or offline
  if(r.mode==="navigate"&&/^\/track(\/|$)/.test(new URL(r.url).pathname)){const u=new URL(r.url);e.respondWith(Response.redirect(u.origin+"/#"+u.pathname.slice(1).replace(/\/+$/,""),302));return}
  // Pages: try the network first so updates show right away, fall back to the saved copy offline
  if(r.mode==="navigate"){const pth=new URL(r.url).pathname,isMain=["/","/index.html"].includes(pth),isFlare=["/flare-forecast","/flare-forecast.html"].includes(pth);
    e.respondWith(fetch(r).then(res=>{if((isMain||isFlare)&&res.ok&&!res.redirected){const cp=res.clone();caches.open(CACHE).then(c=>c.put(isMain?"index.html":"flare-forecast",cp))}return res}).catch(()=>caches.match(isMain?"index.html":isFlare?"flare-forecast":r).then(m=>m||caches.match("index.html"))));return}
  // Everything else: saved copy first, then the network (and save fonts/icons for next time)
  e.respondWith(caches.match(r).then(hit=>hit||fetch(r).then(res=>{if(res&&res.ok){const cp=res.clone();caches.open(CACHE).then(c=>c.put(r,cp))}return res}).catch(()=>hit)));
});
