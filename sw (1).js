// positiveLife4me: lets the site install like an app and open without a connection
const CACHE="pl4m-v5";
const CORE=["./","index.html","manifest.webmanifest","icon-192.png","icon-512.png","icon-maskable-512.png","apple-touch-icon.png"];
self.addEventListener("install",e=>{e.waitUntil(caches.open(CACHE).then(c=>c.addAll(CORE)));self.skipWaiting()});
self.addEventListener("activate",e=>{e.waitUntil(caches.keys().then(ks=>Promise.all(ks.filter(k=>k!==CACHE).map(k=>caches.delete(k)))).then(()=>self.clients.claim()))});
self.addEventListener("fetch",e=>{
  const r=e.request;if(r.method!=="GET")return;
  // never cache the private profile and workout helpers
  if(new URL(r.url).pathname.startsWith("/api/"))return;
  // outside services (weather, place search, fonts) go straight to the network, never saved or replaced
  if(new URL(r.url).origin!==self.location.origin)return;
  // Pages: try the network first so updates show right away, fall back to the saved copy offline
  if(r.mode==="navigate"){const isMain=["/","/index.html"].includes(new URL(r.url).pathname);
    e.respondWith(fetch(r).then(res=>{if(isMain&&res.ok){const cp=res.clone();caches.open(CACHE).then(c=>c.put("index.html",cp))}return res}).catch(()=>caches.match(isMain?"index.html":r).then(m=>m||caches.match("index.html"))));return}
  // Everything else: saved copy first, then the network (and save fonts/icons for next time)
  e.respondWith(caches.match(r).then(hit=>hit||fetch(r).then(res=>{if(res&&res.ok){const cp=res.clone();caches.open(CACHE).then(c=>c.put(r,cp))}return res}).catch(()=>hit)));
});
