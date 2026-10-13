// 오프라인 안내 한 장만 캐시합니다. 자료실 화면·API·토큰은 캐시하지 않습니다.
const CACHE='vault-offline-v1';
self.addEventListener('install',event=>event.waitUntil(caches.open(CACHE).then(cache=>cache.add('/offline.html'))));
self.addEventListener('activate',event=>event.waitUntil(caches.keys().then(keys=>Promise.all(keys.filter(key=>key.startsWith('vault-offline-')&&key!==CACHE).map(key=>caches.delete(key)))).then(()=>self.clients.claim())));
self.addEventListener('fetch',event=>{
  if(event.request.mode==='navigate'&&new URL(event.request.url).origin===self.location.origin)
    event.respondWith(fetch(event.request).catch(()=>caches.open(CACHE).then(cache=>cache.match('/offline.html'))));
});
