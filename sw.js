/* Surrey 89ers player portal — service worker.
   Its only job is notifications: show one when it arrives, and open
   the right page when it is tapped. It deliberately does NOT cache
   any pages, so the portal keeps loading live from the Google Sheet. */

self.addEventListener("install", function(){ self.skipWaiting(); });
self.addEventListener("activate", function(event){ event.waitUntil(self.clients.claim()); });

self.addEventListener("push", function(event){
  var data = {};
  try{ data = event.data ? event.data.json() : {}; }catch(e){}
  /* Always show something: a phone that receives a push and shows
     nothing will stop delivering them. */
  event.waitUntil(self.registration.showNotification(data.title || "Surrey 89ers", {
    body: data.body || "",
    tag: data.tag || undefined,
    icon: "/icons/icon-192.png",
    data: { url: data.url || "/" }
  }));
});

self.addEventListener("notificationclick", function(event){
  event.notification.close();
  var url = new URL((event.notification.data && event.notification.data.url) || "/", self.location.origin).href;
  event.waitUntil((async function(){
    var open = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
    for(var i = 0; i < open.length; i++){
      try{
        var c = await open[i].navigate(url);
        if(c){ return c.focus(); }
      }catch(e){ /* fall through and open a new one */ }
    }
    return self.clients.openWindow(url);
  })());
});
