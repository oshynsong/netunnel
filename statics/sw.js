self.addEventListener('install', (event) => {
    event.waitUntil(self.skipWaiting().then((resolve, rejected) => {
        // todo: load wasm
        console.log("sw installed");
    }));
});

self.addEventListener('activate', (event) => {
    event.waitUntil(clients.claim().finally(() => {
        return self.registration?.navigationPreload.enable()
    }));
});

self.addEventListener('fetch', (event)=>{
    let method = event.request.method;
    let url = new URL(event.request.url);

    let resp = new Response("YOU ARE RUNNING INTO AN INVALID PAGE, PLEASE CONTRACT THE ADMINISTRATOR!")
    if (method === 'GET' &&
        (url.pathname === '/' || url.pathname === '/favicon.ico')) {
        console.log("sw interceptor fetch directly: ", method, event.request.url);
        resp = fetch(event.request);
    } else if (url.pathname.startsWith('/forward')) {
        console.log("sw interceptor with forward: ", method, event.request.url);
        resp = fetch(event.request);
    } else {
        let redirectURL = new URL(location.href);
        redirectURL.pathname = "/forward";
        redirectURL.searchParams.append("addr", url.toString());
        console.log("sw interceptor redirect: ", method, event.request.url, redirectURL.toString());
        let req = new Request(redirectURL, {
            method: event.request.method,
            headers: event.request.headers,
            referrer: event.request.referrer,
            body: event.request.body,
        })
        console.log("redirect", req);
        resp = fetch(req);
    }
    event.respondWith(resp);
});