const CACHE_NAME = 'private-messenger-v2';
const urlsToCache = [
  '/',
  '/static/styles.css',
  '/static/icons/icon-192x192.png',
  '/static/icons/icon-512x512.png',
  '/static/manifest.json'
];

// Install event - cache core resources
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => {
      console.log('[SW] Caching app shell');
      return cache.addAll(urlsToCache);
    })
  );
  self.skipWaiting(); // Activate worker immediately
});

// Fetch event - serve from cache or fetch from network
self.addEventListener('fetch', event => {
  event.respondWith(
    caches.match(event.request).then(response => {
      return response || fetch(event.request).catch(() => {
        // Optionally return a fallback page/image for offline
        if (event.request.destination === 'image') {
          return caches.match('/static/icons/icon-192x192.png');
        }
      });
    })
  );
});

// Activate event - remove old caches
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(
        keys.map(key => {
          if (key !== CACHE_NAME) {
            console.log('[SW] Removing old cache:', key);
            return caches.delete(key);
          }
        })
      )
    )
  );
  self.clients.claim(); // Start controlling pages immediately
});

// Background sync - custom logic
self.addEventListener('sync', event => {
  if (event.tag === 'background-sync') {
    event.waitUntil(doBackgroundSync());
  }
});

function doBackgroundSync() {
  console.log('[SW] Background sync triggered');
  // TODO: Implement actual sync logic here (e.g. send queued messages)
}

// Push Notification
self.addEventListener('push', event => {
  const data = event.data ? event.data.text() : 'New message received!';
  const options = {
    body: data,
    icon: '/static/icons/icon-192x192.png',
    badge: '/static/icons/icon-96x96.png',
    vibrate: [100, 50, 100],
    data: {
      dateOfArrival: Date.now(),
      primaryKey: 1
    },
    actions: [
      {
        action: 'explore',
        title: 'Open App',
        icon: '/static/icons/icon-96x96.png'
      },
      {
        action: 'close',
        title: 'Close',
        icon: '/static/icons/icon-96x96.png'
      }
    ]
  };

  event.waitUntil(
    self.registration.showNotification('Private Messenger', options)
  );
});

// Handle notification click
self.addEventListener('notificationclick', event => {
  event.notification.close();

  if (event.action === 'explore') {
    event.waitUntil(clients.openWindow('/'));
  } else {
    // Handle other actions like 'close'
    console.log('[SW] Notification closed');
  }
});