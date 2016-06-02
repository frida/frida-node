'use strict';

const co = require('co');
const frida = require('..');

const source = 
`recv(function onMessage(message) {
  send({ name: "pong", payload: message });
  recv(onMessage);
});`;

const spawnExample = co.wrap(function *() {
  const pid = yield frida.spawn(['/bin/cat', '/etc/resolv.conf']);

  console.log('spawned:', pid);

  // This is where you could attach (see below) and instrument APIs before you call resume()
  yield frida.resume(pid);
  console.log('resumed');
});

const attachExample = co.wrap(function *() {
  const session = yield frida.attach('cat');
  console.log('attached:', session);

  const script = yield session.createScript(source);
  console.log('script created:', script);

  script.events.listen('message', (message, data) => {
    console.log('message from script:', message, data);
  });

  yield script.load();

  console.log('script loaded');
  setInterval(() => {
    script.postMessage({ name: 'ping' });
  }, 1000);
});

const usbExample = co.wrap(function *() {
  const device = yield frida.getUsbDevice(10000);

  console.log('usb device:', device);
  // Now call spawn(), attach(), etc. on `device` just like the above calls on `frida`
});

attachExample()
.catch(error => {
  console.log('error:', error.message);
});
