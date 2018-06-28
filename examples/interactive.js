'use strict';

const frida = require('..');

const source = `'use strict';

recv(onMessage);

function onMessage(message) {
  send({ name: 'pong', payload: message });

  recv(onMessage);
}`;

async function spawnExample() {
  const pid = await frida.spawn(['/bin/cat', '/etc/resolv.conf']);

  console.log('spawned:', pid);

  // This is where you could attach (see below) and instrument APIs before you call resume()
  await frida.resume(pid);
  console.log('resumed');
}

async function attachExample() {
  const session = await frida.attach('cat');
  console.log('attached:', session);

  const script = await session.createScript(source);
  console.log('script created:', script);

  script.message.connect((message, data) => {
    console.log('message from script:', message, data);
  });

  await script.load();

  console.log('script loaded');
  setInterval(() => {
    script.post({ name: 'ping' });
  }, 1000);
}

async function usbExample() {
  const device = await frida.getUsbDevice(10000);

  console.log('usb device:', device);
  // Now call spawn(), attach(), etc. on `device` just like the above calls on `frida`
}

attachExample()
  .catch(e => {
    console.error(e);
  });
