'use strict';

const frida = require('..');
const { inspect } = require('util');

const source = `'use strict';

recv(onMessage);

function onMessage(message) {
  send({ name: 'pong', payload: message });

  recv(onMessage);
}`;

async function spawnExample() {
  const pid = await frida.spawn(['/bin/cat', '/etc/resolv.conf']);

  console.log(`[*] Spawned pid=${pid}`);

  // This is where you could attach (see below) and instrument APIs before you call resume()
  await frida.resume(pid);
  console.log('[*] Resumed');
}

async function attachExample() {
  const session = await frida.attach('cat');
  console.log(`[*] Attached session=${inspect(session, { colors: true })}`);

  const script = await session.createScript(source);
  console.log('[*] Script created');

  script.message.connect(message => {
    console.log(`[*] onMessage(message=${inspect(message, { colors: true })})`);
  });

  await script.load();

  console.log('[*] Script loaded');
  setInterval(() => {
    script.post({ name: 'ping' });
  }, 1000);
}

async function usbExample() {
  const device = await frida.getUsbDevice(10000);
  console.log('[*] USB device:', device);

  // Now call spawn(), attach(), etc. on `device` just like the above calls on `frida`
}

attachExample()
  .catch(e => {
    console.error(e);
  });
