'use strict';

const frida = require('..');

async function main() {
  process.stdin.pause();

  const device = await frida.getUsbDevice();
  device.processCrashed.connect(onProcessCrashed);

  const session = await device.attach('Hello');
  session.detached.connect(onSessionDetached);

  console.log('[*] Attached. Press any key to exit.');
  process.stdin.setRawMode(true);
  process.stdin.resume();
  process.stdin.on('data', () => {
    session.detach();
  });
}

function onProcessCrashed(crash) {
  console.log('[*] onProcessCrashed() crash:', crash);
}

function onSessionDetached(reason, crash) {
  console.log('[*] onDetached() reason:', reason, 'crash:', crash);
}

main()
  .catch(e => {
    console.error(e);
  });
