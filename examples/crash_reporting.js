const frida = require('..');

async function main() {
  const device = await frida.getUsbDevice();
  device.processCrashed.connect(onProcessCrashed);

  const session = await device.attach('Hello');
  session.detached.connect(onSessionDetached);

  console.log('[*] Ready');
}

function onProcessCrashed(crash) {
  console.log('[*] onProcessCrashed() crash:', crash);
  console.log(crash.report);
}

function onSessionDetached(reason, crash) {
  console.log('[*] onDetached() reason:', reason, 'crash:', crash);
}

main()
  .catch(e => {
    console.error(e);
  });
