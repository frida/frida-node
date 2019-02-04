const frida = require('..');

async function main() {
  const device = await frida.getUsbDevice();
  const application = await device.getFrontmostApplication();
  console.log('[*] Frontmost application:', application);
}

main()
  .catch(e => {
    console.error(e);
  });
