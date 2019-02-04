const frida = require('..');

async function main() {
  const device = await frida.getUsbDevice();
  const applications = await device.enumerateApplications();
  console.log('[*] Applications:', applications);
}

main()
  .catch(e => {
    console.error(e);
  });
