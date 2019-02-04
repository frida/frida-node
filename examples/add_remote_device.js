const frida = require('..');

async function main() {
  const deviceManager = frida.getDeviceManager();

  const device = await deviceManager.addRemoteDevice('192.168.1.15:1337');
  console.log('[*] Added:', device);

  let processes = await device.enumerateProcesses();
  console.log('[*] Processes:', processes);

  await deviceManager.removeRemoteDevice('192.168.1.15:1337');
}

main()
  .catch(e => {
    console.error(e);
  });
