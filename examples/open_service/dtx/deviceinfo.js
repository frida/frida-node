const frida = require('../../..');
const util = require('util');

async function main() {
  const device = await frida.getUsbDevice();

  const deviceinfo = await device.openService('dtx:com.apple.instruments.server.services.deviceinfo');
  const response = await deviceinfo.request({ method: 'runningProcesses' });
  console.log(util.inspect(response, {
    colors: true,
    depth: Infinity,
    maxArrayLength: Infinity
  }));
}

main()
  .catch(e => {
    console.error(e);
  });
