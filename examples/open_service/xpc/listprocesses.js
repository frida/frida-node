const frida = require('../../..');
const util = require('util');

async function main() {
  const device = await frida.getUsbDevice();

  const appservice = await device.openService('xpc:com.apple.coredevice.appservice');
  const response = await appservice.request({
    'CoreDevice.featureIdentifier': 'com.apple.coredevice.feature.listprocesses',
    'CoreDevice.action': {},
    'CoreDevice.input': {},
  });
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
