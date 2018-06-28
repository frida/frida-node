'use strict';

const frida = require('..');

async function main() {
  const device = await frida.getUsbDevice();
  const application = await device.getFrontmostApplication();
  console.log('Application:', application);
}

main()
  .catch(e => {
    console.error(e);
  });