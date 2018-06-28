'use strict';

const frida = require('..');

const deviceManager = frida.getDeviceManager();
deviceManager.added.connect(device => {
  console.log('added!', device);
});
deviceManager.removed.connect(device => {
  console.log('removed!', device);
});
deviceManager.changed.connect(() => {
  console.log('changed!');
});

async function run() {
  const devices = await deviceManager.enumerateDevices();
  console.log('enumerateDevices() =>', devices);
};

run()
  .catch(e => {
    console.error(e);
  });
