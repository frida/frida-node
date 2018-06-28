'use strict';

const frida = require('..');

const deviceManager = frida.getDeviceManager();
deviceManager.added.connect(device => {
  console.log('added!', device.name);
});
deviceManager.removed.connect(device => {
  console.log('removed!', device.name);
});
deviceManager.changed.connect(() => {
  console.log('changed!');
});

async function run() {
  const devices = await deviceManager.enumerateDevices();
  console.log('enumerateDevices() =>', devices.map(device => device.name));
};

run()
  .catch(e => {
    console.error(e);
  });
