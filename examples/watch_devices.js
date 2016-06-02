'use strict';

const co = require('co');
const frida = require('..');

const mgr = frida.getDeviceManager();
mgr.events.listen('added', device => {
  console.log('added!', device);
});
mgr.events.listen('removed', device => {
  console.log('removed!', device);
});
mgr.events.listen('changed', () => {
  console.log('changed!');
});

co(function *() {
  const devices = yield mgr.enumerateDevices();
  console.log('enumerateDevices() =>', devices);
})
.catch(error => {
  console.error(error);
});
