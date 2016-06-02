'use strict';

const co = require('co');
const frida = require('..');

co(function *() {
  const device = yield frida.getUsbDevice();
  const applications = yield device.enumerateApplications();
  console.log('Applications:', applications);
})
.catch(error => {
  console.error(error);
});
