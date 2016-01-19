'use strict';

const co = require('co');
const frida = require('..');

co(function *() {
  const device = yield frida.getUsbDevice();
  const application = yield device.getFrontmostApplication();
  console.log('Application:', application);
})
.catch(error => {
  console.error(error);
});
