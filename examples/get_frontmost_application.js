'use strict';

const co = require('co');
const frida = require('..');

co(function *() {
  const device = yield frida.getUsbDevice();
  const application = yield device.getFrontmostApplication();
  console.log('application:', application);
})
.catch(onError);

function onError(error) {
  console.error(error);
}
