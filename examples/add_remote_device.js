'use strict';

const co = require('co');
const frida = require('..');

co(function *() {
  const mgr = frida.getDeviceManager();

  const device = yield mgr.addRemoteDevice('192.168.1.3:1337');
  console.log('added', device);

  let processes = yield device.enumerateProcesses();
  console.log('processes', processes);

  yield mgr.removeRemoteDevice('192.168.1.3:1337');

  /*
  processes = yield device.enumerateProcesses();
  console.log('should not get here', processes);
  */
})
.catch(onError);

function onError(error) {
  console.error(error);
}
