'use strict';

const co = require('co');
const frida = require('..');

const mgr = frida.getDeviceManager();
mgr.events.listen('changed', function () {
  console.log('changed!');
});
mgr.events.listen('added', function (device) {
  console.log('added!', device);
});
mgr.events.listen('removed', function (device) {
  console.log('removed!', device);
});

co(function *() {
  const devices = yield mgr.enumerateDevices();
  console.log('enumerateDevices() =>', devices);
})
.catch(onError);

function onError(error) {
  console.error(error);
}
