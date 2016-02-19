'use strict';

module.exports = DeviceManager;


var Device = require('./device');
var $ = Symbol('impl');

function DeviceManager(impl) {
  Object.defineProperty(this, $, { value: impl });

  Object.defineProperty(this, 'events',
      Object.getOwnPropertyDescriptor(impl, 'events'));
}

DeviceManager.prototype.enumerateDevices = function () {
  return this[$].enumerateDevices()
  .then(function (devices) {
    return devices.map(function (impl) { return new Device(impl); });
  });
};

DeviceManager.prototype.addRemoteDevice = function (host) {
  return this[$].addRemoteDevice(host)
  .then(function (impl) {
    return new Device(impl);
  });
};

DeviceManager.prototype.removeRemoteDevice = function (host) {
  return this[$].removeRemoteDevice(host);
};
