'use strict';

module.exports = DeviceManager;


var Device = require('./device');
var $ = Symbol('binding');

function DeviceManager(binding) {
  Object.defineProperty(this, $, {value: binding});

  Object.defineProperty(this, 'events', Object.getOwnPropertyDescriptor(binding, 'events'));
}

DeviceManager.prototype.enumerateDevices = function () {
  return this[$].enumerateDevices()
  .then(function (devices) {
    return devices.map(function (binding) { return new Device(binding); });
  });
};
