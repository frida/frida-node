'use strict';

exports.spawn = function (commandLine) {
  return getLocalDevice().then(function (device) {
    return device.spawn(commandLine);
  });
};

exports.resume = function (target) {
  return getLocalDevice().then(function (device) {
    return device.resume(target);
  });
};

exports.kill = function (target) {
  return getLocalDevice().then(function (device) {
    return device.kill(target);
  });
};

exports.attach = function (target) {
  return getLocalDevice().then(function (device) {
    return device.attach(target);
  });
};

exports.getLocalDevice = getLocalDevice;

exports.getUsbDevice = getUsbDevice;

exports.getRemoteDevice = getRemoteDevice;

exports.getDeviceManager = getDeviceManager;

exports.ptr = require('./ptr');


var binary = require('node-pre-gyp');
var path = require('path');
var bindingPath = binary.find(path.resolve(
    path.join(__dirname, '../package.json')));
var binding = require(bindingPath);
var DeviceManager = require('./device_manager');
var deviceManager = null;

function getDeviceManager() {
  if (deviceManager === null) {
    deviceManager = new DeviceManager(new binding.DeviceManager());
  }
  return deviceManager;
}

function getLocalDevice(timeout) {
  return getDevice('local', 0);
}
function getUsbDevice(timeout) {
  return getDevice('tether', timeout || 0);
}
function getRemoteDevice() {
  return getDevice('remote', 0);
}
function getDevice(type, timeout) {
  return new Promise(function (resolve, reject) {
    findDevice(type)
    .then(resolve)
    .catch(function (error) {
      if (timeout === 0) {
        reject(error);
        return;
      }

      var mgr = getDeviceManager();

      function onChanged() {
        findDevice(type).then(deliverResult);
      }
      function onTimeout() {
        deliverResult(null);
      }

      mgr.events.listen('changed', onChanged);
      var timer = (typeof timeout === 'number') ?
          setTimeout(onTimeout, timeout) : null;

      function deliverResult(device) {
        clearTimeout(timer);
        mgr.events.unlisten('changed', onChanged);

        if (device !== null) {
          resolve(device);
        } else {
          reject(error);
        }
      }

      findDevice(type).then(deliverResult);
    });
  });
}

function findDevice(type) {
  return new Promise(function (resolve, reject) {
    getDeviceManager().enumerateDevices()
    .then(function (devices) {
      var matching = devices.filter(function (device) { return device.type === type; });
      if (matching.length > 0) {
        resolve(matching[0]);
      } else {
        reject(new Error('Device not found'));
      }
    })
    .catch(reject);
  });
}
