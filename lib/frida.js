'use strict';

exports.spawn = function (argv) {
  return getLocalDevice().then(function (device) {
    return device.spawn(argv);
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

exports.injectLibraryFile = function (target, path, entrypoint, data) {
  return getLocalDevice().then(function (device) {
    return device.injectLibraryFile(target, path, entrypoint, data);
  });
};

exports.injectLibraryBlob = function (target, blob, entrypoint, data) {
  return getLocalDevice().then(function (device) {
    return device.injectLibraryBlob(target, blob, entrypoint, data);
  });
};

exports.enumerateDevices = function () {
  return getDeviceManager().enumerateDevices();
};

exports.getLocalDevice = getLocalDevice;

exports.getUsbDevice = getUsbDevice;

exports.getRemoteDevice = getRemoteDevice;

exports.getDevice = getDevice;

exports.getDeviceManager = getDeviceManager;

exports.ptr = require('./ptr');


var binding = require('bindings')({
  bindings: 'frida_binding',
  try: [
    [ 'module_root', 'build', 'bindings' ],
    [ 'module_root', 'build', 'Debug', 'bindings' ],
    [ 'module_root', 'build', 'Release', 'bindings' ],
    [ 'module_root', 'out', 'Debug', 'bindings' ],
    [ 'module_root', 'Debug', 'bindings' ],
    [ 'module_root', 'out', 'Release', 'bindings' ],
    [ 'module_root', 'Release', 'bindings' ],
    [ 'module_root', 'build', 'default', 'bindings' ],
    [ 'module_root', 'compiled', 'version', 'platform', 'arch', 'bindings' ],
    [ process.cwd(), 'bindings' ],
  ]
});
var DeviceManager = require('./device_manager');
var deviceManager = null;

function getDeviceManager() {
  if (deviceManager === null) {
    deviceManager = new DeviceManager(new binding.DeviceManager());
  }
  return deviceManager;
}

function getLocalDevice() {
  return _getDevice(function (device) { return device.type === 'local'; }, 0);
}
function getUsbDevice(timeout) {
  return _getDevice(function (device) { return device.type === 'tether'; }, timeout || 0);
}
function getRemoteDevice() {
  return _getDevice(function (device) { return device.type === 'remote'; }, 0);
}
function getDevice(id, timeout) {
  return _getDevice(function (device) { return device.id === id; }, timeout || 0);
}
function _getDevice(predicate, timeout) {
  return new Promise(function (resolve, reject) {
    findDevice(predicate)
    .then(resolve)
    .catch(function (error) {
      if (timeout === 0) {
        reject(error);
        return;
      }

      var mgr = getDeviceManager();

      function onChanged() {
        findDevice(predicate).then(deliverResult, noop);
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

      findDevice(predicate).then(deliverResult, noop);
    });
  });
}

function findDevice(predicate) {
  return new Promise(function (resolve, reject) {
    getDeviceManager().enumerateDevices()
    .then(function (devices) {
      var matching = devices.filter(predicate);
      if (matching.length > 0)
        resolve(matching[0]);
      else
        reject(new Error('Device not found'));
    })
    .catch(reject);
  });
}

function noop() {
}
