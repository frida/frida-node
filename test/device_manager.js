'use strict';

/* global describe, afterEach, gc, it */

var frida = require('..');
var should = require('should');

describe('DeviceManager', function () {
  afterEach(gc);

  it('should enumerate devices', function () {
    var deviceManager = frida.getDeviceManager();
    return deviceManager.enumerateDevices().then(function (devices) {
      devices.length.should.be.above(0);
    });
  });
});
