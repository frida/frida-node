'use strict';

/* global describe, afterEach, gc, it */

var frida = require('..');
var should = require('should');

describe('Device', function () {
  afterEach(gc);

  it('should have some metadata', function () {
    return frida.getLocalDevice().then(function (device) {
      device.should.have.properties('id', 'name', 'icon', 'type', 'events');
      device.id.should.be.an.instanceof(String);
      device.name.should.be.an.instanceof(String);
      device.name.should.equal('Local System');
      device.type.should.be.an.instanceof(String);
      device.type.should.equal('local');
    });
  });

  it('should enumerate processes', function () {
    return frida.getLocalDevice()
    .then(function (device) {
      return device.enumerateProcesses();
    })
    .then(function (processes) {
      processes.length.should.be.above(0);
      var process = processes[0];
      process.should.have.properties('pid', 'name', 'smallIcon', 'largeIcon');
      process.pid.should.be.an.instanceof(Number);
      process.name.should.be.an.instanceof(String);
    });
  });
});
