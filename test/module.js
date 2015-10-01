'use strict';

/* global describe, before, after, afterEach, gc, it */

var data = require('./data');
var frida = require('..');
var should = require('should');
var spawn = require('child_process').spawn;

describe('Module', function () {
  var target;
  var module;

  before(function () {
    target = spawn(data.targetProgram, [], {
      stdio: 'inherit'
    });
    return frida.attach(target.pid)
    .then(function (session) {
      return session.enumerateModules();
    })
    .then(function (modules) {
      module = modules[1];
    });
  });

  after(function () {
    target.kill('SIGKILL');
  });

  afterEach(gc);

  it('should enumerate exports', function () {
    module.should.have.property('enumerateExports');
    return module.enumerateExports().then(function (exports) {
      exports.length.should.be.above(0);
      var e = exports[0];
      e.should.have.properties('name', 'absoluteAddress',
          'module', 'relativeAddress', 'exported');
      e.name.should.be.an.instanceof(String);
      e.exported.should.be.an.instanceof(Boolean);
      e.exported.should.equal(true);
    });
  });

  it('should enumerate ranges', function () {
    module.should.have.property('enumerateRanges');
    return module.enumerateRanges('r--').then(function (ranges) {
      ranges.length.should.be.above(0);
      var r = ranges[0];
      r.should.have.properties('baseAddress', 'size', 'protection');
      r.size.should.be.an.instanceof(Number);
      r.protection.should.be.an.instanceof(String);
    });
  });
});
