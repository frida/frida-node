'use strict';

/* global describe, before, after, afterEach, gc, it */

var data = require('./data');
var frida = require('..');
var should = require('should');
var spawn = require('child_process').spawn;

describe('Script', function () {
  var target;
  var session;

  before(function () {
    target = spawn(data.targetProgram, [], {
      stdio: 'inherit'
    });
    return frida.attach(target.pid)
    .then(function (s) {
      session = s;
    });
  });

  after(function () {
    target.kill('SIGKILL');
  });

  afterEach(gc);

  it('should support rpc', function (done) {
    var script, exp;
    session.createScript(
      '"use strict";' +
      '' +
      'rpc.exports = {' +
        'add(a, b) {' +
          'const result = a + b;' +
          'if (result < 0)' +
            'throw new Error("No");' +
          'return result;' +
        '},' +
        'sub(a, b) {' +
          'return a - b;' +
        '},' +
        'speak() {' +
          'const buf = Memory.allocUtf8String("Yo");' +
          'return Memory.readByteArray(buf, 2);' +
        '}' +
      '};')
    .then(function (s) {
      script = s;
      return script.load();
    })
    .then(function () {
      return script.getExports();
    })
    .then(function (e) {
      exp = e;
      exp.should.have.property('add');
      exp.should.have.property('sub');
      return exp.add(2, 3);
    })
    .then(function (result) {
      result.should.equal(5);
      return exp.sub(5, 3);
    })
    .then(function (result) {
      result.should.equal(2);
      return exp.add(1, -2);
    })
    .catch(function (error) {
      error.message.should.equal('No');
      return exp.speak();
    })
    .then(function (buf) {
      should.deepEqual(buf.toJSON().data, [0x59, 0x6f]);
      done();
    })
    .catch(function (error) {
      console.error(error.message);
    });
  });
});
