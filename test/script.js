'use strict';

/* global describe, beforeEach, afterEach, gc, it */

const co = require('co');
const data = require('./data');
const frida = require('..');
const should = require('should');
const spawn = require('child_process').spawn;

describe('Script', function () {
  var target;
  var session;

  beforeEach(function () {
    target = spawn(data.targetProgram, [], {
      stdio: ['pipe', process.stdout, process.stderr]
    });
    return frida.attach(target.pid)
    .then(function (s) {
      session = s;
    });
  });

  afterEach(function () {
    target.kill('SIGKILL');
    gc();
  });

  it('should support rpc', function (done) {
    var script, exp;
    session.createScript(
      '"use strict";' +
      '' +
      'rpc.exports = {' +
        'add: function (a, b) {' +
          'var result = a + b;' +
          'if (result < 0)' +
            'throw new Error("No");' +
          'return result;' +
        '},' +
        'sub: function (a, b) {' +
          'return a - b;' +
        '},' +
        'speak: function () {' +
          'var buf = Memory.allocUtf8String("Yo");' +
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

  it('should fail rpc request if post() fails', co.wrap(function *() {
    const script = yield session.createScript(
      '"use strict";' +
      '' +
      'rpc.exports = {' +
        'init: function () {' +
        '}' +
      '};');
    yield script.load();

    const api = yield script.getExports();

    yield session.detach();

    let thrownException = null;
    try {
      yield api.init();
    } catch (e) {
      thrownException = e;
    }

    if (thrownException === null)
      throw new Error('Should not succeed');
    thrownException.message.should.equal('Script is destroyed');
  }));
});
