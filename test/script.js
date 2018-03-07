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

  it('should support rpc', co.wrap(function *() {
    const script = yield session.createScript(
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
      '};');
    yield script.load();

    const agent = yield script.getExports();

    agent.should.have.property('add');
    agent.should.have.property('sub');

    (yield agent.add(2, 3)).should.equal(5);
    (yield agent.sub(5, 3)).should.equal(2);

    let thrownException = null;
    try {
      yield agent.add(1, -2);
    } catch (e) {
      thrownException = e;
    }
    should(thrownException).not.equal(null);
    thrownException.message.should.equal('No');

    const buf = yield agent.speak();
    should.deepEqual(buf.toJSON().data, [0x59, 0x6f]);
  }));

  it('should fail rpc request if post() fails', co.wrap(function *() {
    const script = yield session.createScript(
      '"use strict";' +
      '' +
      'rpc.exports = {' +
        'init: function () {' +
        '}' +
      '};');
    yield script.load();

    const agent = yield script.getExports();

    yield session.detach();

    let thrownException = null;
    try {
      yield agent.init();
    } catch (e) {
      thrownException = e;
    }
    should(thrownException).not.equal(null);
    thrownException.message.should.equal('Script is destroyed');
  }));

  it('should fail rpc request if script is unloaded mid-request', co.wrap(function *() {
    const script = yield session.createScript(
      '"use strict";' +
      '' +
      'rpc.exports = {' +
        'waitForever: function () {' +
          'return new Promise(function () {});' +
        '}' +
      '};');
    yield script.load();

    const agent = yield script.getExports();

    setTimeout(() => script.unload(), 100);

    let thrownException = null;
    try {
      yield agent.waitForever();
    } catch (e) {
      thrownException = e;
    }
    should(thrownException).not.equal(null);
    thrownException.message.should.equal('Script is destroyed');
  }));

  it('should fail rpc request if session gets detached mid-request', co.wrap(function *() {
    const script = yield session.createScript(
      '"use strict";' +
      '' +
      'rpc.exports = {' +
        'waitForever: function () {' +
          'return new Promise(function () {});' +
        '}' +
      '};');
    yield script.load();

    const agent = yield script.getExports();

    setTimeout(() => target.kill('SIGKILL'), 100);

    let thrownException = null;
    try {
      yield agent.waitForever();
    } catch (e) {
      thrownException = e;
    }
    should(thrownException).not.equal(null);
    thrownException.message.should.equal('Script is destroyed');
  }));

  it('should support custom log handler', co.wrap(function *() {
    const script = yield session.createScript(
      '"use strict";' +
      '' +
      'console.error(new Error("test message"))');

    script.setLogHandler(function (level, text) {
      should(level).equal('error');
      should(text).equal('Error: test message');
    });

    yield script.load();
  }));
});
