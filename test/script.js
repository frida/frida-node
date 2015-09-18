'use strict';

/* global describe, before, after, afterEach, gc, it */

var frida = require('..');
var should = require('should');
var spawn = require('child_process').spawn;

describe('Script', function () {
  var target;
  var session;

  before(function () {
    target = spawn(
        process.platform === 'win32' ? 'C:\\Windows\\notepad.exe' : '/bin/cat',
        [], {
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
      done();
    });
  });

  it('should support common-js', function (done) {
    var script, exp;

    frida.load(require.resolve('./cjs'))
    .then(function (source) {
      return session.createScript(source);
    })
    .then(function (s) {
      script = s;
      return script.load();
    })
    .then(function () {
      return script.getExports();
    })
    .then(function (e) {
      exp = e;
      return exp.add(5, 2);
    })
    .then(function (result) {
      result.should.equal(7);
      return exp.match('bar.foo', '*.foo');
    })
    .then(function (result) {
      result.should.equal(true);
      script.events.listen('message', function (message) {
        message.type.should.equal('error');
        message.description.should.equal('Error: Oops!');
        message.stack.should.equal('Error: Oops!\n    at index.js:15:1');
        message.fileName.should.equal('index.js');
        message.lineNumber.should.equal(15);
        message.columnNumber.should.equal(1);
        done();
      });
      return exp.crashLater();
    })
    .catch(function (error) {
      console.error(error.message);
    });
  });
});
