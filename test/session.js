'use strict';

/* global describe, before, after, afterEach, gc, it */

var data = require('./data');
var frida = require('..');
var should = require('should');
var spawn = require('child_process').spawn;

describe('Session', function () {
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

  it('should have some metadata', function () {
    session.should.have.property('pid');
    session.pid.should.equal(target.pid);
  });

  it('should enumerate modules', function () {
    session.should.have.property('enumerateModules');
    return session.enumerateModules().then(function (modules) {
      modules.length.should.be.above(0);
      var module = modules[0];
      module.should.have.properties('name', 'baseAddress', 'size', 'path');
      module.name.should.be.an.instanceof(String);
      module.size.should.be.an.instanceof(Number);
      module.path.should.be.an.instanceof(String);
    });
  });

  it('should enumerate exports for a module', function () {
    return session.enumerateModules().then(function (modules) {
      return session.enumerateExports(modules[1].name).then(function (exp) {
        exp.length.should.be.above(0);
        var e = exp[0];
        e.should.have.property('name');
        e.should.have.property('address');
      });
    });
  });

  it('should enumerate ranges', function () {
    session.should.have.property('enumerateRanges');
    return session.enumerateRanges('r--').then(function (ranges) {
      ranges.length.should.be.above(0);
      var range = ranges[0];
      range.should.have.properties('baseAddress', 'size', 'protection');
      range.size.should.be.an.instanceof(Number);
      range.protection.should.be.an.instanceof(String);
    });
  });

  it('should enumerate ranges scoped to a module', function () {
    return session.enumerateRanges('r--').then(function (allRanges) {
      return session.enumerateModules().then(function (modules) {
        return session.enumerateRanges('r--', { scope: modules[0].name }).then(function (ranges) {
          ranges.length.should.be.above(0);
          ranges.length.should.be.below(allRanges.length);
        });
      });
    });
  });

  it('should find base address', function () {
    session.should.have.property('findBaseAddress');
    return session.enumerateModules().then(function (modules) {
      var m = modules[0];
      return session.findBaseAddress(m.name).then(function (baseAddress) {
        baseAddress.equals(m.baseAddress).should.equal(true);
        return session.findBaseAddress('_does_not_exist$#@$');
      })
      .then(function (baseAddress) {
        baseAddress.isZero().should.equal(true);
      });
    });
  });

  it('should should provide memory access', function (done) {
    session.createScript(
      'hello = Memory.allocUtf8String(\"Hello\");\n' +
      'send(hello);\n')
    .then(function (script) {
      var getHelloAddress = new Promise(function (resolve, reject) {
        script.events.listen('message', onMessage);
        function onMessage(message) {
          script.events.unlisten('message', onMessage);
          resolve(message.payload);
        }
      });
      getHelloAddress.then(function (helloAddressStr) {
        var helloAddress = frida.ptr(helloAddressStr);

        session.should.have.property('readBytes');
        return session.readBytes(helloAddress, 6)
        .then(function (buf) {
          should.deepEqual(buf.toJSON().data,
              [0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x00]);

          session.should.have.property('readUtf8');
          return session.readUtf8(helloAddress);
        })
        .then(function (str) {
          str.should.equal('Hello');

          session.should.have.property('writeBytes');
          return session.writeBytes(helloAddress, [0x59, 0x6f, 0x00]);
        })
        .then(function () {
          return session.readBytes(helloAddress, 6);
        })
        .then(function (buf) {
          should.deepEqual(buf.toJSON().data,
              [0x59, 0x6f, 0x00, 0x6c, 0x6f, 0x00]);

          return session.readUtf8(helloAddress);
        })
        .then(function (str) {
          str.should.equal('Yo');

          session.should.have.property('writeUtf8');
          return session.writeUtf8(helloAddress, 'Hei');
        })
        .then(function () {
          return session.readBytes(helloAddress, 6);
        })
        .then(function (buf) {
          should.deepEqual(buf.toJSON().data,
              [0x48, 0x65, 0x69, 0x00, 0x6f, 0x00]);

          return session.readUtf8(helloAddress);
        })
        .then(function (str) {
          str.should.equal('Hei');

          done();
        });
      });
      script.load();
    });
  });

  it('should act as a function container', function () {
    return session.enumerateModules().then(function (modules) {
      var m = modules[1];
      return m.enumerateExports().then(function (exports) {
        var e = exports[0];

        return session.ensureFunction(e.absoluteAddress)
        .then(function (f) {
          f.should.equal(e);
        });
      });
    });
  });
});
