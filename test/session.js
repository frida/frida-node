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
      stdio: ['pipe', process.stdout, process.stderr]
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
});
