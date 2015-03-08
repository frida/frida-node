var frida = require('..');
var should = require('should');
var spawn = require('child_process').spawn;

describe('Session', function () {
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
});
