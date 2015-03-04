'use strict';

module.exports = Device;


var Minimatch = require('minimatch').Minimatch;
var $ = Symbol('binding');
var getPid = Symbol('getPid');

function Device(binding) {
  Object.defineProperty(this, $, {value: binding});

  ['id', 'name', 'icon', 'type', 'events'].forEach(function (prop) {
    Object.defineProperty(this, prop, Object.getOwnPropertyDescriptor(binding, prop));
  }, this);
}

Device.prototype.enumerateProcesses = function () {
  return this[$].enumerateProcesses();
};

Device.prototype.getProcess = function (name) {
  return this.enumerateProcesses()
  .then(function (processes) {
    var mm = new Minimatch(name.toLowerCase());
    var matching = processes.filter(function (process) {
      return mm.match(process.name.toLowerCase());
    });
    if (matching.length === 1) {
      return matching[0];
    } else if (matching.length > 1) {
      throw new Error('Ambiguous name; it matches: ' + matching.map(function (process) {
        return process.name + ' (pid: ' + process.pid + ')';
      }).join(', '));
    } else {
      throw new Error('Process not found');
    }
  });
};

Device.prototype.spawn = function (commandLine) {
  return this[$].spawn(commandLine);
};

Device.prototype.resume = function (target) {
  return this[getPid](target).then(function (pid) {
    return this[$].resume(pid);
  }.bind(this));
};

Device.prototype.kill = function (target) {
  return this[getPid](target).then(function (pid) {
    return this[$].kill(pid);
  }.bind(this));
};

Device.prototype.attach = function (target) {
  return this[getPid](target).then(function (pid) {
    return this[$].attach(pid);
  }.bind(this));
};

Device.prototype[getPid] = function (target) {
  return new Promise(function (resolve, reject) {
    if (typeof target === 'number') {
      resolve(target);
    } else {
      this.getProcess(target)
      .then(function (process) {
        resolve(process.pid);
      })
      .catch(reject);
    }
  }.bind(this));
};
