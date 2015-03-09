'use strict';

module.exports = Module;


var ModuleFunction = require('./module_function');
var ptr = require('./ptr');
var request = Symbol('request');
var exportsPromise = Symbol('exportsPromise');

function Module(name, baseAddress, size, path, session, sessionRequest) {
  Object.defineProperty(this, 'name', {
    enumerable: true,
    value: name
  });

  Object.defineProperty(this, 'baseAddress', {
    enumerable: true,
    value: baseAddress
  });

  Object.defineProperty(this, 'size', {
    enumerable: true,
    value: size
  });

  Object.defineProperty(this, 'path', {
    enumerable: true,
    value: path
  });

  Object.defineProperty(this, request, {
    value: session[sessionRequest].bind(session)
  });

  this[exportsPromise] = null;
}

Module.prototype.enumerateExports = function () {
  if (this[exportsPromise] === null) {
    this[exportsPromise] = new Promise(function (resolve, reject) {
      this[request]('module:enumerate-exports', { modulePath: this.path })
      .then(function (result) {
        resolve(result.exports.map(function (e) {
          var relativeAddress = ptr(e.address).subtract(this.baseAddress);
          return new ModuleFunction(this, e.name, relativeAddress, true);
        }, this));
      }.bind(this))
      .catch(reject);
    }.bind(this));
  }
  return this[exportsPromise];
};
