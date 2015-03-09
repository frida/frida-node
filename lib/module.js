'use strict';

module.exports = Module;


var FunctionContainer = require('./function_container');
var ModuleFunction = require('./module_function');
var ptr = require('./ptr');
var Range = require('./range');
var request = Symbol('request');
var exportsPromise = Symbol('exportsPromise');
var functionsInitialized = Symbol('functionsInitialized');

function Module(name, baseAddress, size, path, session, sessionRequest) {
  FunctionContainer.call(this);

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

  this[functionsInitialized] = false;
}

Module.prototype = Object.create(FunctionContainer.prototype);

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

Module.prototype.enumerateRanges = function (protection) {
  return this[request]('module:enumerate-ranges', {
    modulePath: this.path,
    protection: protection
  })
  .then(function (result) {
    return result.ranges.map(function (r) {
      return new Range(ptr(r.base), r.size, r.protection);
    });
  });
};

Module.prototype._doEnsureFunction = function (relativeAddress) {
  return this.enumerateExports().then(function (exports) {
    var mf;

    if (!this[functionsInitialized]) {
      for (var i = 0; i !== exports.length; i++) {
        mf = exports[i];
        this._functions[mf.relativeAddress.toString(16)] = mf;
      }
      this[functionsInitialized] = true;
    }

    var id = relativeAddress.toString(16);
    mf = this._functions[id];
    if (!mf) {
      mf = new ModuleFunction(this, 'sub_' + id, relativeAddress, false);
      this._functions[id] = mf;
    }
    return mf;
  }.bind(this));
};
