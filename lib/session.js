'use strict';

module.exports = Session;


var fs = require('fs');
var Module = require('./module');
var path = require('path');
var ptr = require('./ptr');
var Range = require('./range');
var $ = Symbol('impl');
var pending = Symbol('pending');
var nextRequestId = Symbol('nextRequestId');
var modulesPromise = Symbol('modulesPromise');
var request = Symbol('request');
var onMessage = Symbol('onMessage');
var getSessionScript = Symbol('getSessionScript');
var scriptPromise = Symbol('scriptPromise');

function Session(impl) {
  Object.defineProperty(this, $, { value: impl });

  Object.defineProperty(this, 'pid',
      Object.getOwnPropertyDescriptor(impl, 'pid'));

  this[pending] = {};
  this[nextRequestId] = 1;
}

Session.prototype.detach = function () {
  return this[$].detach();
};

Session.prototype.enumerateModules = function () {
  if (!this[modulesPromise]) {
    this[modulesPromise] = new Promise(function (resolve, reject) {
      this[request]('process:enumerate-modules')
      .then(function (result) {
        resolve(result.modules.map(function (m) {
          return new Module(m.name, ptr(m.base), m.size, m.path, this);
        }, this));
      }.bind(this))
      .catch(reject);
    }.bind(this));
  }
  return this[modulesPromise];
};

Session.prototype.enumerateRanges = function (protection) {
  return this[request]('process:enumerate-ranges', { protection: protection })
  .then(function (result) {
    return result.ranges.map(function (r) {
      return new Range(ptr(r.base), r.size, r.protection);
    });
  });
};

Session.prototype.findBaseAddress = function (moduleName) {
  return this[request]('module:find-base-address', { moduleName: moduleName })
  .then(function (result) {
    return ptr(result.baseAddress);
  });
};

Session.prototype.readBytes = function (address, size) {
  return this[request]('memory:read-byte-array', {
    address: address.toString(),
    size: size
  })
  .then(function (result) {
    var data = result[1];
    return data;
  });
};

Session.prototype.createScript = function (source) {
  return this[$].createScript(source);
};

Session.prototype[request] = function (name, payload) {
  return new Promise(function (resolve, reject) {
    this[getSessionScript]()
    .then(function (script) {
      var id = this[nextRequestId]++;
      this[pending][id] = function (err, result, data) {
        if (!err) {
          if (data.length > 0) {
            resolve([result, data]);
          } else {
            resolve(result);
          }
        } else {
          reject(err);
        }
      };
      script.postMessage({
        id: id,
        name: name,
        payload: payload || {}
      });
    }.bind(this))
    .catch(reject);
  }.bind(this));
};

Session.prototype[onMessage] = function (message, data) {
  switch (message.type) {
    case 'send':
      var stanza = message.payload;
      var callback = this[pending][stanza.id];
      delete this[pending][stanza.id];
      switch (stanza.name) {
        case 'request:result':
          callback(null, stanza.payload, data);
          break;
        case 'request:error':
          callback(new Error(stanza.payload), null);
          break;
      }
      break;
    case 'log':
      console.log('[session_script.js] ' + message.payload);
      break;
    case 'error':
      console.error('[session_script.js:' + message.lineNumber + '] ' + message.description);
      break;
  }
};

Session.prototype[getSessionScript] = function () {
  if (!this[scriptPromise]) {
    this[scriptPromise] = new Promise(function (resolve, reject) {
      fs.readFile(path.join(path.dirname(module.filename),
          'session_script.js'), { encoding: 'utf-8' }, function (err, source) {
        if (err) {
          reject(err);
          return;
        }

        this.createScript(source)
        .then(function (script) {
          script.events.listen('message', this[onMessage].bind(this));
          return script.load().then(function () {
            return script;
          });
        }.bind(this))
        .then(resolve)
        .catch(reject);
      }.bind(this));
    }.bind(this));
  }
  return this[scriptPromise];
};
