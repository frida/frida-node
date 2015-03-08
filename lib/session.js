'use strict';

module.exports = Session;


var bigInt = require('big-integer');
var fs = require('fs');
var Module = require('./module');
var path = require('path');
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
      .then(function (modules) {
        resolve(modules.map(function (m) {
          return new Module(m.name, bigInt(m.base, 16), m.size, m.path, this);
        }, this));
      }.bind(this))
      .catch(reject);
    }.bind(this));
  }
  return this[modulesPromise];
};

Session.prototype.enumerateRanges = function (protection) {
  return new Promise(function (resolve, reject) {
    this[request]('process:enumerate-ranges', { protection: protection })
    .then(function (ranges) {
      resolve(ranges.map(function (r) {
        return new Range(bigInt(r.base, 16), r.size, r.protection);
      }));
    })
    .catch(reject);
  }.bind(this));
};

Session.prototype.createScript = function (source) {
  return this[$].createScript(source);
};

Session.prototype[request] = function (name, payload) {
  return new Promise(function (resolve, reject) {
    this[getSessionScript]()
    .then(function (script) {
      var id = this[nextRequestId]++;
      this[pending][id] = function (err, result) {
        if (!err) {
          resolve(result);
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
          callback(null, stanza.payload);
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
