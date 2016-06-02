'use strict';

module.exports = Session;


var fs = require('fs');
var FunctionContainer = require('./function_container');
var Module = require('./module');
var ModuleMap = require('./module_map');
var path = require('path');
var ProcessFunction = require('./process_function');
var ptr = require('./ptr');
var Range = require('./range');
var Script = require('./script');
var $ = Symbol('impl');
var pending = Symbol('pending');
var nextRequestId = Symbol('nextRequestId');
var modulesPromise = Symbol('modulesPromise');
var request = Symbol('request');
var onMessage = Symbol('onMessage');
var getSessionScript = Symbol('getSessionScript');
var scriptPromise = Symbol('scriptPromise');
var moduleMap = Symbol('moduleMap');

function Session(impl) {
  FunctionContainer.call(this);

  Object.defineProperty(this, $, { value: impl });

  ['pid', 'events'].forEach(function (prop) {
    Object.defineProperty(this, prop,
        Object.getOwnPropertyDescriptor(impl, prop));
  }, this);

  this[pending] = {};
  this[nextRequestId] = 1;

  this[modulesPromise] = null;

  this[scriptPromise] = null;

  this[moduleMap] = null;
}

Session.prototype = Object.create(FunctionContainer.prototype);

Session.prototype.detach = function () {
  return this[$].detach();
};

Session.prototype.enumerateModules = function () {
  if (this[modulesPromise] === null) {
    this[modulesPromise] = new Promise(function (resolve, reject) {
      this[request]('process:enumerate-modules')
      .then(function (result) {
        resolve(result.modules.map(function (m) {
          return new Module(m.name, ptr(m.base), m.size, m.path, this, request);
        }, this));
      }.bind(this))
      .catch(reject);
    }.bind(this));
  }
  return this[modulesPromise];
};

Session.prototype.enumerateRanges = function (protection, options) {
  options = options || {};
  var scope = options.scope || null;
  var name = "process:enumerate-ranges";
  var data = { protection: protection };
  if (scope !== null) {
    name = "module:enumerate-ranges";
    data.modulePath = scope;
  }
  return this[request](name, data)
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

Session.prototype.writeBytes = function (address, data) {
  return this[request]('memory:write-byte-array', {
    address: address.toString(),
    data: data
  });
};

Session.prototype.readUtf8 = function (address, length) {
  return this[request]('memory:read-utf8', {
    address: address.toString(),
    length: length || -1
  })
  .then(function (result) {
    return result.string;
  });
};

Session.prototype.writeUtf8 = function (address, string) {
  return this[request]('memory:write-utf8', {
    address: address.toString(),
    string: string
  });
};

Session.prototype.enumerateExports = function (moduleName) {
  return this[request]('module:enumerate-exports', {
    modulePath: moduleName
  })
  .then(function (result) {
    return result.exports.map(function (e) {
      e.address = ptr(e.address);
      return e;
    });
  });
};

Session.prototype.createScript = function (source, options) {
  options = options || {};
  var name = options.name || null;
  return this[$].createScript(name, source).then(function (impl) {
    return new Script(impl);
  });
};

Session.prototype.createScriptFromBytes = function (bytes, options) {
  options = options || {};
  var name = options.name || null;
  return this[$].createScriptFromBytes(name, bytes).then(function (impl) {
    return new Script(impl);
  });
};

Session.prototype.compileScript = function (source) {
  return this[$].compileScript(source);
};

Session.prototype.enableDebugger = function (options) {
  options = options || {};
  var port = options.port || 0;
  return this[$].enableDebugger(port);
};

Session.prototype.disableDebugger = function () {
  return this[$].disableDebugger();
};

Session.prototype.disableJit = function () {
  return this[$].disableJit();
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
  if (this[scriptPromise] === null) {
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

Session.prototype._doEnsureFunction = function (absoluteAddress) {
  return this.enumerateModules().then(function (modules) {
    if (this[moduleMap] === null) {
      this[moduleMap] = new ModuleMap(modules);
    }
    var m = this[moduleMap].lookup(absoluteAddress);
    if (m !== null) {
      return m.ensureFunction(absoluteAddress.subtract(m.baseAddress));
    }
    var f = new ProcessFunction('dsub_' + absoluteAddress.toString(16),
        absoluteAddress);
    this._functions[absoluteAddress.toString(16)] = f;
    return f;
  }.bind(this));
};
