'use strict';

/* global Process, Module, Memory, ptr, send, recv */

var handlers = {};

handlers['process:enumerate-modules'] = function () {
  return new Promise(function (resolve, reject) {
    var modules = [];
    Process.enumerateModules({
      onMatch: function (m) {
        modules.push(m);
      },
      onComplete: function () {
        resolve({ modules: modules });
      }
    });
  });
};

handlers['process:enumerate-ranges'] = function (payload) {
  return new Promise(function (resolve, reject) {
    var ranges = [];
    Process.enumerateRanges(payload.protection, {
      onMatch: function (r) {
        ranges.push(r);
      },
      onComplete: function () {
        resolve({ ranges: ranges });
      }
    });
  });
};

handlers['module:find-base-address'] = function (payload) {
  return new Promise(function (resolve, reject) {
    var address = Module.findBaseAddress(payload.moduleName);
    resolve({ baseAddress: (address !== null) ? address : "0" });
  });
};

handlers['memory:read-byte-array'] = function (payload) {
  return new Promise(function (resolve, reject) {
    var data = Memory.readByteArray(ptr(payload.address), payload.size);
    resolve([{}, data]);
  });
};

handlers['memory:write-byte-array'] = function (payload) {
  return new Promise(function (resolve, reject) {
    var base = ptr(payload.address);
    var data = payload.data;
    for (var i = 0; i !== data.length; i++) {
      Memory.writeU8(base.add(i), data[i]);
    }
    resolve({});
  });
};

handlers['memory:read-utf8'] = function (payload) {
  return new Promise(function (resolve, reject) {
    resolve({
      string: Memory.readUtf8String(ptr(payload.address), payload.length)
    });
  });
};

handlers['memory:write-utf8'] = function (payload) {
  return new Promise(function (resolve, reject) {
    Memory.writeUtf8String(ptr(payload.address), payload.string);
    resolve({});
  });
};

handlers['module:enumerate-exports'] = function (payload) {
  return new Promise(function (resolve, reject) {
    var exports = [];
    Module.enumerateExports(payload.modulePath, {
      onMatch: function (e) {
        if (e.type === 'function')
          exports.push(e);
      },
      onComplete: function () {
        resolve({ exports: exports });
      }
    });
  });
};

handlers['module:enumerate-ranges'] = function (payload) {
  return new Promise(function (resolve, reject) {
    var ranges = [];
    Module.enumerateRanges(payload.modulePath, payload.protection, {
      onMatch: function (r) {
        ranges.push(r);
      },
      onComplete: function () {
        resolve({ ranges: ranges });
      }
    });
  });
};

function onStanza(stanza) {
  var handler = handlers[stanza.name];
  handler(stanza.payload)
  .then(function (result) {
    var payload = result.length === 2 ? result[0] : result;
    var data = result.length === 2 ? result[1] : null;
    send({
      id: stanza.id,
      name: 'request:result',
      payload: payload
    }, data);
  })
  .catch(function (error) {
    send({
      id: stanza.id,
      name: 'request:error',
      payload: error.stack
    });
  });

  recv(onStanza);
}
recv(onStanza);
