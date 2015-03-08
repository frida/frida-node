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
