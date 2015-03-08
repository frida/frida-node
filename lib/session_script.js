var handlers = {};

handlers['process:enumerate-modules'] = function () {
  return new Promise(function (resolve, reject) {
    var modules = [];
    Process.enumerateModules({
      onMatch: function (m) {
        modules.push(m);
      },
      onComplete: function () {
        resolve(modules);
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
        resolve(ranges);
      }
    });
  });
};

function onStanza(stanza) {
  var handler = handlers[stanza.name];
  handler(stanza.payload)
  .then(function (result) {
    send({
      id: stanza.id,
      name: 'request:result',
      payload: result
    });
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
