'use strict';

module.exports = Script;


var $ = Symbol('impl');
var messageHandlers = Symbol('messageHandlers');
var nextRequestId = Symbol('nextRequestId');
var pending = Symbol('pending');
var rpcRequest = Symbol('rpcRequest');
var onDestroyed = Symbol('onDestroyed');
var onDestroyedCallback = Symbol('onDestroyedCallback');
var onMessage = Symbol('onMessage');
var onMessageCallback = Symbol('onMessageCallback');
var onRpcMessage = Symbol('onRpcMessage');

function Script(impl) {
  Object.defineProperty(this, $, { value: impl });

  Object.defineProperty(this, 'events', { value: new ScriptEvents(impl, this[onRpcMessage].bind(this)) });

  this[pending] = {};
  this[nextRequestId] = 1;
}

Script.prototype.load = function () {
  return this[$].load();
};

Script.prototype.unload = function () {
  return this[$].unload();
};

Script.prototype.postMessage = function (message) {
  return this[$].postMessage(message);
};

Script.prototype.getExports = function () {
  return this[rpcRequest]('list', [])
  .then(function (methodNames) {
    var proxy = methodNames.reduce(function (proxy, methodName) {
      proxy[methodName] = makeRpcMethod(methodName, this);
      return proxy;
    }.bind(this), {});
    return Object.freeze(proxy);
  }.bind(this));
};

function makeRpcMethod(name, script) {
  return function () {
    return script[rpcRequest]('call', name, Array.prototype.slice.call(arguments));
  };
}

Script.prototype[rpcRequest] = function (operation) {
  var params = Array.prototype.slice.call(arguments, 1);

  return new Promise(function (resolve, reject) {
    var id = this[nextRequestId]++;
    this[pending][id] = function (err, result) {
      if (!err)
        resolve(result);
      else
        reject(err);
    };
    this.postMessage(['frida:rpc', id, operation].concat(params));
  }.bind(this));
};

Script.prototype[onRpcMessage] = function (id, operation, params, data) {
  if (operation === 'ok' || operation === 'error') {
    var callback = this[pending][id];
    delete this[pending][id];

    var value = null;
    var error = null;
    if (operation === 'ok') {
      value = (data.length > 0) ? data : params[0];
    } else {
      error = new Error(params[0]);

      var name = params[1];
      if (name)
        error.name = name;

      var stack = params[2];
      if (stack)
        error.stack = stack;
    }

    callback(error, value);
  }
};

function ScriptEvents(impl, onRpcMessageCallback) {
  Object.defineProperty(this, $, { value: impl });

  this[messageHandlers] = [];

  this[onDestroyedCallback] = this[onDestroyed].bind(this);
  this[onMessageCallback] = this[onMessage].bind(this);
  impl.events.listen('destroyed', this[onDestroyedCallback]);
  impl.events.listen('message', this[onMessageCallback]);

  this[onRpcMessage] = onRpcMessageCallback;
}

ScriptEvents.prototype[onDestroyed] = function () {
  var impl = this[$];
  impl.events.unlisten('message', this[onMessageCallback]);
  impl.events.unlisten('destroyed', this[onDestroyedCallback]);
};

ScriptEvents.prototype[onMessage] = function (message, data) {
  if (isRpcMessage(message)) {
    var rpcMessage = message.payload;
    var id = rpcMessage[1];
    var operation = rpcMessage[2];
    var params = rpcMessage.slice(3);
    this[onRpcMessage](id, operation, params, data);
  } else if (isLogMessage(message)) {
    const text = message.payload;
    switch (message.level) {
      case 'info':
        console.log(text);
        break;
      case 'warning':
        console.warn(text);
        break;
      case 'error':
        console.error(text);
        break;
    }
  }
};

ScriptEvents.prototype.listen = function (signal, callback) {
  if (signal !== 'message') {
    this[$].events.listen(signal, callback);
    return;
  }

  var handler = {
    callback: callback,
    proxy: function (message, data) {
      var isInternalMessage = isRpcMessage(message) || isLogMessage(message);
      if (!isInternalMessage)
        callback(message, data);
    }
  };
  this[messageHandlers].push(handler);
  this[$].events.listen(signal, handler.proxy);
};

ScriptEvents.prototype.unlisten = function (signal, callback) {
  if (signal !== 'message') {
    this[$].events.unlisten(signal, callback);
    return;
  }

  var handlers = this[messageHandlers];
  for (var i = 0; i !== handlers.length; i++) {
    var handler = handlers[i];
    if (handler.callback === callback) {
      this[$].events.unlisten(signal, handler.proxy);
      handlers.splice(i, 1);
      break;
    }
  }
};

function isLogMessage(message) {
  return message.type === 'log';
}

function isRpcMessage(message) {
  if (message.type !== 'send')
    return false;
  var payload = message.payload;
  if (!(payload instanceof Array))
    return false;
  return payload[0] === 'frida:rpc';
}
