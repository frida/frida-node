'use strict';

module.exports = Script;


var $ = Symbol('impl');
var messageHandlers = Symbol('messageHandlers');
var onDestroyed = Symbol('onDestroyed');
var onDestroyedCallback = Symbol('onDestroyedCallback');
var onMessage = Symbol('onMessage');
var onMessageCallback = Symbol('onMessageCallback');

function Script(impl) {
  Object.defineProperty(this, $, { value: impl });

  Object.defineProperty(this, 'events', { value: new ScriptEvents(impl) });
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

function ScriptEvents(impl) {
  Object.defineProperty(this, $, { value: impl });

  this[messageHandlers] = [];

  this[onDestroyedCallback] = this[onDestroyed].bind(this);
  this[onMessageCallback] = this[onMessage].bind(this);
  impl.events.listen('destroyed', this[onDestroyedCallback]);
  impl.events.listen('message', this[onMessageCallback]);
}

ScriptEvents.prototype[onDestroyed] = function () {
  var impl = this[$];
  impl.events.unlisten('message', this[onMessageCallback]);
  impl.events.unlisten('destroyed', this[onDestroyedCallback]);
};

ScriptEvents.prototype[onMessage] = function (message, data) {
  if (message.type === 'log') {
    console.log(message.payload);
  }
};

ScriptEvents.prototype.listen = function (signal, callback) {
  if (signal != 'message') {
    this[$].events.listen(signal, callback);
    return;
  }

  var handler = {
    callback: callback,
    proxy: function (message, data) {
      if (message.type !== 'log') {
        callback(message, data);
      }
    }
  };
  this[messageHandlers].push(handler);
  this[$].events.listen(signal, handler.proxy);
};

ScriptEvents.prototype.unlisten = function (signal, callback) {
  if (signal != 'message') {
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
