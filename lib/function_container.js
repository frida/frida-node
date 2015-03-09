'use strict';

module.exports = FunctionContainer;


function FunctionContainer() {
  Object.defineProperty(this, '_functions', {
    enumerable: false,
    value: {}
  });
}

FunctionContainer.prototype.ensureFunction = function (address) {
  return new Promise(function (resolve, reject) {
    var f = this._functions[address.toString(16)];
    if (f) {
      resolve(f);
    } else {
      this._doEnsureFunction(address).then(resolve, reject);
    }
  }.bind(this));
};

FunctionContainer.prototype._doEnsureFunction = function (address) {
  throw new Error('Not implemented');
};
