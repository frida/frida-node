'use strict';

module.exports = ModuleFunction;


var ProcessFunction = require('./process_function');

function ModuleFunction(module, name, relativeAddress, exported) {
  ProcessFunction.call(this, name, module.baseAddress.add(relativeAddress));

  Object.defineProperty(this, 'module', {
    enumerable: true,
    value: module
  });

  Object.defineProperty(this, 'relativeAddress', {
    enumerable: true,
    value: relativeAddress
  });

  Object.defineProperty(this, 'exported', {
    enumerable: true,
    value: exported
  });
}

ModuleFunction.prototype = Object.create(ProcessFunction.prototype);
