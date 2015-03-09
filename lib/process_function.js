'use strict';

module.exports = ProcessFunction;


function ProcessFunction(name, absoluteAddress) {
  Object.defineProperty(this, 'name', {
    enumerable: true,
    value: name
  });

  Object.defineProperty(this, 'absoluteAddress', {
    enumerable: true,
    value: absoluteAddress
  });
}
