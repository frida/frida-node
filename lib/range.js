'use strict';

module.exports = Range;


function Range(baseAddress, size, protection) {
  Object.defineProperty(this, 'baseAddress', {
    enumerable: true,
    value: baseAddress
  });

  Object.defineProperty(this, 'size', {
    enumerable: true,
    value: size
  });

  Object.defineProperty(this, 'protection', {
    enumerable: true,
    value: protection
  });
}
