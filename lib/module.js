'use strict';

module.exports = Module;


function Module(name, baseAddress, size, path, session) {
  Object.defineProperty(this, 'name', {
    enumerable: true,
    value: name
  });

  Object.defineProperty(this, 'baseAddress', {
    enumerable: true,
    value: baseAddress
  });

  Object.defineProperty(this, 'size', {
    enumerable: true,
    value: size
  });

  Object.defineProperty(this, 'path', {
    enumerable: true,
    value: path
  });
}
