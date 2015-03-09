'use strict';

module.exports = FunctionMap;


var AddressMap = require('./address_map');

function FunctionMap(functions) {
  AddressMap.call(this, functions, getAddress, getSize);
}

function getAddress(f) {
  return f.absoluteAddress;
}

function getSize(f) {
  return 1;
}

FunctionMap.prototype = Object.create(AddressMap.prototype);
