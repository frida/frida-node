'use strict';

module.exports = ModuleMap;


var AddressMap = require('./address_map');

function ModuleMap(modules) {
  AddressMap.call(this, modules, getAddress, getSize);
}

function getAddress(m) {
  return m.baseAddress;
}

function getSize(m) {
  return m.size;
}

ModuleMap.prototype = Object.create(AddressMap.prototype);
