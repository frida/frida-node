'use strict';

module.exports = AddressMap;


var items = Symbol('items');
var indices = Symbol('indices');
var getAddress = Symbol('getAddress');
var getSize = Symbol('getSize');

function AddressMap(collection, getAddressImpl, getSizeImpl) {
  this[items] = collection.slice().sort(function (a, b) {
    return getAddressImpl(a).compare(getAddressImpl(b));
  });
  this[indices] = this[items].map(function (item) {
    return getAddressImpl(item);
  });
  this[getAddress] = getAddressImpl;
  this[getSize] = getSizeImpl;
}

AddressMap.prototype.lookup = function (address) {
  var index = bisect(this[indices], address);
  if (index === 0) {
    return null;
  }
  var item = this[items][index - 1];
  if (address.greaterOrEquals(
      this[getAddress](item).add(this[getSize](item)))) {
    return null;
  }
  return item;
};

function bisect(addresses, address, low, high) {
  low = low || 0;
  high = high || addresses.length;

  while (low < high) {
    var middle = (low + high) >> 1;
    if (address.lesser(addresses[middle])) {
      high = middle;
    } else {
      low = middle + 1;
    }
  }

  return low;
}
