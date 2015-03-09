'use strict';

module.exports = ptr;


var bigInt = require('big-integer');

function ptr(value) {
  if (typeof value === 'string') {
    if (value.indexOf('0x') === 0) {
      return bigInt(value.substr(2), 16);
    } else {
      return bigInt(value, 10);
    }
  } else if (typeof value === 'number') {
    return bigInt(value);
  } else {
    throw new Error('Invalid pointer value: ' + value);
  }
}
