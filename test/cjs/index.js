'use strict';

const math = require('./math');
const minimatch = require('minimatch');

rpc.exports = {
  add(a, b) {
    return math.add(a, b);
  },
  match(list, pattern) {
    return minimatch(list, pattern);
  },
  crashLater() {
    setTimeout(function () {
      throw new Error('Oops!');
    }, 0);
  }
};
