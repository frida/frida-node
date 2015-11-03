'use strict';

module.exports = load;


var browserify = require('browserify');
var concat = require('concat-stream');
var mold = require('mold-source-map');
var path = require('path');

function load(file) {
  return new Promise(function (resolve, reject) {
    browserify(file, {
      basedir: path.dirname(file),
      debug: true
    })
    .transform('babelify', {
      presets: ['es2015']
    })
    .bundle()
    .pipe(mold.transform(trimSourceMap))
    .pipe(concat(function (buf) {
      resolve(buf.toString());
    }))
    .once('error', reject);
  });
}

function trimSourceMap(molder) {
  var map = molder.sourcemap;
  map.setProperty('sourcesContent', undefined);
  return map.toComment();
}
