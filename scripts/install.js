'use strict';

var spawn = require('child_process').spawn;

spawn('prebuild-install', [], { shell: true, stdio: 'inherit' }).once('close', function (code) {
  if (code === 0)
    return;

  spawn('node-gyp rebuild', [], { shell: true, stdio: 'inherit' }).once('close', function (code) {
    if (code === 0)
      return;

    process.exitCode = code;
  });
});
