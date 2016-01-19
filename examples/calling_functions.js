'use strict';

var frida = require('..');

var processName    = process.argv[2];
var processAddress = process.argv[3];

var script = 
  "var fn = new NativeFunction(ptr('%addr%'), 'void', [ 'int' ]);"
+ "fn(1);"
+ "fn(1);"
+ "fn(1);";

frida.attach(processName).then(session => {
  return session.createScript(script.replace('%addr%', processAddress));
}).then(script => {
  script.load().then(() => {
    console.log("script loaded");
  }).catch(err => {
    console.error(err);
  });
}).catch(err => {
  console.error(err);
});
