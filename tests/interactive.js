var frida = require('../');

function spawnExample() {
  frida.spawn(['/bin/cat', '/etc/resolv.conf'])
  .then(function (pid) {
    console.log('spawned:', pid);
    // This is where you could attach (see below) and instrument APIs before you call resume()
    return frida.resume(pid);
  })
  .then(function () {
    console.log('resumed');
  })
  .catch(function (error) {
    console.log('error:', error.message);
  });
}

function attachExample() {
  frida.attach('cat')
  .then(function (session) {
    console.log('attached:', session);
    return session.createScript('function onMessage(message) { send({ name: "pong", payload: message }); recv(onMessage); } recv(onMessage);');
  })
  .then(function (script) {
    console.log('script created:', script);
    script.events.listen('message', function (message, data) {
      console.log('message from script:', message, data);
    });
    script.load()
    .then(function () {
      console.log('script loaded');
      setInterval(function () {
        script.postMessage({ name: 'ping' });
      }, 1000);
    })
  })
  .catch(function (error) {
    console.log('error:', error.message);
  });
}

function usbExample() {
  frida.getUsbDevice(10000)
  .then(function (device) {
    console.log('usb device:', device);
    // Now call spawn(), attach(), etc. on `device` just like the above calls on `frida`
  })
  .catch(function (error) {
    console.log('error:', error.message);
  });
}

attachExample();
