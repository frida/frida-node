const frida = require('..');

async function main() {
  const gw = new frida.WebGatewayService({
    gatewayParams: new frida.EndpointParameters({
      port: 8080
    }),
    targetParams: new frida.EndpointParameters({
      port: 27042
    }),
    root: '/Users/oleavr/src/frida/frida-python/examples/web_client/dist',
    //origin: 'gateway.frida.re',
  });

  await gw.start();
  console.log('Started!');
}

main()
  .catch(e => {
    console.error(e);
  });
