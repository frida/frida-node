const frida = require('../../..');
const fs = require('fs');

async function main() {
  if (process.argv.length !== 3) {
    console.error(`Usage: ${process.argv[0]} outfile.png`);
    process.exit(1);
  }
  const outfile = process.argv[2];

  const device = await frida.getUsbDevice();

  const screenshot = await device.openService('dtx:com.apple.instruments.server.services.screenshot');
  const png = await screenshot.request({ method: 'takeScreenshot' });
  fs.writeFileSync(outfile, png);
}

main()
  .catch(e => {
    console.error(e);
  });
