const frida = require('..');
const readline = require('readline');
const util = require('util');

class Application {
  constructor(nick) {
    this._nick = nick;
    this._channel = null;
    this._prompt = '> ';

    this._device = null;
    this._bus = null;
    this._input = null;
  }

  async run() {
    const token = {
      nick: this._nick,
      secret: 'knock-knock'
    };
    this._device = await frida.getDeviceManager().addRemoteDevice('::1', {
      token: JSON.stringify(token)
    });

    const bus = this._device.bus;
    this._bus = bus;
    bus.detached.connect(this._onBusDetached);
    bus.message.connect(this._onBusMessage);
    await bus.attach();

    const input = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
      terminal: true
    });
    this._input = input;
    input.on('close', this._onStdinClosed);
    input.on('line', this._onStdinCommand);

    this._showPrompt();
  }

  _quit() {
    const { _bus: bus, _input: input } = this;
    this._bus = null;
    this._input = null;

    if (bus !== null) {
      bus.detached.disconnect(this._onBusDetached);
      bus.message.disconnect(this._onBusMessage);
    }

    if (input !== null)
      input.close();
  }

  _onStdinClosed = () => {
    this._quit();
  };

  _onStdinCommand = async command => {
    try {
      process.stdout.write('\x1B[1A\x1B[K');

      if (command.length === 0) {
        this._print('Processes:', await this._device.enumerateProcesses());
        return;
      }

      if (command.startsWith('/join ')) {
        if (this._channel !== null) {
          this._bus.post({
            type: 'part',
            channel: this._channel
          });
        }

        const channel = command.substr(6);
        this._channel = channel;

        this._prompt = `${channel} > `;

        this._bus.post({
          type: 'join',
          channel: channel
        });

        return;
      }

      if (command.startsWith('/announce ')) {
        this._bus.post({
          type: 'announce',
          text: command.substr(10)
        });

        return;
      }

      if (this._channel !== null) {
        this._bus.post({
          channel: this._channel,
          type: 'say',
          text: command
        });
      } else {
        this._print('*** Need to /join a channel first');
      }
    } catch (e) {
      this._print(e);
    } finally {
      this._showPrompt();
    }
  };

  _onBusDetached = () => {
    this._quit();
  };

  _onBusMessage = (message, data) => {
    switch (message.type) {
      case 'welcome': {
        this._print('*** Welcome! Available channels:', message.channels);

        break;
      }
      case 'membership': {
        this._print('*** Joined', message.channel);

        const membersSummary = message.members.map(m => `${m.nick} (connected from ${m.address})`).join('\n\t');
        this._print('- Members:\n\t' + membersSummary);

        for (const item of message.history)
          this._print(`<${item.sender}> ${item.text}`);

        break;
      }
      case 'join': {
        const { user } = message;
        this._print(`👋 ${user.nick} (${user.address}) joined ${message.channel}`);

        break;
      }
      case 'part': {
        const { user } = message;
        this._print(`🚪 ${user.nick} (${user.address}) left ${message.channel}`);

        break;
      }
      case 'chat': {
        this._print(`<${message.sender}> ${message.text}`);

        break;
      }
      case 'announce': {
        this._print(`📣 <${message.sender}> ${message.text}`);

        break;
      }
      default: {
        this._print('Unhandled message:', message);

        break;
      }
    }
  };

  _showPrompt() {
    process.stdout.write('\r\x1B[K' + this._prompt);
  }

  _print(...words) {
    const text = words.map(w => (typeof w === 'string') ? w : util.inspect(w, { colors: true })).join(' ');
    process.stdout.write(`\r\x1B[K${text}\n${this._prompt}`);
  }
}

const nick = process.argv[2];
const app = new Application(nick);
app.run()
  .catch(e => {
    console.error(e);
  });
