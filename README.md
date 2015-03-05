# frida-node

Node.js bindings for [Frida](http://www.frida.re).

## Depends

- Node.js 0.12.x

## Install

Install from binary:

    npm install

Install from source:

    FRIDA=/absolute/path/to/fully/compiled/frida/repo npm install --build-from-source

## Developing

The [node-pre-gyp](https://github.com/mapbox/node-pre-gyp#usage) tool is
used to handle building from source and packaging.

To recompile only the C++ files that have changed, first put `node-gyp`
and `node-pre-gyp` on your PATH:

    export PATH=`npm explore npm -g -- pwd`/bin/node-gyp-bin:./node_modules/.bin:${PATH}

Also tell the build system where your fully compiled Frida repo is:

    export FRIDA=/absolute/path/to/fully/built/frida/repo

Then simply run:

    node-pre-gyp build

### Packaging

    node-pre-gyp build package

