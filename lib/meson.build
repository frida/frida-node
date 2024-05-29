sources = [
  'index.ts',

  'application.ts',
  'authentication.ts',
  'bus.ts',
  'cancellable.ts',
  'child.ts',
  'crash.ts',
  'device.ts',
  'device_manager.ts',
  'endpoint_parameters.ts',
  'icon.ts',
  'iostream.ts',
  'native.ts',
  'portal_membership.ts',
  'portal_service.ts',
  'process.ts',
  'relay.ts',
  'script.ts',
  'service.ts',
  'session.ts',
  'signals.ts',
  'socket_address.ts',
  'spawn.ts',
  'system_parameters.ts',
]

outputs = []
foreach s : sources
  stem = s.split('.')[0]
  outputs += [
    stem + '.js',
    stem + '.d.ts',
  ]
endforeach

custom_target('js',
  input: sources,
  output: outputs,
  command: [
    python,
    files('build.py'),
    '@OUTDIR@',
    '@PRIVATE_DIR@',
    npm,
    package_json,
    tsconfig_json,
    '@INPUT@',
  ],
  install: true,
  install_dir: pkg_install_dir / 'dist',
)
