if frida_core_dep.type_name() == 'internal'
  frida_core_subprj = subproject('frida-core')
  frida_gir = frida_core_subprj.get_variable('core_public_gir')
  gio_gir = frida_core_subprj.get_variable('gio_gir')
else
  girdir = frida_core_dep.get_variable('frida_girdir')
  frida_gir = girdir / 'Frida-1.0.gir'
  gio_gir = girdir / 'Gio-2.0.gir'
endif

code = custom_target('binding-code',
  output: [
    'frida.ts',
    'frida_binding.d.ts',
    'frida_binding.c',
  ],
  input: [
    frida_gir,
    gio_gir,
  ],
  command: [
    python,
    files('generate.py'),
    '@INPUT@',
    '@OUTPUT@',
  ],
  install: true,
  install_dir: [
    false,
    pkg_install_dir / 'build' / 'src',
    false,
  ],
)

custom_target('js',
  input: [
    code[0],
    code[1],
  ],
  output: [
    'frida.js',
    'frida.d.ts',
  ],
  command: [
    python,
    files('tsc.py'),
    '@OUTDIR@',
    '@PRIVATE_DIR@',
    npm,
    package_json,
    tsconfig_json,
    '@INPUT@',
  ],
  install: true,
  install_dir: pkg_install_dir / 'build' / 'src',
)

frida_binding_sources = [
  code[2],
  files('win_delay_load_hook.c'),
]

if system == 'windows'
  if cpp.get_argument_syntax() != 'msvc'
    symfile = 'addon.symbols'
    extra_link_args += '-Wl,--retain-symbols-file,' + meson.current_source_dir() / symfile
    extra_link_depends += files(symfile)
  endif
elif system == 'darwin'
  symlist = 'addon.symbols'
  extra_link_args += '-Wl,-exported_symbols_list,' + meson.current_source_dir() / symlist
  extra_link_depends += files(symlist)
else
  symscript = 'addon.version'
  extra_link_args += '-Wl,--version-script,' + meson.current_source_dir() / symscript
  extra_link_depends += files(symscript)
endif
