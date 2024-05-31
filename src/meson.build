frida_binding_sources = files(
  'addon.cc',
  'device_manager.cc',
  'device.cc',
  'application.cc',
  'process.cc',
  'spawn.cc',
  'child.cc',
  'crash.cc',
  'bus.cc',
  'service.cc',
  'session.cc',
  'script.cc',
  'relay.cc',
  'portal_membership.cc',
  'portal_service.cc',
  'endpoint_parameters.cc',
  'authentication.cc',
  'iostream.cc',
  'cancellable.cc',
  'signals.cc',
  'glib_object.cc',
  'runtime.cc',
  'uv_context.cc',
  'glib_context.cc',
  'win_delay_load_hook.cc',
)

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
