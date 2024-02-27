project('frida-node', 'cpp',
  version: '1.0.0',
)

node = find_program('node')

fs = import('fs')
node_incroot = fs.parent(fs.parent(node.full_path())) / 'include'
node_incdir = node_incroot / 'node'
if fs.exists(node_incdir)
  incdirs = include_directories(node_incdir, node_incroot)
else
  message('Downloading Node.js headers')
  run_command('python', 'scripts' / 'grabheaders.py', node.full_path(), meson.current_build_dir(),
    capture: false,
    check: true,
  )
  incdirs = include_directories('abi-headers' / 'include' / 'node')
endif

nan_dep = dependency('nan')

frida_core_dep = dependency('frida-core-1.0', default_options: [
  'compiler_backend=disabled',
])

subdir('src')
