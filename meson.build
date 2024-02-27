project('frida-node', 'cpp',
  version: '1.0.0',
)

fs = import('fs')
node_incroot = fs.parent(fs.parent(find_program('node').full_path())) / 'include'
node_incdir = node_incroot / 'node'
if not fs.exists(node_incdir)
  error('Node.js development headers not found')
endif

frida_core_dep = dependency('frida-core-1.0', default_options: [
  'compiler_backend=disabled',
])
nan_dep = dependency('nan')

subdir('src')
