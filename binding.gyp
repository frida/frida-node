{
  'variables': {
    'conditions': [
      ['OS=="win"', {
        'frida_host': 'windows',
      }],
      ['OS=="mac" and target_arch=="ia32"', {
        'frida_host': 'mac-i386',
      }],
      ['OS=="mac" and target_arch=="x64"', {
        'frida_host': 'mac-x86_64',
      }],
      ['OS=="linux" and target_arch=="ia32"', {
        'frida_host': 'linux-i386',
      }],
      ['OS=="linux" and target_arch=="x64"', {
        'frida_host': 'linux-x86_64',
      }],
    ],
    'frida_host_msvs': 'unix',
  },
  'targets': [
    {
      'variables': {
        'conditions': [
          ['OS=="win" and target_arch=="ia32"', {
            'frida_host_msvs': 'Win32-<(CONFIGURATION_NAME)',
          }],
          ['OS=="win" and target_arch=="x64"', {
            'frida_host_msvs': 'x64-<(CONFIGURATION_NAME)',
          }],
        ],
      },
      'target_name': 'frida_binding',
      'sources': [
        'src/addon.cc',
        'src/device_manager.cc',
        'src/device.cc',
        'src/process.cc',
        'src/icon.cc',
        'src/session.cc',
        'src/script.cc',
        'src/events.cc',
        'src/glib_object.cc',
        'src/runtime.cc',
        'src/uv_context.cc',
        'src/glib_context.cc',
      ],
      'target_conditions': [
        ['OS=="win"', {
          'include_dirs': [
            '$(FRIDA)/build/tmp-windows/<(frida_host_msvs)/frida-core',
            '$(FRIDA)/build/sdk-windows/<(frida_host_msvs)/include/gee-0.8',
            '$(FRIDA)/build/sdk-windows/<(frida_host_msvs)/include/glib-2.0',
            '$(FRIDA)/build/sdk-windows/<(frida_host_msvs)/lib/glib-2.0/include',
          ],
          "library_dirs": [
            "$(FRIDA)/build/tmp-windows/<(frida_host_msvs)/frida-core",
            "$(FRIDA)/build/sdk-windows/<(frida_host_msvs)/lib",
          ],
          'libraries': [
            '-lfrida-core.lib',
            '-lgee-0.8.lib',
            '-lgio-2.0.lib',
            '-lgthread-2.0.lib',
            '-lgobject-2.0.lib',
            '-lgmodule-2.0.lib',
            '-lglib-2.0.lib',
            '-lz.lib',
            '-lffi.lib',
            '-lintl.lib',
            '-ldnsapi.lib',
            '-liphlpapi.lib',
            '-lole32.lib',
            '-lpsapi.lib',
            '-lshlwapi.lib',
            '-lwinmm.lib',
            '-lws2_32.lib',
          ],
        }, {
          'include_dirs': [
            '$(FRIDA)/build/frida-<(frida_host)/include/frida-1.0',
            '$(FRIDA)/build/sdk-<(frida_host)/include/glib-2.0',
            '$(FRIDA)/build/sdk-<(frida_host)/lib/glib-2.0/include',
          ],
          'library_dirs': [
            '$(FRIDA)/build/frida-<(frida_host)/lib',
            '$(FRIDA)/build/sdk-<(frida_host)/lib',
          ],
          'libraries': [
            '-lfrida-core-1.0',
            '-lfrida-gum-1.0',
            '-lgee-0.8',
            '-lgio-2.0',
            '-lgthread-2.0',
            '-lgobject-2.0',
            '-lgmodule-2.0',
            '-lglib-2.0',
            '-lffi',
          ],
        }],
        ['OS=="mac"', {
          'xcode_settings': {
            'OTHER_CFLAGS': [
              '-std=c++11',
              '-stdlib=libc++',
              '-mmacosx-version-min=10.7',
            ],
            'OTHER_LDFLAGS': [
              '-Wl,-macosx_version_min,10.7',
              '-Wl,-dead_strip',
              '-Wl,-no_compact_unwind',
            ],
          },
          'libraries': [
            '-Wl,-framework -Wl,Foundation -Wl,-framework -Wl,AppKit',
          ],
        }],
        ['OS=="linux"', {
          'cflags': [
            '-std=c++11',
            '-ffunction-sections',
            '-fdata-sections',
          ],
          'ldflags': [
            '-Wl,--gc-sections',
          ],
        }],
      ],
    },
    {
      'target_name': 'action_after_build',
      'type': 'none',
      'dependencies': [ '<(module_name)' ],
      'copies': [
        {
          'files': [ '<(PRODUCT_DIR)/<(module_name).node' ],
          'destination': '<(module_path)',
        },
      ]
    },
  ],
}
