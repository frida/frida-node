{
  "targets": [
    {
      "target_name": "frida_binding",
      "sources": [
        "src/addon.cc",
        "src/device_manager.cc",
        "src/device.cc",
        "src/process.cc",
        "src/icon.cc",
        "src/session.cc",
        "src/script.cc",
        "src/events.cc",
        "src/glib_object.cc",
        "src/runtime.cc",
        "src/uv_context.cc",
        "src/glib_context.cc",
      ],
      'configurations': {
        'Debug': {
          'conditions': [
            ['OS=="win" and target_arch=="ia32"', {
              "include_dirs": [
                "$(FRIDA)/build/tmp-windows/Win32-Debug/frida-core",
                "$(FRIDA)/build/sdk-windows/Win32-Debug/include/gee-0.8",
                "$(FRIDA)/build/sdk-windows/Win32-Debug/include/glib-2.0",
                "$(FRIDA)/build/sdk-windows/Win32-Debug/lib/glib-2.0/include",
              ],
              "library_dirs": [
                "$(FRIDA)/build/tmp-windows/Win32-Debug/frida-core",
                "$(FRIDA)/build/sdk-windows/Win32-Debug/lib",
              ],
            }],
            ['OS=="win" and target_arch=="x64"', {
              "include_dirs": [
                "$(FRIDA)/build/tmp-windows/x64-Debug/frida-core",
                "$(FRIDA)/build/sdk-windows/x64-Debug/include/gee-0.8",
                "$(FRIDA)/build/sdk-windows/x64-Debug/include/glib-2.0",
                "$(FRIDA)/build/sdk-windows/x64-Debug/lib/glib-2.0/include",
              ],
              "library_dirs": [
                "$(FRIDA)/build/tmp-windows/x64-Debug/frida-core",
                "$(FRIDA)/build/sdk-windows/x64-Debug/lib",
              ],
            }],
          ],
        },
        'Release': {
          'conditions': [
            ['OS=="win" and target_arch=="ia32"', {
              "include_dirs": [
                "$(FRIDA)/build/tmp-windows/Win32-Release/frida-core",
                "$(FRIDA)/build/sdk-windows/Win32-Release/include/gee-0.8",
                "$(FRIDA)/build/sdk-windows/Win32-Release/include/glib-2.0",
                "$(FRIDA)/build/sdk-windows/Win32-Release/lib/glib-2.0/include",
              ],
              "library_dirs": [
                "$(FRIDA)/build/tmp-windows/Win32-Release/frida-core",
                "$(FRIDA)/build/sdk-windows/Win32-Release/lib",
              ],
            }],
            ['OS=="win" and target_arch=="x64"', {
              "include_dirs": [
                "$(FRIDA)/build/tmp-windows/x64-Release/frida-core",
                "$(FRIDA)/build/sdk-windows/x64-Release/include/gee-0.8",
                "$(FRIDA)/build/sdk-windows/x64-Release/include/glib-2.0",
                "$(FRIDA)/build/sdk-windows/x64-Release/lib/glib-2.0/include",
              ],
              "library_dirs": [
                "$(FRIDA)/build/tmp-windows/x64-Release/frida-core",
                "$(FRIDA)/build/sdk-windows/x64-Release/lib",
              ],
            }],
          ],
        },
      },
      'conditions': [
        ['OS=="win"', {
          "libraries": [
            "-lfrida-core.lib",
            "-lgee-0.8.lib",
            "-lgio-2.0.lib",
            "-lgthread-2.0.lib",
            "-lgobject-2.0.lib",
            "-lgmodule-2.0.lib",
            "-lglib-2.0.lib",
            "-lz.lib",
            "-lffi.lib",
            "-lintl.lib",
            "-ldnsapi.lib",
            "-liphlpapi.lib",
            "-lole32.lib",
            "-lpsapi.lib",
            "-lshlwapi.lib",
            "-lwinmm.lib",
            "-lws2_32.lib",
          ],
        }],
        ['OS=="mac"', {
          "xcode_settings": {
            "OTHER_CFLAGS": [
              "-std=c++11",
              "-stdlib=libc++",
              "-mmacosx-version-min=10.7",
            ],
            "OTHER_LDFLAGS": [
              "-Wl,-macosx_version_min,10.7",
              "-Wl,-dead_strip",
              "-Wl,-no_compact_unwind",
            ],
          },
          "include_dirs": [
            "$(FRIDA)/build/frida-mac-x86_64/include/frida-1.0",
            "$(FRIDA)/build/sdk-mac-x86_64/include/glib-2.0",
            "$(FRIDA)/build/sdk-mac-x86_64/lib/glib-2.0/include",
          ],
          "library_dirs": [
            "$(FRIDA)/build/frida-mac-x86_64/lib",
            "$(FRIDA)/build/sdk-mac-x86_64/lib",
          ],
          "libraries": [
            "-lfrida-core-1.0",
            "-lfrida-gum-1.0",
            "-lgee-0.8",
            "-lgio-2.0",
            "-lgthread-2.0",
            "-lgobject-2.0",
            "-lgmodule-2.0",
            "-lglib-2.0",
            "-lffi",
            "-Wl,-framework -Wl,Foundation -Wl,-framework -Wl,AppKit",
          ],
        }],
        ['OS=="linux"', {
          "cflags": [
            "-std=c++11",
            "-ffunction-sections",
            "-fdata-sections",
          ],
          "ldflags": [
            "-Wl,--gc-sections",
          ],
          "include_dirs": [
            "$(FRIDA)/build/frida-linux-x86_64/include/frida-1.0",
            "$(FRIDA)/build/sdk-linux-x86_64/include/glib-2.0",
            "$(FRIDA)/build/sdk-linux-x86_64/lib/glib-2.0/include",
          ],
          "library_dirs": [
            "$(FRIDA)/build/frida-linux-x86_64/lib",
            "$(FRIDA)/build/sdk-linux-x86_64/lib",
          ],
          "libraries": [
            "-lfrida-core-1.0",
            "-lfrida-gum-1.0",
            "-lgee-0.8",
            "-lgio-2.0",
            "-lgthread-2.0",
            "-lgobject-2.0",
            "-lgmodule-2.0",
            "-lglib-2.0",
            "-lffi",
          ],
        }],
      ],
    },
    {
      "target_name": "action_after_build",
      "type": "none",
      "dependencies": [ "<(module_name)" ],
      "copies": [
        {
          "files": [ "<(PRODUCT_DIR)/<(module_name).node" ],
          "destination": "<(module_path)",
        },
      ]
    },
  ],
}
