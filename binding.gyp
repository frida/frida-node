{
  "variables": {
    "conditions": [
      ["OS=='win'", {
        "frida_host": "windows",
      }],
      ["OS=='mac' and target_arch=='ia32'", {
        "frida_host": "macos-x86",
      }],
      ["OS=='mac' and target_arch=='x64'", {
        "frida_host": "macos-x86_64",
      }],
      ["OS=='linux' and target_arch=='ia32'", {
        "frida_host": "linux-x86",
      }],
      ["OS=='linux' and target_arch=='x64'", {
        "frida_host": "linux-x86_64",
      }],
      ["OS=='linux' and target_arch=='arm'", {
        "frida_host": "linux-armhf",
      }],
      ["OS=='linux' and target_arch=='arm64'", {
        "frida_host": "linux-arm64",
      }],
    ],
    "frida_host_msvs": "unix",
    "build_v8_with_gn": 0,
  },
  "targets": [
    {
      "variables": {
        "conditions": [
          ["OS=='win' and target_arch=='ia32'", {
            "frida_host_msvs": "Win32-<(CONFIGURATION_NAME)",
          }],
          ["OS=='win' and target_arch=='x64'", {
            "frida_host_msvs": "x64-<(CONFIGURATION_NAME)",
          }],
        ],
      },
      "target_name": "frida_binding",
      "sources": [
        "src/addon.cc",
        "src/device_manager.cc",
        "src/device.cc",
        "src/application.cc",
        "src/process.cc",
        "src/spawn.cc",
        "src/child.cc",
        "src/crash.cc",
        "src/icon.cc",
        "src/session.cc",
        "src/script.cc",
        "src/iostream.cc",
        "src/cancellable.cc",
        "src/signals.cc",
        "src/glib_object.cc",
        "src/runtime.cc",
        "src/uv_context.cc",
        "src/glib_context.cc",
      ],
      "target_conditions": [
        ["OS=='win'", {
          "include_dirs": [
            "$(FRIDA)/build/tmp-windows/<(frida_host_msvs)/frida-core/api",
            "$(FRIDA)/build/sdk-windows/<(frida_host_msvs)/include/json-glib-1.0",
            "$(FRIDA)/build/sdk-windows/<(frida_host_msvs)/include/gee-0.8",
            "$(FRIDA)/build/sdk-windows/<(frida_host_msvs)/include/glib-2.0",
            "$(FRIDA)/build/sdk-windows/<(frida_host_msvs)/lib/glib-2.0/include",
            "<!(node -e \"require(\'nan\')\")",
          ],
          "library_dirs": [
            "$(FRIDA)/build/tmp-windows/<(frida_host_msvs)/frida-core",
            "$(FRIDA)/build/sdk-windows/<(frida_host_msvs)/lib",
            "$(FRIDA)/build/sdk-windows/<(frida_host_msvs)/lib/gio/modules",
          ],
          "libraries": [
            "-lfrida-core.lib",
            "-llibsoup-2.4.a",
            "-llibpsl.a",
            "-llibxml2.a",
            "-llibjson-glib-1.0.a",
            "-llibgee-0.8.a",
            "-llibgioschannel.a",
            "-llibgio-2.0.a",
            "-llibgthread-2.0.a",
            "-llibgobject-2.0.a",
            "-llibgmodule-2.0.a",
            "-llibglib-2.0.a",
            "-llibz.a",
            "-llibffi.a",
            "-lcrypt32.lib",
            "-ldnsapi.lib",
            "-liphlpapi.lib",
            "-lole32.lib",
            "-lpsapi.lib",
            "-lsecur32.lib",
            "-lshlwapi.lib",
            "-lwinmm.lib",
            "-lws2_32.lib",
          ],
        }, {
          "include_dirs": [
            "$(FRIDA)/build/frida-<(frida_host)/include/frida-1.0",
            "$(FRIDA)/build/sdk-<(frida_host)/include/json-glib-1.0",
            "$(FRIDA)/build/sdk-<(frida_host)/include/glib-2.0",
            "$(FRIDA)/build/sdk-<(frida_host)/lib/glib-2.0/include",
            "<!(node -e \"require(\'nan\')\")",
          ],
          "library_dirs": [
            "$(FRIDA)/build/frida-<(frida_host)/lib",
            "$(FRIDA)/build/sdk-<(frida_host)/lib",
            "$(FRIDA)/build/sdk-<(frida_host)/lib/gio/modules",
          ],
          "libraries": [
            "-lfrida-core-1.0",
            "-lfrida-gumjs-1.0",
            "-lsoup-2.4",
            "-lpsl",
            "-lxml2",
            "-ljson-glib-1.0",
            "-lfrida-gum-1.0",
            "-lcapstone",
            "-lgee-0.8",
            "-lgioopenssl",
            "-lssl",
            "-lcrypto",
            "-lgio-2.0",
            "-lgthread-2.0",
            "-lgobject-2.0",
            "-lgmodule-2.0",
            "-lglib-2.0",
            "-lffi",
            "-lz",
          ],
        }],
        ["OS=='mac'", {
          "xcode_settings": {
            "OTHER_CFLAGS": [
              "-std=c++11",
              "-stdlib=libc++",
              "-mmacosx-version-min=10.9",
            ],
            "OTHER_LDFLAGS": [
              "-stdlib=libc++",
              "-Wl,-dead_strip",
              "-Wl,-exported_symbols_list,binding.symbols",
            ],
          },
          "libraries": [
            "-lbsm",
            "-liconv",
            "-Wl,-framework -Wl,Foundation -Wl,-framework -Wl,AppKit",
            "-mmacosx-version-min=10.9",
          ],
        }],
        ["OS=='linux'", {
          "cflags": [
            "-std=c++11",
            "-ffunction-sections",
            "-fdata-sections",
          ],
          "ldflags": [
            "-static-libgcc",
            "-static-libstdc++",
            "-Wl,--gc-sections",
            "-Wl,-z,noexecstack",
            "-Wl,--version-script",
            "-Wl,../binding.version",
          ],
          "library_dirs": [
            "$(FRIDA)/build/sdk-<(frida_host)/lib32",
            "$(FRIDA)/build/sdk-<(frida_host)/lib64",
          ],
        }],
      ],
    },
  ],
}
