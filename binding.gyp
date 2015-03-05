{
  "variables": { "frida%": '<!(echo $FRIDA)' },
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
      'conditions': [
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
            "<(frida)/build/frida-mac-x86_64/include/frida-1.0",
            "<(frida)/build/sdk-mac-x86_64/include/glib-2.0",
            "<(frida)/build/sdk-mac-x86_64/lib/glib-2.0/include",
          ],
          "library_dirs": [
            "<(frida)/build/frida-mac-x86_64/lib",
            "<(frida)/build/sdk-mac-x86_64/lib",
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
      ],
    },
  ],
}
