import * as bindings from "bindings";

export const binding = bindings({
    bindings: "frida_binding",
    try: [
        ["module_root", "build", "bindings"],
        ["module_root", "build", "Debug", "bindings"],
        ["module_root", "build", "Release", "bindings"],
        ["module_root", "out", "Debug", "bindings"],
        ["module_root", "Debug", "bindings"],
        ["module_root", "out", "Release", "bindings"],
        ["module_root", "Release", "bindings"],
        ["module_root", "build", "default", "bindings"],
        ["module_root", "compiled", "version", "platform", "arch", "bindings"],
        [process.cwd(), "bindings"],
    ]
});