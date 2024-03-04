import * as bindings from "bindings";

export const binding = bindings({
    bindings: "frida_binding",
    try: [
        ["module_root", "build", "bindings"],
        [process.cwd(), "bindings"],
    ]
});
