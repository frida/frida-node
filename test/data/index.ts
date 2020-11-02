export function targetProgram() {
    const platform = process.platform;
    if (platform === "win32") {
        return "C:\\Windows\\notepad.exe";
    } else if (platform === "darwin") {
        return __dirname + "/unixvictim-macos";
    } else {
        let fridaArch: string;
        const nodeArch = process.arch;
        if (nodeArch.startsWith("arm")) {
            fridaArch = (nodeArch === "arm64") ? "arm64" : "armhf";
        } else {
            fridaArch = (nodeArch === "x64") ? "x86_64" : "x86";
        }
        return __dirname + "/unixvictim-linux-" + fridaArch;
    }
}
