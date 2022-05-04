export function targetProgram() {
    const platform = process.platform;
    if (platform === "win32") {
        return "C:\\Windows\\notepad.exe";
    } else if (platform === "darwin") {
        return __dirname + "/unixvictim-macos";
    } else if (platform === "linux" && ["ia32", "x64"].includes(process.arch)) {
        const fridaArch = (process.arch === "x64") ? "x86_64" : "x86";
        return __dirname + "/unixvictim-linux-" + fridaArch;
    } else {
        return "/bin/cat";
    }
}
