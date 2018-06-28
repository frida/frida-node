export function targetProgram() {
    const platform = process.platform;
    if (platform === "win32")
        return "C:\\Windows\\notepad.exe";
    else if (platform === "darwin")
        return __dirname + "/unixvictim-macos";
    else
        return "/bin/cat";
}
