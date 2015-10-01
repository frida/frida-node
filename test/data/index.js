function targetProgram() {
  var platform = process.platform;
  if (platform === 'win32')
    return 'C:\\Windows\\notepad.exe';
  else if (platform === 'darwin')
    return __dirname + '/unixvictim-mac';
  else
    return '/bin/cat';
}

module.exports.targetProgram = targetProgram();
