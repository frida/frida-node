/*
 * When this file is linked to a DLL, it sets up a delay-load hook that
 * intervenes when the DLL is trying to load the host executable
 * dynamically. Instead of trying to locate the .exe file it'll just
 * return a handle to the process image.
 *
 * This allows compiled addons to work when the host executable is renamed.
 */

#ifdef _MSC_VER

#pragma managed(push, off)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>

#include <delayimp.h>
#include <string.h>

static FARPROC WINAPI load_exe_hook(unsigned int event, DelayLoadInfo* info) {
#ifdef FRIDA_NODE_WEBKIT
  static HMODULE node_dll = NULL;
  static HMODULE nw_dll = NULL;

  switch (event) {
    case dliStartProcessing:
      node_dll = GetModuleHandle("node.dll");
      nw_dll = GetModuleHandle("nw.dll");
      return NULL;
    case dliNotePreLoadLibrary:
      if (_stricmp(info->szDll, "node.exe") == 0)
        return (FARPROC) node_dll;
      return NULL;
    case dliNotePreGetProcAddress: {
      FARPROC ret = GetProcAddress(node_dll, info->dlp.szProcName);
      if (ret)
        return ret;
      return GetProcAddress(nw_dll, info->dlp.szProcName);
    }
    default:
      return NULL;
  }
#else
  HMODULE m;
  if (event != dliNotePreLoadLibrary)
    return NULL;

  if (_stricmp(info->szDll, HOST_BINARY) != 0)
    return NULL;

  m = GetModuleHandle(NULL);
  return (FARPROC) m;
#endif
}

decltype(__pfnDliNotifyHook2) __pfnDliNotifyHook2 = load_exe_hook;

#pragma managed(pop)

#endif
