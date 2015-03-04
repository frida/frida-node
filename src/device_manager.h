#ifndef FRIDANODE_DEVICE_MANAGER_H
#define FRIDANODE_DEVICE_MANAGER_H

#include "glib_object.h"

#include <frida-core.h>

namespace frida {

class DeviceManager : public GLibObject {
 public:
  static void Init(v8::Handle<v8::Object> exports, Runtime* runtime);

 private:
  DeviceManager(FridaDeviceManager* handle, Runtime* runtime);
  ~DeviceManager();

  static void New(const v8::FunctionCallbackInfo<v8::Value>& args);

  static void Close(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void EnumerateDevices(const v8::FunctionCallbackInfo<v8::Value>& args);

  v8::Persistent<v8::Object> events_;
};

}

#endif
