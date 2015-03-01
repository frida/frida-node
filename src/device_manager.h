#ifndef FRIDANODE_DEVICE_MANAGER_H
#define FRIDANODE_DEVICE_MANAGER_H

#include <frida-core.h>
#include <node.h>
#include <node_object_wrap.h>

namespace frida {

class DeviceManager : public node::ObjectWrap {
 public:
  static void Init(v8::Handle<v8::Object> exports);

 private:
  explicit DeviceManager(FridaDeviceManager* handle);
  ~DeviceManager();

  static void New(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void EnumerateDevices(const v8::FunctionCallbackInfo<v8::Value>& args);

  static v8::Persistent<v8::Function> constructor;

  FridaDeviceManager* handle_;
};

}

#endif
