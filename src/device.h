#ifndef FRIDANODE_DEVICE_H
#define FRIDANODE_DEVICE_H

#include "glib_object.h"

#include <frida-core.h>

namespace frida {

class Device : public GLibObject {
 public:
  static void Init(v8::Handle<v8::Object> exports, Runtime* runtime);
  static v8::Local<v8::Object> New(gpointer handle, Runtime* runtime);

 private:
  Device(FridaDevice* handle, Runtime* runtime);
  ~Device();

  static void New(const v8::FunctionCallbackInfo<v8::Value>& args);

  static void GetId(v8::Local<v8::String> property,
      const v8::PropertyCallbackInfo<v8::Value>& info);
  static void GetName(v8::Local<v8::String> property,
      const v8::PropertyCallbackInfo<v8::Value>& info);
  static void GetIcon(v8::Local<v8::String> property,
      const v8::PropertyCallbackInfo<v8::Value>& info);
  static void GetType(v8::Local<v8::String> property,
      const v8::PropertyCallbackInfo<v8::Value>& info);

  static void GetFrontmostApplication(
      const v8::FunctionCallbackInfo<v8::Value>& args);
  static void EnumerateApplications(
      const v8::FunctionCallbackInfo<v8::Value>& args);
  static void EnumerateProcesses(
      const v8::FunctionCallbackInfo<v8::Value>& args);
  static void Spawn(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void Resume(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void Kill(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void Attach(const v8::FunctionCallbackInfo<v8::Value>& args);

  v8::Persistent<v8::Object> events_;
};

}

#endif
