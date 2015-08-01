#ifndef FRIDANODE_DEVICE_H
#define FRIDANODE_DEVICE_H

#include "glib_object.h"

#include <frida-core.h>
#include <nan.h>

namespace frida {

class Device : public GLibObject {
 public:
  static void Init(v8::Handle<v8::Object> exports, Runtime* runtime);
  static v8::Local<v8::Object> New(gpointer handle, Runtime* runtime);

 private:
  Device(FridaDevice* handle, Runtime* runtime);
  ~Device();

  static void New(const Nan::FunctionCallbackInfo<v8::Value>& info);

  static void GetId(v8::Local<v8::String> property,
      const Nan::PropertyCallbackInfo<v8::Value>& info);
  static void GetName(v8::Local<v8::String> property,
      const Nan::PropertyCallbackInfo<v8::Value>& info);
  static void GetIcon(v8::Local<v8::String> property,
      const Nan::PropertyCallbackInfo<v8::Value>& info);
  static void GetType(v8::Local<v8::String> property,
      const Nan::PropertyCallbackInfo<v8::Value>& info);

  static void GetFrontmostApplication(
      const Nan::FunctionCallbackInfo<v8::Value>& info);
  static void EnumerateApplications(
      const Nan::FunctionCallbackInfo<v8::Value>& info);
  static void EnumerateProcesses(
      const Nan::FunctionCallbackInfo<v8::Value>& info);
  static void Spawn(const Nan::FunctionCallbackInfo<v8::Value>& info);
  static void Resume(const Nan::FunctionCallbackInfo<v8::Value>& info);
  static void Kill(const Nan::FunctionCallbackInfo<v8::Value>& info);
  static void Attach(const Nan::FunctionCallbackInfo<v8::Value>& info);

  v8::Persistent<v8::Object> events_;
};

}

#endif
