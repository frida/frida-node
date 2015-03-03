#ifndef FRIDANODE_DEVICE_H
#define FRIDANODE_DEVICE_H

#include <frida-core.h>
#include <node_object_wrap.h>

namespace frida {

class Device : public node::ObjectWrap {
 public:
  static void Init(v8::Handle<v8::Object> exports);
  static v8::Local<v8::Object> Create(gpointer handle);

 private:
  explicit Device(FridaDevice* handle);
  ~Device();

  static void New(const v8::FunctionCallbackInfo<v8::Value>& args);

  static void GetId(v8::Local<v8::String> property,
      const v8::PropertyCallbackInfo<v8::Value>& info);
  static void GetName(v8::Local<v8::String> property,
      const v8::PropertyCallbackInfo<v8::Value>& info);
  static void GetType(v8::Local<v8::String> property,
      const v8::PropertyCallbackInfo<v8::Value>& info);

  static void EnumerateProcesses(
      const v8::FunctionCallbackInfo<v8::Value>& args);
  static void Attach(const v8::FunctionCallbackInfo<v8::Value>& args);

  static v8::Persistent<v8::Function> constructor_;

  FridaDevice* handle_;
  v8::Persistent<v8::Object> events_;
};

}

#endif
