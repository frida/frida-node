#ifndef FRIDANODE_SESSION_H
#define FRIDANODE_SESSION_H

#include "glib_object.h"

#include <frida-core.h>
#include <nan.h>

namespace frida {

class Session : public GLibObject {
 public:
  static void Init(v8::Handle<v8::Object> exports, Runtime* runtime);
  static v8::Local<v8::Object> New(gpointer handle, Runtime* runtime);

 private:
  explicit Session(FridaSession* handle, Runtime* runtime);
  ~Session();

  static void New(const Nan::FunctionCallbackInfo<v8::Value>& info);

  static void GetPid(v8::Local<v8::String> property,
      const Nan::PropertyCallbackInfo<v8::Value>& info);

  static void Detach(const Nan::FunctionCallbackInfo<v8::Value>& info);
  static void CreateScript(const Nan::FunctionCallbackInfo<v8::Value>& info);
  static void EnableDebugger(const Nan::FunctionCallbackInfo<v8::Value>& info);
  static void DisableDebugger(const Nan::FunctionCallbackInfo<v8::Value>& info);

  v8::Persistent<v8::Object> events_;
};

}

#endif
