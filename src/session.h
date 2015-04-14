#ifndef FRIDANODE_SESSION_H
#define FRIDANODE_SESSION_H

#include "glib_object.h"

#include <frida-core.h>

namespace frida {

class Session : public GLibObject {
 public:
  static void Init(v8::Handle<v8::Object> exports, Runtime* runtime);
  static v8::Local<v8::Object> New(gpointer handle, Runtime* runtime);

 private:
  explicit Session(FridaSession* handle, Runtime* runtime);
  ~Session();

  static void New(const v8::FunctionCallbackInfo<v8::Value>& args);

  static void GetPid(v8::Local<v8::String> property,
      const v8::PropertyCallbackInfo<v8::Value>& info);

  static void Detach(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void CreateScript(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void EnableDebugger(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void DisableDebugger(const v8::FunctionCallbackInfo<v8::Value>& args);

  v8::Persistent<v8::Object> events_;
};

}

#endif
