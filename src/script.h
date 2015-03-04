#ifndef FRIDANODE_SCRIPT_H
#define FRIDANODE_SCRIPT_H

#include "glib_object.h"

#include <frida-core.h>

namespace frida {

class Script : public GLibObject {
 public:
  static void Init(v8::Handle<v8::Object> exports, Runtime* runtime);
  static v8::Local<v8::Object> New(gpointer handle, Runtime* runtime);

 private:
  explicit Script(FridaScript* handle, Runtime* runtime);
  ~Script();

  static void New(const v8::FunctionCallbackInfo<v8::Value>& args);

  static void Load(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void Unload(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void PostMessage(const v8::FunctionCallbackInfo<v8::Value>& args);

  v8::Persistent<v8::Object> events_;
};

}

#endif
