#ifndef FRIDANODE_SCRIPT_H
#define FRIDANODE_SCRIPT_H

#include <frida-core.h>
#include <node_object_wrap.h>

namespace frida {

class Script : public node::ObjectWrap {
 public:
  static void Init(v8::Handle<v8::Object> exports);
  static v8::Local<v8::Object> Create(gpointer handle);

 private:
  explicit Script(FridaScript* handle);
  ~Script();

  static void New(const v8::FunctionCallbackInfo<v8::Value>& args);

  static void Load(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void Unload(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void PostMessage(const v8::FunctionCallbackInfo<v8::Value>& args);

  static v8::Persistent<v8::Function> constructor_;

  FridaScript* handle_;
  v8::Persistent<v8::Object> events_;
};

}

#endif
