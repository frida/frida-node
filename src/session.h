#ifndef FRIDANODE_SESSION_H
#define FRIDANODE_SESSION_H

#include <frida-core.h>
#include <node_object_wrap.h>

namespace frida {

class Session : public node::ObjectWrap {
 public:
  static void Init(v8::Handle<v8::Object> exports);
  static v8::Local<v8::Object> Create(gpointer handle);

 private:
  explicit Session(FridaSession* handle);
  ~Session();

  static void New(const v8::FunctionCallbackInfo<v8::Value>& args);

  static void GetPid(v8::Local<v8::String> property,
      const v8::PropertyCallbackInfo<v8::Value>& info);

  static void Detach(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void CreateScript(const v8::FunctionCallbackInfo<v8::Value>& args);

  static v8::Persistent<v8::Function> constructor_;

  FridaSession* handle_;
  v8::Persistent<v8::Object> events_;
};

}

#endif
