#ifndef FRIDANODE_PROCESS_H
#define FRIDANODE_PROCESS_H

#include <frida-core.h>
#include <node_object_wrap.h>

namespace frida {

class Process : public node::ObjectWrap {
 public:
  static void Init(v8::Handle<v8::Object> exports);
  static v8::Local<v8::Object> Create(gpointer handle);

 private:
  explicit Process(FridaProcess* handle);
  ~Process();

  static void New(const v8::FunctionCallbackInfo<v8::Value>& args);

  static void GetPid(v8::Local<v8::String> property,
      const v8::PropertyCallbackInfo<v8::Value>& info);
  static void GetName(v8::Local<v8::String> property,
      const v8::PropertyCallbackInfo<v8::Value>& info);

  static v8::Persistent<v8::Function> constructor_;

  FridaProcess* handle_;
};

}

#endif
