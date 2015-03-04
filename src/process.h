#ifndef FRIDANODE_PROCESS_H
#define FRIDANODE_PROCESS_H

#include "glib_object.h"

#include <frida-core.h>

namespace frida {

class Process : public GLibObject {
 public:
  static void Init(v8::Handle<v8::Object> exports, Runtime* runtime);
  static v8::Local<v8::Object> New(gpointer handle, Runtime* runtime);

 private:
  explicit Process(FridaProcess* handle, Runtime* runtime);
  ~Process();

  static void New(const v8::FunctionCallbackInfo<v8::Value>& args);

  static void GetPid(v8::Local<v8::String> property,
      const v8::PropertyCallbackInfo<v8::Value>& info);
  static void GetName(v8::Local<v8::String> property,
      const v8::PropertyCallbackInfo<v8::Value>& info);
};

}

#endif
