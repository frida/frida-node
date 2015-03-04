#ifndef FRIDANODE_GLIB_OBJECT_H
#define FRIDANODE_GLIB_OBJECT_H

#include "runtime.h"

#include <glib.h>
#include <node_object_wrap.h>

namespace frida {

class GLibObject : public node::ObjectWrap {
 protected:
  GLibObject(gpointer handle, Runtime* runtime)
    : handle_(handle),
      runtime_(runtime) {
  }

  static v8::Local<v8::FunctionTemplate> CreateTemplate(v8::Isolate* isolate,
      v8::Handle<v8::String> name, v8::FunctionCallback callback,
      Runtime* runtime);
  static Runtime* GetRuntimeFromConstructorArgs(
      const v8::FunctionCallbackInfo<v8::Value>& args);

 public:
  template<typename T>
  T* GetHandle() const { return static_cast<T*>(handle_); }

  Runtime* GetRuntime() const { return runtime_; }

 protected:
  gpointer handle_;
  Runtime* runtime_;
};

}

#endif
