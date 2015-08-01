#ifndef FRIDANODE_SCRIPT_H
#define FRIDANODE_SCRIPT_H

#include "glib_object.h"

#include <frida-core.h>
#include <nan.h>

namespace frida {

class Script : public GLibObject {
 public:
  static void Init(v8::Handle<v8::Object> exports, Runtime* runtime);
  static v8::Local<v8::Object> New(gpointer handle, Runtime* runtime);

 private:
  explicit Script(FridaScript* handle, Runtime* runtime);
  ~Script();

  static void New(const Nan::FunctionCallbackInfo<v8::Value>& info);

  static void Load(const Nan::FunctionCallbackInfo<v8::Value>& info);
  static void Unload(const Nan::FunctionCallbackInfo<v8::Value>& info);
  static void PostMessage(const Nan::FunctionCallbackInfo<v8::Value>& info);

  static v8::Local<v8::Value> TransformMessageEvent(v8::Isolate* isolate,
      const gchar* name, guint index, const GValue* value, gpointer user_data);

  v8::Persistent<v8::Object> events_;
};

}

#endif
