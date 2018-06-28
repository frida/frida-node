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

  static NAN_METHOD(New);

  static NAN_METHOD(Load);
  static NAN_METHOD(Unload);
  static NAN_METHOD(Post);

  static v8::Local<v8::Value> TransformMessageSignal(const gchar* name,
      guint index, const GValue* value, gpointer user_data);

  v8::Persistent<v8::Object> signals_;
};

}

#endif
