#ifndef FRIDANODE_EVENTS_H
#define FRIDANODE_EVENTS_H

#include <glib-object.h>
#include <node_object_wrap.h>
#include <uv.h>

namespace frida {

class Events : public node::ObjectWrap {
 public:
  static void Init(v8::Handle<v8::Object> exports);
  static v8::Local<v8::Object> Create(gpointer handle);

 private:
  Events(gpointer handle);
  ~Events();

  static void New(const v8::FunctionCallbackInfo<v8::Value>& args);

  static void Listen(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void Unlisten(const v8::FunctionCallbackInfo<v8::Value>& args);

  bool GetSignalArguments(
      const v8::FunctionCallbackInfo<v8::Value>& args,
      guint& signal_id, v8::Local<v8::Function>& callback);

  static v8::Persistent<v8::Function> constructor_;

  gpointer handle_;
  GSList* closures_;
  GSList* pending_;
};

}

#endif
