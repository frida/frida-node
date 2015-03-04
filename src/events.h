#ifndef FRIDANODE_EVENTS_H
#define FRIDANODE_EVENTS_H

#include "glib_object.h"

namespace frida {

typedef v8::Local<v8::Value>(*EventsTransformer)(v8::Isolate* isolate,
    const gchar* name, guint index, const GValue* value, gpointer user_data);

class Events : public GLibObject {
 public:
  static void Init(v8::Handle<v8::Object> exports, Runtime* runtime);
  static v8::Local<v8::Object> New(gpointer handle, Runtime* runtime,
      EventsTransformer transformer = NULL, gpointer transformer_data = NULL);

 private:
  Events(gpointer handle, EventsTransformer transformer,
      gpointer transformer_data, Runtime* runtime);
  ~Events();

  static void New(const v8::FunctionCallbackInfo<v8::Value>& args);

  static void Listen(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void Unlisten(const v8::FunctionCallbackInfo<v8::Value>& args);

  bool GetSignalArguments(
      const v8::FunctionCallbackInfo<v8::Value>& args,
      guint& signal_id, v8::Local<v8::Function>& callback);

  EventsTransformer transformer_;
  gpointer transformer_data_;
  GSList* closures_;
};

}

#endif
