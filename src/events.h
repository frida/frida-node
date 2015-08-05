#ifndef FRIDANODE_EVENTS_H
#define FRIDANODE_EVENTS_H

#include "glib_object.h"

namespace frida {

class Events : public GLibObject {
 public:
  typedef v8::Local<v8::Value>(*TransformCallback)(const gchar* name,
      guint index, const GValue* value, gpointer user_data);
  typedef void (*ListenCallback)(const gchar* signal, gpointer user_data);
  typedef void (*UnlistenCallback)(const gchar* signal, gpointer user_data);

  static void Init(v8::Handle<v8::Object> exports, Runtime* runtime);
  static v8::Local<v8::Object> New(gpointer handle, Runtime* runtime,
      TransformCallback transform = NULL, gpointer transform_data = NULL);

  void SetListenCallback(ListenCallback callback, gpointer user_data);
  void SetUnlistenCallback(UnlistenCallback callback, gpointer user_data);

 private:
  Events(gpointer handle, TransformCallback transform, gpointer transform_data,
      Runtime* runtime);
  ~Events();

  static NAN_METHOD(New);

  static NAN_METHOD(Listen);
  static NAN_METHOD(Unlisten);

  bool GetSignalArguments(
      const Nan::FunctionCallbackInfo<v8::Value>& info,
      guint& signal_id, v8::Local<v8::Function>& callback);

  TransformCallback transform_;
  gpointer transform_data_;
  ListenCallback listen_;
  gpointer listen_data_;
  UnlistenCallback unlisten_;
  gpointer unlisten_data_;
  GSList* closures_;
};

}

#endif
