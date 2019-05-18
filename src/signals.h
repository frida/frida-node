#ifndef FRIDANODE_SIGNALS_H
#define FRIDANODE_SIGNALS_H

#include "glib_object.h"

namespace frida {

class Signals : public GLibObject {
 public:
  typedef v8::Local<v8::Value>(*TransformCallback)(const gchar* name,
      guint index, const GValue* value, gpointer user_data);
  typedef void (*ConnectCallback)(const gchar* name, gpointer user_data);
  typedef void (*DisconnectCallback)(const gchar* name, gpointer user_data);

  static void Init(v8::Local<v8::Object> exports, Runtime* runtime);
  static v8::Local<v8::Object> New(gpointer handle, Runtime* runtime,
      TransformCallback transform = NULL, gpointer transform_data = NULL);

  void SetConnectCallback(ConnectCallback callback, gpointer user_data);
  void SetDisconnectCallback(DisconnectCallback callback, gpointer user_data);

 private:
  Signals(gpointer handle, TransformCallback transform, gpointer transform_data,
      Runtime* runtime);
  ~Signals();

  static NAN_METHOD(New);

  static NAN_METHOD(Connect);
  static NAN_METHOD(Disconnect);

  bool GetSignalArguments(
      const Nan::FunctionCallbackInfo<v8::Value>& info,
      guint& signal_id, v8::Local<v8::Function>& callback);

  TransformCallback transform_;
  gpointer transform_data_;
  ConnectCallback connect_;
  gpointer connect_data_;
  DisconnectCallback disconnect_;
  gpointer disconnect_data_;
  GSList* closures_;
};

}

#endif
