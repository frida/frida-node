#ifndef FRIDANODE_SERVICE_H
#define FRIDANODE_SERVICE_H

#include "glib_object.h"

#include <frida-core.h>

namespace frida {

class Service : public GLibObject {
 public:
  static void Init(v8::Local<v8::Object> exports, Runtime* runtime);
  static v8::Local<v8::Object> New(gpointer handle, Runtime* runtime);

 private:
  explicit Service(FridaService* handle, Runtime* runtime);
  ~Service();

  static NAN_METHOD(New);

  static NAN_METHOD(Activate);
  static NAN_METHOD(Cancel);
  static NAN_METHOD(Request);

  static v8::Local<v8::Value> TransformSignal(const gchar* name, guint index,
      const GValue* value, gpointer user_data);
  static void OnConnect(const gchar* signal, gpointer user_data);
  static bool ShouldStayAliveToEmit(const gchar* signal);
  void EnsureUsageMonitorCreated();

  bool usage_monitor_created_;
};

}

#endif
