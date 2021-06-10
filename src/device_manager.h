#ifndef FRIDANODE_DEVICE_MANAGER_H
#define FRIDANODE_DEVICE_MANAGER_H

#include "glib_object.h"

#include <frida-core.h>

namespace frida {

class DeviceManager : public GLibObject {
 public:
  static void Init(v8::Local<v8::Object> exports, Runtime* runtime);
  static void Dispose(Runtime* runtime);

 private:
  DeviceManager(FridaDeviceManager* handle, Runtime* runtime);
  ~DeviceManager();

  static NAN_METHOD(New);

  static NAN_METHOD(Close);
  static NAN_METHOD(EnumerateDevices);
  static NAN_METHOD(AddRemoteDevice);
  static NAN_METHOD(RemoveRemoteDevice);

  static v8::Local<v8::Value> TransformDeviceSignals(const gchar* name,
      guint index, const GValue* value, gpointer user_data);
  static void OnConnect(const gchar* signal, gpointer user_data);
  static void OnDisconnect(const gchar* signal, gpointer user_data);
  static bool ShouldStayAliveToEmit(const gchar* signal);
};

}

#endif
