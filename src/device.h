#ifndef FRIDANODE_DEVICE_H
#define FRIDANODE_DEVICE_H

#include "glib_object.h"

#include <frida-core.h>

namespace frida {

class Device : public GLibObject {
 public:
  static void Init(v8::Local<v8::Object> exports, Runtime* runtime);
  static v8::Local<v8::Object> New(gpointer handle, Runtime* runtime);

 private:
  Device(FridaDevice* handle, Runtime* runtime);
  ~Device();

  static NAN_METHOD(New);

  static NAN_PROPERTY_GETTER(GetId);
  static NAN_PROPERTY_GETTER(GetName);
  static NAN_PROPERTY_GETTER(GetIcon);
  static NAN_PROPERTY_GETTER(GetType);
  static NAN_PROPERTY_GETTER(GetBus);
  static NAN_PROPERTY_GETTER(IsLost);

  static NAN_METHOD(QuerySystemParameters);
  static NAN_METHOD(GetFrontmostApplication);
  static NAN_METHOD(EnumerateApplications);
  static NAN_METHOD(EnumerateProcesses);
  static NAN_METHOD(EnableSpawnGating);
  static NAN_METHOD(DisableSpawnGating);
  static NAN_METHOD(EnumeratePendingSpawn);
  static NAN_METHOD(EnumeratePendingChildren);
  static NAN_METHOD(Spawn);
  static NAN_METHOD(Input);
  static NAN_METHOD(Resume);
  static NAN_METHOD(Kill);
  static NAN_METHOD(Attach);
  static NAN_METHOD(InjectLibraryFile);
  static NAN_METHOD(InjectLibraryBlob);
  static NAN_METHOD(OpenChannel);
  static NAN_METHOD(OpenService);
  static NAN_METHOD(Unpair);

  static v8::Local<v8::Value> TransformSignal(const gchar* name, guint index,
      const GValue* value, gpointer user_data);
  static void OnConnect(const gchar* signal, gpointer user_data);
  static void OnDisconnect(const gchar* signal, gpointer user_data);
  static bool ShouldStayAliveToEmit(const gchar* signal);
};

}

#endif
