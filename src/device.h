#ifndef FRIDANODE_DEVICE_H
#define FRIDANODE_DEVICE_H

#include "glib_object.h"

#include <frida-core.h>
#include <nan.h>

namespace frida {

class Device : public GLibObject {
 public:
  static void Init(v8::Handle<v8::Object> exports, Runtime* runtime);
  static v8::Local<v8::Object> New(gpointer handle, Runtime* runtime);

 private:
  Device(FridaDevice* handle, Runtime* runtime);
  ~Device();

  static NAN_METHOD(New);

  static NAN_PROPERTY_GETTER(GetId);
  static NAN_PROPERTY_GETTER(GetName);
  static NAN_PROPERTY_GETTER(GetIcon);
  static NAN_PROPERTY_GETTER(GetType);

  static NAN_METHOD(GetFrontmostApplication);
  static NAN_METHOD(EnumerateApplications);
  static NAN_METHOD(EnumerateProcesses);

  static NAN_METHOD(Spawn);
  static NAN_METHOD(Resume);
  static NAN_METHOD(Kill);
  static NAN_METHOD(Attach);

  v8::Persistent<v8::Object> events_;
};

}

#endif
