#ifndef FRIDANODE_CRASH_H
#define FRIDANODE_CRASH_H

#include "glib_object.h"

#include <frida-core.h>

namespace frida {

class Crash : public GLibObject {
 public:
  static void Init(v8::Local<v8::Object> exports, Runtime* runtime);
  static v8::Local<v8::Object> New(gpointer handle, Runtime* runtime);

 private:
  explicit Crash(FridaCrash* handle, Runtime* runtime);
  ~Crash();

  static NAN_METHOD(New);

  static NAN_PROPERTY_GETTER(GetPid);
  static NAN_PROPERTY_GETTER(GetProcessName);
  static NAN_PROPERTY_GETTER(GetSummary);
  static NAN_PROPERTY_GETTER(GetReport);
  static NAN_PROPERTY_GETTER(GetParameters);
};

}

#endif
