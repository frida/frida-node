#ifndef FRIDANODE_SPAWN_H
#define FRIDANODE_SPAWN_H

#include "glib_object.h"

#include <frida-core.h>

namespace frida {

class Spawn : public GLibObject {
 public:
  static void Init(v8::Local<v8::Object> exports, Runtime* runtime);
  static v8::Local<v8::Object> New(gpointer handle, Runtime* runtime);

 private:
  explicit Spawn(FridaSpawn* handle, Runtime* runtime);
  ~Spawn();

  static NAN_METHOD(New);

  static NAN_PROPERTY_GETTER(GetPid);
  static NAN_PROPERTY_GETTER(GetIdentifier);
};

}

#endif
