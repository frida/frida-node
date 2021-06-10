#ifndef FRIDANODE_RELAY_H
#define FRIDANODE_RELAY_H

#include "glib_object.h"

#include <frida-core.h>

namespace frida {

class Relay : public GLibObject {
 public:
  static void Init(v8::Local<v8::Object> exports, Runtime* runtime);

  static FridaRelay* TryParse(v8::Local<v8::Value> value, Runtime* runtime);
  static bool HasInstance(v8::Local<v8::Value> value, Runtime* runtime);

 private:
  explicit Relay(FridaRelay* handle, Runtime* runtime);
  ~Relay();

  static NAN_METHOD(New);

  static NAN_PROPERTY_GETTER(GetAddress);
  static NAN_PROPERTY_GETTER(GetUsername);
  static NAN_PROPERTY_GETTER(GetPassword);
  static NAN_PROPERTY_GETTER(GetKind);
};

}

#endif
