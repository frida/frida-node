#ifndef FRIDANODE_ENDPOINT_PARAMETERS_H
#define FRIDANODE_ENDPOINT_PARAMETERS_H

#include "glib_object.h"

#include <frida-core.h>

namespace frida {

class EndpointParameters : public GLibObject {
 public:
  static void Init(v8::Local<v8::Object> exports, Runtime* runtime);

  static FridaEndpointParameters* TryParse(v8::Local<v8::Value> value,
      Runtime* runtime);
  static bool HasInstance(v8::Local<v8::Value> value, Runtime* runtime);

 private:
  explicit EndpointParameters(FridaEndpointParameters* handle,
      Runtime* runtime);
  ~EndpointParameters();

  static NAN_METHOD(New);
};

}

#endif
