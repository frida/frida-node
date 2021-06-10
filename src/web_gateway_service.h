#ifndef FRIDANODE_WEB_GATEWAY_SERVICE_H
#define FRIDANODE_WEB_GATEWAY_SERVICE_H

#include "glib_object.h"

#include <frida-core.h>

namespace frida {

class WebGatewayService : public GLibObject {
 public:
  static void Init(v8::Local<v8::Object> exports, Runtime* runtime);

 private:
  explicit WebGatewayService(FridaWebGatewayService* handle, Runtime* runtime);
  ~WebGatewayService();

  static NAN_METHOD(New);

  static NAN_METHOD(Start);
  static NAN_METHOD(Stop);
};

}

#endif
