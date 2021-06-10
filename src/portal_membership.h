#ifndef FRIDANODE_PORTAL_MEMBERSHIP_H
#define FRIDANODE_PORTAL_MEMBERSHIP_H

#include "glib_object.h"

#include <frida-core.h>

namespace frida {

class PortalMembership : public GLibObject {
 public:
  static void Init(v8::Local<v8::Object> exports, Runtime* runtime);
  static v8::Local<v8::Object> New(gpointer handle, Runtime* runtime);

 private:
  explicit PortalMembership(FridaPortalMembership* handle, Runtime* runtime);
  ~PortalMembership();

  static NAN_METHOD(New);

  static NAN_METHOD(Terminate);
};

}

#endif
