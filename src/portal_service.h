#ifndef FRIDANODE_PORTAL_SERVICE_H
#define FRIDANODE_PORTAL_SERVICE_H

#include "glib_object.h"

#include <frida-core.h>

namespace frida {

class PortalService : public GLibObject {
 public:
  static void Init(v8::Local<v8::Object> exports, Runtime* runtime);

 private:
  explicit PortalService(FridaPortalService* handle, Runtime* runtime);
  ~PortalService();

  static NAN_METHOD(New);

  static NAN_PROPERTY_GETTER(GetDevice);

  static NAN_METHOD(Start);
  static NAN_METHOD(Stop);
  static NAN_METHOD(Post);
  static NAN_METHOD(Narrowcast);
  static NAN_METHOD(Broadcast);
  static NAN_METHOD(EnumerateTags);
  static NAN_METHOD(Tag);
  static NAN_METHOD(Untag);

  static bool ValueToConnectionId(v8::Local<v8::Value> value,
      guint* connection_id);

  static v8::Local<v8::Value> TransformSignal(const gchar* name, guint index,
      const GValue* value, gpointer user_data);
};

}

#endif
