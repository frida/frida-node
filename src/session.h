#ifndef FRIDANODE_SESSION_H
#define FRIDANODE_SESSION_H

#include "glib_object.h"

#include <frida-core.h>

namespace frida {

class Session : public GLibObject {
 public:
  static void Init(v8::Local<v8::Object> exports, Runtime* runtime);
  static v8::Local<v8::Object> New(gpointer handle, Runtime* runtime);

 private:
  explicit Session(FridaSession* handle, Runtime* runtime);
  ~Session();

  static NAN_METHOD(New);

  static NAN_PROPERTY_GETTER(GetPid);
  static NAN_PROPERTY_GETTER(GetPersistTimeout);
  static NAN_PROPERTY_GETTER(IsDetached);

  static NAN_METHOD(Detach);
  static NAN_METHOD(Resume);
  static NAN_METHOD(EnableChildGating);
  static NAN_METHOD(DisableChildGating);
  static NAN_METHOD(CreateScript);
  static NAN_METHOD(CreateScriptFromBytes);
  static NAN_METHOD(CompileScript);
  static NAN_METHOD(SnapshotScript);
  static NAN_METHOD(SetupPeerConnection);
  static NAN_METHOD(JoinPortal);

  static v8::Local<v8::Value> TransformSignal(const gchar* name, guint index,
      const GValue* value, gpointer user_data);
};

}

#endif
