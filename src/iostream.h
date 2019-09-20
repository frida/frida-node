#ifndef FRIDANODE_IOSTREAM_H
#define FRIDANODE_IOSTREAM_H

#include "glib_object.h"

#include <gio/gio.h>
#include <nan.h>

namespace frida {

class IOStream : public GLibObject {
 public:
  static void Init(v8::Local<v8::Object> exports, Runtime* runtime);
  static v8::Local<v8::Object> New(gpointer handle, Runtime* runtime);

 private:
  explicit IOStream(GIOStream* handle, Runtime* runtime);
  ~IOStream();

  static NAN_METHOD(New);

  static NAN_PROPERTY_GETTER(IsClosed);

  static NAN_METHOD(Close);
  static NAN_METHOD(Read);
  static NAN_METHOD(Write);

  v8::Persistent<v8::Object> signals_;
};

}

#endif
