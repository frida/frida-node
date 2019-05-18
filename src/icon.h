#ifndef FRIDANODE_ICON_H
#define FRIDANODE_ICON_H

#include "glib_object.h"

#include <frida-core.h>
#include <nan.h>

namespace frida {

class Icon : public GLibObject {
 public:
  static void Init(v8::Local<v8::Object> exports, Runtime* runtime);
  static v8::Local<v8::Value> New(gpointer handle, Runtime* runtime);

 private:
  explicit Icon(FridaIcon* handle, Runtime* runtime);
  ~Icon();

  static NAN_METHOD(New);

  static NAN_PROPERTY_GETTER(GetWidth);
  static NAN_PROPERTY_GETTER(GetHeight);
  static NAN_PROPERTY_GETTER(GetRowstride);
  static NAN_PROPERTY_GETTER(GetPixels);

};

}

#endif
