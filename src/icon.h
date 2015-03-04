#ifndef FRIDANODE_ICON_H
#define FRIDANODE_ICON_H

#include "glib_object.h"

#include <frida-core.h>

namespace frida {

class Icon : public GLibObject {
 public:
  static void Init(v8::Handle<v8::Object> exports, Runtime* runtime);
  static v8::Local<v8::Value> New(gpointer handle, Runtime* runtime);

 private:
  explicit Icon(FridaIcon* handle, Runtime* runtime);
  ~Icon();

  static void New(const v8::FunctionCallbackInfo<v8::Value>& args);

  static void GetWidth(v8::Local<v8::String> property,
      const v8::PropertyCallbackInfo<v8::Value>& info);
  static void GetHeight(v8::Local<v8::String> property,
      const v8::PropertyCallbackInfo<v8::Value>& info);
  static void GetRowstride(v8::Local<v8::String> property,
      const v8::PropertyCallbackInfo<v8::Value>& info);
  static void GetPixels(v8::Local<v8::String> property,
      const v8::PropertyCallbackInfo<v8::Value>& info);
};

}

#endif
