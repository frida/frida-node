#ifndef FRIDANODE_CANCELLABLE_H
#define FRIDANODE_CANCELLABLE_H

#include "glib_object.h"

#include <gio/gio.h>

namespace frida {

class Cancellable : public GLibObject {
 public:
  static void Init(v8::Local<v8::Object> exports, Runtime* runtime);

  static GCancellable* TryParse(v8::Local<v8::Value> value, Runtime* runtime);
  static bool HasInstance(v8::Local<v8::Value> value, Runtime* runtime);

 private:
  explicit Cancellable(GCancellable* handle, Runtime* runtime);
  ~Cancellable();

  static NAN_METHOD(New);

  static NAN_PROPERTY_GETTER(IsCancelled);

  static NAN_METHOD(ThrowIfCancelled);
  static NAN_METHOD(Cancel);
};

}

#endif
