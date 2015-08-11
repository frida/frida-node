#ifndef FRIDANODE_RUNTIME_H
#define FRIDANODE_RUNTIME_H

#include "glib_context.h"
#include "uv_context.h"

#include <v8.h>

namespace frida {

class Runtime {
 public:
  Runtime(UVContext* uv_context, GLibContext* glib_context);
  ~Runtime();

  UVContext* GetUVContext() const;
  GLibContext* GetGLibContext() const;

  void* GetDataPointer(const char* id);
  void SetDataPointer(const char* id, void* value);

  v8::Local<v8::String> ValueToJson(v8::Handle<v8::Value> value);
  v8::Local<v8::Value> ValueFromJson(v8::Handle<v8::String> json);

 private:
  UVContext* uv_context_;
  GLibContext* glib_context_;

  GHashTable* data_;

  v8::Persistent<v8::Object> json_module_;
  v8::Persistent<v8::Function> json_stringify_;
  v8::Persistent<v8::Function> json_parse_;
};

}

#endif
