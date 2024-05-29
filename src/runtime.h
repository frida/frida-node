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

  v8::Local<v8::String> ValueToJson(v8::Local<v8::Value> value);
  v8::Local<v8::Value> ValueFromJson(v8::Local<v8::String> json);

  static v8::Local<v8::Value> ValueFromDatetime(const char* iso8601_text);

  static bool ValueToStrv(v8::Local<v8::Value> value, gchar*** strv,
      gint* length);
  static v8::Local<v8::Value> ValueFromStrv(gchar* const* strv, gint length);

  static bool ValueToEnvp(v8::Local<v8::Value> value, gchar*** envp,
      gint* length);
  static v8::Local<v8::Value> ValueFromEnvp(gchar* const* envp, gint length);

  static bool ValueToEnum(v8::Local<v8::Value> value, GType type,
      gpointer result);
  static v8::Local<v8::String> ValueFromEnum(gint value, GType type);

  static v8::Local<v8::Value> ValueFromParametersDict(GHashTable* dict);

  static GVariant* ValueToVariant(v8::Local<v8::Value> value);
  static v8::Local<v8::Value> ValueFromVariant(GVariant* v);

  static v8::Local<v8::Object> ValueFromSocketAddress(GSocketAddress* address);

  static bool ValueToCertificate(v8::Local<v8::Value> value,
      GTlsCertificate** certificate);

  static const char* ClassNameFromC(const char* cname);
  static char* ParameterNameFromC(const char* cname);

 private:
  static v8::Local<v8::Value> ValueFromVariantByteArray(GVariant* v);
  static v8::Local<v8::Value> ValueFromVariantDict(GVariant* v);
  static v8::Local<v8::Value> ValueFromVariantArray(GVariant* v);

  UVContext* uv_context_;
  GLibContext* glib_context_;

  GHashTable* data_;

  v8::Persistent<v8::Object> json_module_;
  v8::Persistent<v8::Function> json_stringify_;
  v8::Persistent<v8::Function> json_parse_;
};

}

#endif
