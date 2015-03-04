#ifndef FRIDANODE_RUNTIME_H
#define FRIDANODE_RUNTIME_H

#include "glib_context.h"
#include "uv_context.h"

namespace frida {

class Runtime {
 public:
  Runtime(UVContext* uv_context, GLibContext* glib_context);
  ~Runtime();

  UVContext* GetUVContext() const;
  GLibContext* GetGLibContext() const;

  void* GetDataPointer(const char* id);
  void SetDataPointer(const char* id, void* value);

 private:
  UVContext* uv_context_;
  GLibContext* glib_context_;
  GHashTable* data_;
};

}

#endif
