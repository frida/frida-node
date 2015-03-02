#ifndef FRIDANODE_RUNTIME_H
#define FRIDANODE_RUNTIME_H

#include "glib_context.h"
#include "uv_context.h"

namespace frida {

class Runtime {
 public:
  static void Init(UVContext* uv_context, GLibContext* glib_context) {
    uv_context_ = uv_context;
    glib_context_ = glib_context;
  }

  static UVContext* GetUVContext() { return uv_context_; }
  static GLibContext* GetGLibContext() { return glib_context_; }

 private:
  static UVContext* uv_context_;
  static GLibContext* glib_context_;
};

}

#endif
