#ifndef FRIDANODE_UV_CONTEXT_H
#define FRIDANODE_UV_CONTEXT_H

#include <glib.h>
#include <uv.h>

#include <functional>

namespace frida {

class UVContext {
public:
  UVContext(uv_loop_t* handle);
  ~UVContext();

  void schedule(std::function<void ()> f);
  void perform(std::function<void ()> f);

private:
  void ProcessPending();
  static void ProcessPendingWrapper(uv_async_t* handle);

  uv_async_t async_;
  GMutex mutex_;
  GCond cond_;
  GSList* pending_;
};

}

#endif
