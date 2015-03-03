#ifndef FRIDANODE_GLIB_CONTEXT_H
#define FRIDANODE_GLIB_CONTEXT_H

#include <frida-core.h>

#include <functional>

namespace frida {

class GLibContext {
public:
  GLibContext(GMainContext* main_context);
  ~GLibContext();

  void Schedule(std::function<void ()> f);
  void Perform(std::function<void ()> f);

private:
  static gboolean InvokeCallback(gpointer data);
  static void DestroyCallback(gpointer data);

  GMainContext* main_context_;
  GMutex mutex_;
  GCond cond_;
};

}

#endif
