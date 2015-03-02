#ifndef FRIDANODE_MAINCONTEXT_H
#define FRIDANODE_MAINCONTEXT_H

#include <frida-core.h>

#include <functional>

namespace frida {

class MainContext {
public:
  MainContext(GMainContext* main_context);
  ~MainContext();

  void schedule(std::function<void ()> f);
  void perform(std::function<void ()> f);

  GMainContext* handle() const { return handle_; }

private:
  static gboolean InvokeCallback(gpointer data);
  static void DestroyCallback(gpointer data);

  GMainContext* handle_;
  GMutex mutex_;
  GCond cond_;
};

}

#endif
