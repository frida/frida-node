#ifndef FRIDANODE_UV_CONTEXT_H
#define FRIDANODE_UV_CONTEXT_H

#include <glib.h>
#include <nan.h>

#include <functional>

namespace frida {

class UVContext {
public:
  UVContext(uv_loop_t* handle);
  ~UVContext();

  void IncreaseUsage();
  void DecreaseUsage();

  void Schedule(std::function<void ()> f);
  void Perform(std::function<void ()> f);

private:
  static void DeleteAsyncHandle(uv_handle_t* handle);
  void ProcessPending();
  static void ProcessPendingWrapper(const v8::FunctionCallbackInfo<v8::Value>& info);
  static void ProcessPendingWrapper(uv_async_t* handle);

  int usage_count_;
  uv_async_t* async_;
  Nan::AsyncResource async_resource_;
  GMutex mutex_;
  GCond cond_;
  GSList* pending_;
  v8::Persistent<v8::Object> module_;
  v8::Persistent<v8::Function> process_pending_;
};

}

#endif
