#ifndef FRIDANODE_OPERATION_H
#define FRIDANODE_OPERATION_H

#include "runtime.h"

#include <frida-core.h>
#include <node.h>
#include <uv.h>

namespace frida {

template<class T>
class Operation {
 public:
  void Schedule(v8::Isolate* isolate, v8::Handle<v8::Object> parent, T* handle) {
    parent_.Reset(isolate, parent);
    handle_ = handle;
    resolver_.Reset(isolate, v8::Promise::Resolver::New(isolate));

    uv_async_init(uv_default_loop(), &async_, DeliverWrapper);
    async_.data = this;

    Runtime::GetMainContext()->schedule([=] () { Begin(); });
  }

  v8::Local<v8::Promise> GetPromise(v8::Isolate* isolate) {
    return v8::Local<v8::Promise::Resolver>::New(isolate, resolver_)->GetPromise();
  }

 protected:
  Operation() : handle_(NULL), error_(NULL) {
  }
  virtual ~Operation() {
    if (error_ != NULL) {
      g_error_free(error_);
    }
    if (handle_ != NULL) {
      // TODO: is uv_close() enough?
      uv_close(reinterpret_cast<uv_handle_t*>(&async_), NULL);
    }
    resolver_.Reset();
    parent_.Reset();
  }

  virtual void Begin() = 0;
  virtual void End(GAsyncResult* result, GError** error) = 0;
  virtual v8::Local<v8::Value> Result(v8::Isolate* isolate) = 0;

  static void OnReady(GObject* source_object, GAsyncResult* result, gpointer user_data) {
    auto self = static_cast<Operation<T>*>(user_data);
    self->PerformEnd(result);
  }

  v8::Persistent<v8::Value> parent_;
  T* handle_;
  v8::Persistent<v8::Promise::Resolver> resolver_;

 private:
  void PerformEnd(GAsyncResult* result) {
    End(result, &error_);
    uv_async_send(&async_);
  }

  static void DeliverWrapper(uv_async_t* async) {
    auto isolate = v8::Isolate::GetCurrent();
    v8::HandleScope scope(isolate);
    auto instance = static_cast<Operation<T>*>(async->data);
    instance->Deliver(isolate);
    delete instance;
  }

  void Deliver(v8::Isolate* isolate) {
    auto resolver = v8::Local<v8::Promise::Resolver>::New(isolate, resolver_);
    if (error_ == NULL) {
      resolver->Resolve(Result(isolate));
    } else {
      resolver->Reject(v8::Exception::Error(v8::String::NewFromUtf8(isolate, error_->message)));
    }
  }

  static MainContext* main_context_;
  uv_async_t async_;
  GError* error_;
};

}

#endif
