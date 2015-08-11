#ifndef FRIDANODE_OPERATION_H
#define FRIDANODE_OPERATION_H

#include "runtime.h"

#include <glib.h>
#include <nan.h>

namespace frida {

template<class T>
class Operation {
 public:
  void Schedule(v8::Isolate* isolate, GLibObject* parent) {
    parent_.Reset(isolate, parent->handle(isolate));
    handle_ = parent->GetHandle<T>();
    resolver_.Reset(isolate, v8::Promise::Resolver::New(isolate));
    runtime_ = parent->GetRuntime();

    runtime_->GetUVContext()->IncreaseUsage();
    runtime_->GetGLibContext()->Schedule([=]() { Begin(); });
  }

  v8::Local<v8::Promise> GetPromise(v8::Isolate* isolate) {
    return v8::Local<v8::Promise::Resolver>::New(isolate, resolver_)->GetPromise();
  }

 protected:
  Operation() : handle_(NULL), runtime_(NULL), error_(NULL) {
  }

  virtual ~Operation() {
    if (error_ != NULL) {
      g_error_free(error_);
    }
    resolver_.Reset();
    parent_.Reset();
  }

  virtual void Begin() = 0;
  virtual void End(GAsyncResult* result, GError** error) = 0;
  virtual v8::Local<v8::Value> Result(v8::Isolate* isolate) = 0;

  static void OnReady(GObject* source_object, GAsyncResult* result, gpointer user_data) {
    static_cast<Operation<T>*>(user_data)->PerformEnd(result);
  }

  v8::Persistent<v8::Value> parent_;
  T* handle_;
  v8::Persistent<v8::Promise::Resolver> resolver_;
  Runtime* runtime_;

 private:
  void PerformEnd(GAsyncResult* result) {
    End(result, &error_);
    runtime_->GetUVContext()->Schedule([=]() { Deliver(); });
  }

  void Deliver() {
    auto isolate = v8::Isolate::GetCurrent();
    auto resolver = v8::Local<v8::Promise::Resolver>::New(isolate, resolver_);
    if (error_ == NULL) {
      resolver->Resolve(Result(isolate));
    } else {
      resolver->Reject(Nan::Error(error_->message));
    }
    runtime_->GetUVContext()->DecreaseUsage();
    delete this;
  }

  GError* error_;
};

}

#endif
