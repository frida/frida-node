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

    Runtime::GetGLibContext()->schedule([=] () { Begin(); });
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

 private:
  void PerformEnd(GAsyncResult* result) {
    End(result, &error_);
    Runtime::GetUVContext()->schedule([=] () { Deliver(); });
  }

  void Deliver() {
    auto isolate = v8::Isolate::GetCurrent();
    v8::HandleScope scope(isolate);
    auto resolver = v8::Local<v8::Promise::Resolver>::New(isolate, resolver_);
    v8::TryCatch try_catch;
    try_catch.SetVerbose(true);
    if (error_ == NULL) {
      resolver->Resolve(Result(isolate));
    } else {
      resolver->Reject(v8::Exception::Error(v8::String::NewFromUtf8(isolate, error_->message)));
    }
    delete this;
  }

  GError* error_;
};

}

#endif
