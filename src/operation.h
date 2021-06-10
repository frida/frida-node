#ifndef FRIDANODE_OPERATION_H
#define FRIDANODE_OPERATION_H

#include "cancellable.h"
#include "runtime.h"

namespace frida {

template<class T>
class Operation {
 public:
  void Schedule(v8::Isolate* isolate, GLibObject* parent,
      const Nan::FunctionCallbackInfo<v8::Value>& info) {
    wrapper_ = parent;
    parent_.Reset(isolate, parent->handle(isolate));
    handle_ = parent->GetHandle<T>();
    resolver_.Reset(isolate,
        v8::Promise::Resolver::New(isolate->GetCurrentContext())
            .ToLocalChecked());
    runtime_ = parent->GetRuntime();

    auto num_args = info.Length();
    if (num_args >= 1) {
      cancellable_ = Cancellable::TryParse(info[num_args - 1], runtime_);
    }

    runtime_->GetUVContext()->IncreaseUsage();
    runtime_->GetGLibContext()->Schedule([=]() { Begin(); });
  }

  v8::Local<v8::Promise> GetPromise(v8::Isolate* isolate) {
    return v8::Local<v8::Promise::Resolver>::New(isolate, resolver_)->GetPromise();
  }

 protected:
  Operation()
    : wrapper_(NULL),
      handle_(NULL),
      cancellable_(NULL),
      runtime_(NULL),
      error_(NULL) {
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

  template<typename W>
  W* GetWrapper() const { return static_cast<W*>(wrapper_); }

  static void OnReady(GObject* source_object, GAsyncResult* result, gpointer user_data) {
    static_cast<Operation<T>*>(user_data)->PerformEnd(result);
  }

  void* wrapper_;
  v8::Persistent<v8::Value> parent_;
  T* handle_;
  GCancellable* cancellable_;
  v8::Persistent<v8::Promise::Resolver> resolver_;
  Runtime* runtime_;

 private:
  void PerformEnd(GAsyncResult* result) {
    End(result, &error_);
    runtime_->GetUVContext()->Schedule([=]() { Deliver(); });
  }

  void Deliver() {
    auto isolate = v8::Isolate::GetCurrent();
    auto context = isolate->GetCurrentContext();
    auto resolver = v8::Local<v8::Promise::Resolver>::New(isolate, resolver_);
    if (error_ == NULL) {
      resolver->Resolve(context, Result(isolate)).FromJust();
    } else {
      resolver->Reject(context, Nan::Error(error_->message)).FromJust();
    }
    runtime_->GetUVContext()->DecreaseUsage();
    delete this;
  }

  GError* error_;
};

}

#endif
