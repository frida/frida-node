#ifndef FRIDANODE_USAGE_MONITOR_H
#define FRIDANODE_USAGE_MONITOR_H

#include "glib_object.h"

using Nan::HandleScope;

namespace frida {

template<typename T>
class UsageMonitor {
 public:
  typedef gboolean (*CheckCallback)(T* self);

  UsageMonitor(CheckCallback check, const gchar* signal)
      : ref_count_(1),
        check_(check),
        signal_(signal),
        instance_(NULL),
        handler_id_(0),
        runtime_(NULL) {
  }

 private:
  void Ref() {
    g_atomic_int_add(&ref_count_, 1);
  }

  void Unref() {
    if (g_atomic_int_add(&ref_count_, -1) - 1 == 0) {
      delete this;
    }
  }

  ~UsageMonitor() {
    if (!object_.IsEmpty()) {
      object_.ClearWeak();
      object_.Reset();
    }
  }

 public:
  void Enable(GLibObject* wrapper) {
    g_assert(instance_ == NULL);

    auto isolate = v8::Isolate::GetCurrent();
    object_.Reset(wrapper->handle(isolate));
    object_.SetWeak(this, OnWeakNotifyWrapper, Nan::WeakCallbackType::kParameter);
#if NODE_MAJOR_VERSION < 12
    object_.MarkIndependent();
#endif
    instance_ = wrapper->GetHandle<T>();
    g_object_ref(instance_);
    runtime_ = wrapper->GetRuntime();

    runtime_->GetUVContext()->IncreaseUsage();
    runtime_->GetGLibContext()->Schedule([=]() {
      handler_id_ = g_signal_connect_swapped(instance_, signal_,
          reinterpret_cast<GCallback>(OnSignal), this);
      Check();
    });
  }

 private:
  void Disable() {
    if (instance_ == NULL)
      return;

    g_signal_handler_disconnect(instance_, handler_id_);
    g_object_unref(instance_);
    instance_ = NULL;

    runtime_->GetUVContext()->Schedule([=]() {
      runtime_->GetUVContext()->DecreaseUsage();
      Unref();
    });
  }

  void Check() {
    if (check_(instance_))
      Disable();
  }

  static void OnWeakNotifyWrapper(
      const Nan::WeakCallbackInfo<UsageMonitor<T>>& data) {
    HandleScope scope;
    data.GetParameter()->OnWeakNotify();
  }

  void OnWeakNotify() {
    object_.Reset();

    Ref();
    runtime_->GetGLibContext()->Schedule([=]() {
      Disable();
      runtime_->GetUVContext()->Schedule([=]() {
        Unref();
      });
    });
  }

  static void OnSignal(UsageMonitor* monitor) {
    monitor->Check();
  }

  volatile gint ref_count_;
  CheckCallback check_;
  const gchar* signal_;
  Nan::Persistent<v8::Object> object_;
  T* instance_;
  guint handler_id_;
  Runtime* runtime_;
};

}

#endif
