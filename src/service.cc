#include "service.h"

#include "operation.h"
#include "signals.h"
#include "usage_monitor.h"

#include <cstring>

#define SERVICE_DATA_CONSTRUCTOR "service:ctor"

using std::strcmp;
using v8::External;
using v8::Function;
using v8::Isolate;
using v8::Local;
using v8::Object;
using v8::Persistent;
using v8::Value;

namespace frida {

Service::Service(FridaService* handle, Runtime* runtime)
    : GLibObject(handle, runtime),
      usage_monitor_created_(false) {
  g_object_ref(handle_);
}

Service::~Service() {
  g_object_unref(handle_);
}

void Service::Init(Local<Object> exports, Runtime* runtime) {
  auto isolate = Isolate::GetCurrent();

  auto name = Nan::New("Service").ToLocalChecked();
  auto tpl = CreateTemplate(name, New, runtime);

  Nan::SetPrototypeMethod(tpl, "activate", Activate);
  Nan::SetPrototypeMethod(tpl, "cancel", Cancel);
  Nan::SetPrototypeMethod(tpl, "request", Request);

  auto ctor = Nan::GetFunction(tpl).ToLocalChecked();
  Nan::Set(exports, name, ctor);
  runtime->SetDataPointer(SERVICE_DATA_CONSTRUCTOR,
      new Persistent<Function>(isolate, ctor));
}

Local<Object> Service::New(gpointer handle, Runtime* runtime) {
  auto ctor = Nan::New<Function>(
      *static_cast<Persistent<Function>*>(
      runtime->GetDataPointer(SERVICE_DATA_CONSTRUCTOR)));
  const int argc = 1;
  Local<Value> argv[argc] = { Nan::New<External>(handle) };
  return Nan::NewInstance(ctor, argc, argv).ToLocalChecked();
}

NAN_METHOD(Service::New) {
  if (!info.IsConstructCall()) {
    Nan::ThrowError("Use the `new` keyword to create a new instance");
    return;
  }

  if (info.Length() != 1 || !info[0]->IsExternal()) {
    Nan::ThrowTypeError("Bad argument, expected raw handle");
    return;
  }

  auto runtime = GetRuntimeFromConstructorArgs(info);

  auto handle = static_cast<FridaService*>(
      Local<External>::Cast(info[0])->Value());
  auto wrapper = new Service(handle, runtime);
  auto obj = info.This();
  wrapper->Wrap(obj);
  auto signals_obj = Signals::New(handle, runtime, TransformSignal, runtime);

  Nan::Set(obj, Nan::New("signals").ToLocalChecked(), signals_obj);

  auto signals_wrapper = ObjectWrap::Unwrap<Signals>(signals_obj);
  signals_wrapper->SetConnectCallback(OnConnect, wrapper);

  info.GetReturnValue().Set(obj);
}

namespace {

class ActivateOperation : public Operation<FridaService> {
 protected:
  void Begin() {
    frida_service_activate(handle_, cancellable_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    frida_service_activate_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    return Nan::Undefined();
  }
};

}

NAN_METHOD(Service::Activate) {
  auto isolate = info.GetIsolate();
  auto wrapper = ObjectWrap::Unwrap<Service>(info.Holder());

  auto operation = new ActivateOperation();
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

namespace {

class CancelOperation : public Operation<FridaService> {
 protected:
  void Begin() {
    frida_service_cancel(handle_, cancellable_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    frida_service_cancel_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    return Nan::Undefined();
  }
};

}

NAN_METHOD(Service::Cancel) {
  auto isolate = info.GetIsolate();
  auto wrapper = ObjectWrap::Unwrap<Service>(info.Holder());

  auto operation = new CancelOperation();
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

namespace {

class RequestOperation : public Operation<FridaService> {
 public:
  RequestOperation(GVariant* parameters)
    : parameters_(parameters) {
  }

  ~RequestOperation() {
    g_variant_unref(parameters_);
  }

 protected:
  void Begin() {
    frida_service_request(handle_, parameters_, cancellable_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    response_ = frida_service_request_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    auto wrapper = Runtime::ValueFromVariant(response_);
    g_variant_unref(response_);
    return wrapper;
  }

 private:
  GVariant* parameters_;
  GVariant* response_;
};

}

NAN_METHOD(Service::Request) {
  auto isolate = info.GetIsolate();
  auto wrapper = ObjectWrap::Unwrap<Service>(info.Holder());

  if (info.Length() == 0) {
    Nan::ThrowTypeError("Expected a parameters value");
    return;
  }

  auto parameters = Runtime::ValueToVariant(info[0]);
  if (parameters == NULL) {
    return;
  }

  auto operation = new RequestOperation(parameters);
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

Local<Value> Service::TransformSignal(const gchar* name, guint index,
    const GValue* value, gpointer user_data) {
  if (index != 0 || strcmp(name, "message") != 0)
    return Local<Value>();
  return Runtime::ValueFromVariant(g_value_get_variant(value));
}

void Service::OnConnect(const gchar* name, gpointer user_data) {
  auto wrapper = static_cast<Service*>(user_data);

  if (ShouldStayAliveToEmit(name))
    wrapper->EnsureUsageMonitorCreated();
}

bool Service::ShouldStayAliveToEmit(const gchar* name) {
  return strcmp(name, "close") == 0 || strcmp(name, "message") == 0;
}

void Service::EnsureUsageMonitorCreated() {
  if (!usage_monitor_created_) {
    usage_monitor_created_ = true;
    auto monitor =
        new UsageMonitor<FridaService>(frida_service_is_closed, "close");
    monitor->Enable(this);
  }
}

}
