#include "bus.h"

#include "operation.h"
#include "signals.h"
#include "usage_monitor.h"

#include <cstring>

#define BUS_DATA_CONSTRUCTOR "bus:ctor"

using std::strcmp;
using v8::External;
using v8::Function;
using v8::Isolate;
using v8::Local;
using v8::Object;
using v8::Persistent;
using v8::Value;

namespace frida {

Bus::Bus(FridaBus* handle, Runtime* runtime)
    : GLibObject(handle, runtime) {
  g_object_ref(handle_);
}

Bus::~Bus() {
  g_object_unref(handle_);
}

void Bus::Init(Local<Object> exports, Runtime* runtime) {
  auto isolate = Isolate::GetCurrent();

  auto name = Nan::New("Bus").ToLocalChecked();
  auto tpl = CreateTemplate(name, New, runtime);

  Nan::SetPrototypeMethod(tpl, "attach", Attach);
  Nan::SetPrototypeMethod(tpl, "post", Post);

  auto ctor = Nan::GetFunction(tpl).ToLocalChecked();
  Nan::Set(exports, name, ctor);
  runtime->SetDataPointer(BUS_DATA_CONSTRUCTOR,
      new Persistent<Function>(isolate, ctor));
}

Local<Object> Bus::New(gpointer handle, Runtime* runtime) {
  auto ctor = Nan::New<Function>(
      *static_cast<Persistent<Function>*>(
      runtime->GetDataPointer(BUS_DATA_CONSTRUCTOR)));
  const int argc = 1;
  Local<Value> argv[argc] = { Nan::New<External>(handle) };
  return Nan::NewInstance(ctor, argc, argv).ToLocalChecked();
}

NAN_METHOD(Bus::New) {
  if (!info.IsConstructCall()) {
    Nan::ThrowError("Use the `new` keyword to create a new instance");
    return;
  }

  if (info.Length() != 1 || !info[0]->IsExternal()) {
    Nan::ThrowTypeError("Bad argument, expected raw handle");
    return;
  }

  auto runtime = GetRuntimeFromConstructorArgs(info);

  auto handle = static_cast<FridaBus*>(
      Local<External>::Cast(info[0])->Value());
  auto wrapper = new Bus(handle, runtime);
  auto obj = info.This();
  wrapper->Wrap(obj);
  auto signals_obj = Signals::New(handle, runtime, TransformSignal, runtime);

  Nan::Set(obj, Nan::New("signals").ToLocalChecked(), signals_obj);

  auto signals_wrapper = ObjectWrap::Unwrap<Signals>(signals_obj);
  signals_wrapper->SetConnectCallback(OnConnect, runtime);
  signals_wrapper->SetDisconnectCallback(OnDisconnect, runtime);

  info.GetReturnValue().Set(obj);
}

namespace {

class AttachOperation : public Operation<FridaBus> {
 protected:
  void Begin() {
    frida_bus_attach(handle_, cancellable_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    frida_bus_attach_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    return Nan::Undefined();
  }
};

}

NAN_METHOD(Bus::Attach) {
  auto isolate = info.GetIsolate();
  auto wrapper = ObjectWrap::Unwrap<Bus>(info.Holder());

  auto operation = new AttachOperation();
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

NAN_METHOD(Bus::Post) {
  auto wrapper = ObjectWrap::Unwrap<Bus>(info.Holder());

  auto num_args = info.Length();
  if (num_args < 2) {
    Nan::ThrowTypeError("Expected message and data");
    return;
  }

  Nan::Utf8String message(wrapper->runtime_->ValueToJson(info[0]));

  GBytes* data = NULL;
  auto buffer = info[1];
  if (!buffer->IsNull()) {
    if (!node::Buffer::HasInstance(buffer)) {
      Nan::ThrowTypeError("Expected a buffer");
      return;
    }
    data = g_bytes_new(node::Buffer::Data(buffer),
        node::Buffer::Length(buffer));
  }

  frida_bus_post(wrapper->GetHandle<FridaBus>(), *message, data);

  g_bytes_unref(data);
}

Local<Value> Bus::TransformSignal(const gchar* name, guint index,
    const GValue* value, gpointer user_data) {
  if (index != 0 || strcmp(name, "message") != 0)
    return Local<Value>();
  auto runtime = static_cast<Runtime*>(user_data);
  auto json = Nan::New(g_value_get_string(value)).ToLocalChecked();
  return runtime->ValueFromJson(json);
}

void Bus::OnConnect(const gchar* name, gpointer user_data) {
  auto runtime = static_cast<Runtime*>(user_data);

  if (ShouldStayAliveToEmit(name))
    runtime->GetUVContext()->IncreaseUsage();
}

void Bus::OnDisconnect(const gchar* name, gpointer user_data) {
  auto runtime = static_cast<Runtime*>(user_data);

  if (ShouldStayAliveToEmit(name))
    runtime->GetUVContext()->DecreaseUsage();
}

bool Bus::ShouldStayAliveToEmit(const gchar* name) {
  return strcmp(name, "detached") == 0 || strcmp(name, "message") == 0;
}

}
