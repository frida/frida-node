#include "cancellable.h"

#include "signals.h"

#define CANCELLABLE_DATA_TEMPLATE "cancellable:tpl"

using v8::DEFAULT;
using v8::External;
using v8::Function;
using v8::FunctionTemplate;
using v8::Isolate;
using v8::Local;
using v8::Object;
using v8::Persistent;
using v8::ReadOnly;
using v8::Value;

namespace frida {

Cancellable::Cancellable(GCancellable* handle, Runtime* runtime)
    : GLibObject(handle, runtime) {
  g_object_ref(handle_);
}

Cancellable::~Cancellable() {
  g_object_unref(handle_);
}

void Cancellable::Init(Local<Object> exports, Runtime* runtime) {
  auto isolate = Isolate::GetCurrent();

  auto name = Nan::New("Cancellable").ToLocalChecked();
  auto tpl = CreateTemplate(name, Cancellable::New, runtime);

  auto instance_tpl = tpl->InstanceTemplate();
  auto data = Local<Value>();
  Nan::SetAccessor(instance_tpl, Nan::New("isCancelled").ToLocalChecked(),
      IsCancelled, 0, data, DEFAULT, ReadOnly);

  Nan::SetPrototypeMethod(tpl, "throwIfCancelled", ThrowIfCancelled);
  Nan::SetPrototypeMethod(tpl, "cancel", Cancel);

  auto ctor = Nan::GetFunction(tpl).ToLocalChecked();
  Nan::Set(exports, name, ctor);
  runtime->SetDataPointer(CANCELLABLE_DATA_TEMPLATE,
      new Persistent<FunctionTemplate>(isolate, tpl));
}

GCancellable* Cancellable::TryParse(Local<Value> value, Runtime* runtime) {
  if (!value->IsObject())
    return NULL;

  auto impl = Nan::Get(value.As<Object>(), Nan::New("impl").ToLocalChecked())
      .ToLocalChecked();
  if (!HasInstance(impl, runtime))
    return NULL;

  return ObjectWrap::Unwrap<Cancellable>(impl.As<Object>())
      ->GetHandle<GCancellable>();
}

bool Cancellable::HasInstance(Local<Value> value, Runtime* runtime) {
  auto tpl = Nan::New<FunctionTemplate>(
      *static_cast<Persistent<FunctionTemplate>*>(
      runtime->GetDataPointer(CANCELLABLE_DATA_TEMPLATE)));
  return tpl->HasInstance(value);
}

NAN_METHOD(Cancellable::New) {
  if (!info.IsConstructCall()) {
    Nan::ThrowError("Use the `new` keyword to create a new instance");
    return;
  }

  auto runtime = GetRuntimeFromConstructorArgs(info);

  auto handle = g_cancellable_new();

  auto wrapper = new Cancellable(handle, runtime);
  auto obj = info.This();
  wrapper->Wrap(obj);

  auto signals_obj = Signals::New(handle, runtime);
  Nan::Set(obj, Nan::New("signals").ToLocalChecked(), signals_obj);

  g_object_unref(handle);

  info.GetReturnValue().Set(obj);
}

NAN_PROPERTY_GETTER(Cancellable::IsCancelled) {
  auto handle = ObjectWrap::Unwrap<Cancellable>(
      info.Holder())->GetHandle<GCancellable>();

  info.GetReturnValue().Set(
      static_cast<bool>(g_cancellable_is_cancelled(handle)));
}

NAN_METHOD(Cancellable::ThrowIfCancelled) {
  auto handle = ObjectWrap::Unwrap<Cancellable>(
      info.Holder())->GetHandle<GCancellable>();

  GError* error = NULL;
  if (g_cancellable_set_error_if_cancelled(handle, &error)) {
    Nan::ThrowError(Nan::Error(error->message));
    g_error_free(error);
  }
}

NAN_METHOD(Cancellable::Cancel) {
  auto handle = ObjectWrap::Unwrap<Cancellable>(
      info.Holder())->GetHandle<GCancellable>();

  g_cancellable_cancel(handle);
}

}
