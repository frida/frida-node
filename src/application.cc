#include "application.h"

#include "icon.h"

#include <nan.h>

#define APPLICATION_DATA_CONSTRUCTOR "application:ctor"

using v8::AccessorSignature;
using v8::DEFAULT;
using v8::External;
using v8::Function;
using v8::Integer;
using v8::Isolate;
using v8::Local;
using v8::Object;
using v8::ReadOnly;
using v8::Value;

namespace frida {

Application::Application(FridaApplication* handle, Runtime* runtime)
    : GLibObject(handle, runtime) {
  g_object_ref(handle_);
}

Application::~Application() {
  g_object_unref(handle_);
}

void Application::Init(Local<Object> exports, Runtime* runtime) {
  auto isolate = Isolate::GetCurrent();

  auto name = Nan::New("Application").ToLocalChecked();
  auto tpl = CreateTemplate(name, Application::New, runtime);

  auto instance_tpl = tpl->InstanceTemplate();
  auto data = Local<Value>();
  auto signature = AccessorSignature::New(isolate, tpl);
  Nan::SetAccessor(instance_tpl, Nan::New("largeIcon").ToLocalChecked(),
      GetLargeIcon, 0, data, DEFAULT, ReadOnly, signature);
  Nan::SetAccessor(instance_tpl, Nan::New("smallIcon").ToLocalChecked(),
      GetSmallIcon, 0, data, DEFAULT, ReadOnly, signature);
  Nan::SetAccessor(instance_tpl, Nan::New("pid").ToLocalChecked(),
      GetPid, 0, data, DEFAULT, ReadOnly, signature);
  Nan::SetAccessor(instance_tpl, Nan::New("name").ToLocalChecked(),
      GetName, 0, data, DEFAULT, ReadOnly, signature);
  Nan::SetAccessor(instance_tpl, Nan::New("identifier").ToLocalChecked(),
      GetIdentifier, 0, data, DEFAULT, ReadOnly, signature);

  auto ctor = Nan::GetFunction(tpl).ToLocalChecked();
  Nan::Set(exports, name, ctor);
  runtime->SetDataPointer(APPLICATION_DATA_CONSTRUCTOR,
      new v8::Persistent<v8::Function>(isolate, ctor));
}

Local<Object> Application::New(gpointer handle, Runtime* runtime) {
  auto ctor = Nan::New<v8::Function>(
    *static_cast<v8::Persistent<v8::Function>*>(
      runtime->GetDataPointer(APPLICATION_DATA_CONSTRUCTOR)));

  const int argc = 1;
  Local<Value> argv[argc] = { Nan::New<v8::External>(handle) };
  return Nan::NewInstance(ctor, argc, argv).ToLocalChecked();
}

NAN_METHOD(Application::New) {
  if (!info.IsConstructCall()) {
    Nan::ThrowError("Use the `new` keyword to create a new instance");
    return;
  }

  if (info.Length() != 1 || !info[0]->IsExternal()) {
    Nan::ThrowTypeError("Bad argument, expected raw handle");
    return;
  }

  auto runtime = GetRuntimeFromConstructorArgs(info);

  auto handle = static_cast<FridaApplication*>(
      Local<External>::Cast(info[0])->Value());
  auto wrapper = new Application(handle, runtime);
  auto obj = info.This();
  wrapper->Wrap(obj);

  info.GetReturnValue().Set(obj);
}

NAN_PROPERTY_GETTER(Application::GetIdentifier) {
  auto handle = ObjectWrap::Unwrap<Application>(
      info.Holder())->GetHandle<FridaApplication>();

  info.GetReturnValue().Set(
      Nan::New(frida_application_get_identifier(handle)).ToLocalChecked());
}

NAN_PROPERTY_GETTER(Application::GetName) {
  auto handle = ObjectWrap::Unwrap<Application>(
      info.Holder())->GetHandle<FridaApplication>();

  info.GetReturnValue().Set(
      Nan::New(frida_application_get_name(handle)).ToLocalChecked());
}

NAN_PROPERTY_GETTER(Application::GetPid) {
  auto isolate = info.GetIsolate();
  auto handle = ObjectWrap::Unwrap<Application>(
      info.Holder())->GetHandle<FridaApplication>();

  info.GetReturnValue().Set(
      Integer::NewFromUnsigned(isolate, frida_application_get_pid(handle)));
}

NAN_PROPERTY_GETTER(Application::GetSmallIcon) {
  auto wrapper = ObjectWrap::Unwrap<Application>(info.Holder());
  auto handle = wrapper->GetHandle<FridaApplication>();

  info.GetReturnValue().Set(
      Icon::New(frida_application_get_small_icon(handle), wrapper->runtime_));
}

NAN_PROPERTY_GETTER(Application::GetLargeIcon) {
  auto wrapper = ObjectWrap::Unwrap<Application>(info.Holder());
  auto handle = wrapper->GetHandle<FridaApplication>();

  info.GetReturnValue().Set(
      Icon::New(frida_application_get_large_icon(handle), wrapper->runtime_));
}

}
