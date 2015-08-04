#include "application.h"

#include "icon.h"

#include <nan.h>

#define APPLICATION_DATA_CONSTRUCTOR "application:ctor"

using v8::AccessorSignature;
using v8::DEFAULT;
using v8::External;
using v8::Function;
using v8::Handle;
using v8::Integer;
using v8::Isolate;
using v8::Local;
using v8::Object;
using v8::ReadOnly;
using v8::String;
using v8::Value;
using v8::Persistent;
using Nan::HandleScope;

namespace frida {

Application::Application(FridaApplication* handle, Runtime* runtime)
    : GLibObject(handle, runtime) {
  g_object_ref(handle_);
}

Application::~Application() {
  g_object_unref(handle_);
}

void Application::Init(Handle<Object> exports, Runtime* runtime) {
  auto isolate = Isolate::GetCurrent();

  auto name = Nan::New("Application").ToLocalChecked();
  auto tpl = CreateTemplate(isolate, name, Application::New, runtime);

  auto instance_tpl = tpl->InstanceTemplate();
  auto data = Handle<Value>();
  auto signature = AccessorSignature::New(isolate, tpl);
  Nan::SetAccessor(instance_tpl, Nan::New("identifier").ToLocalChecked(),
      GetIdentifier, 0, data, DEFAULT, ReadOnly, signature);
  Nan::SetAccessor(instance_tpl, Nan::New("name").ToLocalChecked(),
      GetName, 0, data, DEFAULT, ReadOnly, signature);
  Nan::SetAccessor(instance_tpl, Nan::New("pid").ToLocalChecked(),
      GetPid, 0, data, DEFAULT, ReadOnly, signature);
  Nan::SetAccessor(instance_tpl, Nan::New("smallIcon").ToLocalChecked(),
      GetSmallIcon, 0, data, DEFAULT, ReadOnly, signature);
  Nan::SetAccessor(instance_tpl, Nan::New("largeIcon").ToLocalChecked(),
      GetLargeIcon, 0, data, DEFAULT, ReadOnly, signature);

  auto ctor = Nan::GetFunction(tpl).ToLocalChecked();
  Nan::Set(exports, name, ctor);
  runtime->SetDataPointer(APPLICATION_DATA_CONSTRUCTOR,
      new v8::Persistent<Function>(isolate, ctor));
}

Local<Object> Application::New(gpointer handle, Runtime* runtime) {
  auto isolate = Isolate::GetCurrent();

  auto ctor = Local<Function>::New(isolate,
      *static_cast<v8::Persistent<Function>*>(
      runtime->GetDataPointer(APPLICATION_DATA_CONSTRUCTOR)));
  const int argc = 1;
  Local<Value> argv[argc] = { External::New(isolate, handle) };
  return ctor->NewInstance(argc, argv);
}

NAN_METHOD(Application::New) {
  HandleScope scope;

  if (info.IsConstructCall()) {
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
  } else {
    info.GetReturnValue().Set(info.Callee()->NewInstance(0, NULL));
  }
}

NAN_PROPERTY_GETTER(Application::GetIdentifier) {
  HandleScope scope;

  auto handle = ObjectWrap::Unwrap<Application>(
      info.Holder())->GetHandle<FridaApplication>();

  info.GetReturnValue().Set(
      Nan::New(frida_application_get_identifier(handle)).ToLocalChecked());
}

NAN_PROPERTY_GETTER(Application::GetName) {
  HandleScope scope;

  auto handle = ObjectWrap::Unwrap<Application>(
      info.Holder())->GetHandle<FridaApplication>();

  info.GetReturnValue().Set(
      Nan::New(frida_application_get_name(handle)).ToLocalChecked());
}

NAN_PROPERTY_GETTER(Application::GetPid) {
  HandleScope scope;

  auto isolate = info.GetIsolate();
  auto handle = ObjectWrap::Unwrap<Application>(
      info.Holder())->GetHandle<FridaApplication>();

  info.GetReturnValue().Set(
      Integer::NewFromUnsigned(isolate, frida_application_get_pid(handle)));
}

NAN_PROPERTY_GETTER(Application::GetSmallIcon) {
  HandleScope scope;

  auto wrapper = ObjectWrap::Unwrap<Application>(info.Holder());
  auto handle = wrapper->GetHandle<FridaApplication>();

  info.GetReturnValue().Set(
      Icon::New(frida_application_get_small_icon(handle), wrapper->runtime_));
}

NAN_PROPERTY_GETTER(Application::GetLargeIcon) {
  HandleScope scope;

  auto wrapper = ObjectWrap::Unwrap<Application>(info.Holder());
  auto handle = wrapper->GetHandle<FridaApplication>();

  info.GetReturnValue().Set(
      Icon::New(frida_application_get_large_icon(handle), wrapper->runtime_));
}

}
