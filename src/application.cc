#include "application.h"

#include "icon.h"

#include <nan.h>

#define APPLICATION_DATA_CONSTRUCTOR "application:ctor"

using v8::AccessorSignature;
using v8::DEFAULT;
using v8::Exception;
using v8::External;
using v8::Function;
using v8::FunctionCallbackInfo;
using v8::Handle;
using v8::Integer;
using v8::Isolate;
using v8::Local;
using v8::Object;
using v8::Persistent;
using v8::PropertyCallbackInfo;
using v8::ReadOnly;
using v8::String;
using v8::Value;

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

  auto name = NanNew("Application");
  auto tpl = CreateTemplate(isolate, name, New, runtime);

  auto instance_tpl = tpl->InstanceTemplate();
  auto data = Handle<Value>();
  auto signature = AccessorSignature::New(isolate, tpl);
  instance_tpl->SetAccessor(NanNew("identifier"),
      GetIdentifier, 0, data, DEFAULT, ReadOnly, signature);
  instance_tpl->SetAccessor(NanNew("name"),
      GetName, 0, data, DEFAULT, ReadOnly, signature);
  instance_tpl->SetAccessor(NanNew("pid"),
      GetPid, 0, data, DEFAULT, ReadOnly, signature);
  instance_tpl->SetAccessor(NanNew("smallIcon"),
      GetSmallIcon, 0, data, DEFAULT, ReadOnly, signature);
  instance_tpl->SetAccessor(NanNew("largeIcon"),
      GetLargeIcon, 0, data, DEFAULT, ReadOnly, signature);

  auto ctor = tpl->GetFunction();
  exports->Set(name, ctor);
  runtime->SetDataPointer(APPLICATION_DATA_CONSTRUCTOR,
      new Persistent<Function>(isolate, ctor));
}

Local<Object> Application::New(gpointer handle, Runtime* runtime) {
  auto isolate = Isolate::GetCurrent();

  auto ctor = Local<Function>::New(isolate,
      *static_cast<Persistent<Function>*>(
      runtime->GetDataPointer(APPLICATION_DATA_CONSTRUCTOR)));
  const int argc = 1;
  Local<Value> argv[argc] = { External::New(isolate, handle) };
  return ctor->NewInstance(argc, argv);
}

void Application::New(const FunctionCallbackInfo<Value>& args) {

  NanScope();

  auto isolate = args.GetIsolate();

  if (args.IsConstructCall()) {
    if (args.Length() != 1 || !args[0]->IsExternal()) {
      isolate->ThrowException(Exception::TypeError(NanNew(
        "Bad argument, expected raw handle")));
      return;
    }
    auto runtime = GetRuntimeFromConstructorArgs(args);

    auto handle = static_cast<FridaApplication*>(
        Local<External>::Cast(args[0])->Value());
    auto wrapper = new Application(handle, runtime);
    auto obj = args.This();
    wrapper->Wrap(obj);

    args.GetReturnValue().Set(obj);
  } else {
    args.GetReturnValue().Set(args.Callee()->NewInstance(0, NULL));
  }
}

void Application::GetIdentifier(Local<String> property,
    const PropertyCallbackInfo<Value>& info) {

  NanScope();

  auto isolate = info.GetIsolate();
  auto handle = ObjectWrap::Unwrap<Application>(
      info.Holder())->GetHandle<FridaApplication>();

  info.GetReturnValue().Set(
      String::NewFromUtf8(isolate, frida_application_get_identifier(handle)));
}

void Application::GetName(Local<String> property,
    const PropertyCallbackInfo<Value>& info) {

  NanScope();

  auto isolate = info.GetIsolate();
  auto handle = ObjectWrap::Unwrap<Application>(
      info.Holder())->GetHandle<FridaApplication>();

  info.GetReturnValue().Set(
      String::NewFromUtf8(isolate, frida_application_get_name(handle)));
}

void Application::GetPid(Local<String> property,
    const PropertyCallbackInfo<Value>& info) {

  NanScope();

  auto isolate = info.GetIsolate();
  auto handle = ObjectWrap::Unwrap<Application>(
      info.Holder())->GetHandle<FridaApplication>();

  info.GetReturnValue().Set(
      Integer::NewFromUnsigned(isolate, frida_application_get_pid(handle)));
}

void Application::GetSmallIcon(Local<String> property,
    const PropertyCallbackInfo<Value>& info) {

  NanScope();

  auto wrapper = ObjectWrap::Unwrap<Application>(info.Holder());
  auto handle = wrapper->GetHandle<FridaApplication>();

  info.GetReturnValue().Set(
      Icon::New(frida_application_get_small_icon(handle), wrapper->runtime_));
}

void Application::GetLargeIcon(Local<String> property,
    const PropertyCallbackInfo<Value>& info) {

  NanScope();

  auto wrapper = ObjectWrap::Unwrap<Application>(info.Holder());
  auto handle = wrapper->GetHandle<FridaApplication>();

  info.GetReturnValue().Set(
      Icon::New(frida_application_get_large_icon(handle), wrapper->runtime_));
}

}
