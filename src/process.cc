#include "process.h"

#include "icon.h"

#define PROCESS_DATA_CONSTRUCTOR "process:ctor"

using v8::AccessorSignature;
using v8::DEFAULT;
using v8::Exception;
using v8::External;
using v8::Function;
using v8::FunctionCallbackInfo;
using v8::Handle;
using v8::HandleScope;
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

Process::Process(FridaProcess* handle, Runtime* runtime)
    : GLibObject(handle, runtime) {
}

Process::~Process() {
  g_object_unref(handle_);
}

void Process::Init(Handle<Object> exports, Runtime* runtime) {
  auto isolate = Isolate::GetCurrent();

  auto name = String::NewFromUtf8(isolate, "Process");
  auto tpl = CreateTemplate(isolate, name, New, runtime);

  auto instance_tpl = tpl->InstanceTemplate();
  auto data = Handle<Value>();
  auto signature = AccessorSignature::New(isolate, tpl);
  instance_tpl->SetAccessor(String::NewFromUtf8(isolate, "pid"),
      GetPid, 0, data, DEFAULT, ReadOnly, signature);
  instance_tpl->SetAccessor(String::NewFromUtf8(isolate, "name"),
      GetName, 0, data, DEFAULT, ReadOnly, signature);
  instance_tpl->SetAccessor(String::NewFromUtf8(isolate, "smallIcon"),
      GetSmallIcon, 0, data, DEFAULT, ReadOnly, signature);
  instance_tpl->SetAccessor(String::NewFromUtf8(isolate, "largeIcon"),
      GetLargeIcon, 0, data, DEFAULT, ReadOnly, signature);

  auto ctor = tpl->GetFunction();
  exports->Set(name, ctor);
  runtime->SetDataPointer(PROCESS_DATA_CONSTRUCTOR,
      new Persistent<Function>(isolate, ctor));
}

Local<Object> Process::New(gpointer handle, Runtime* runtime) {
  auto isolate = Isolate::GetCurrent();

  auto ctor = Local<Function>::New(isolate,
      *static_cast<Persistent<Function>*>(
      runtime->GetDataPointer(PROCESS_DATA_CONSTRUCTOR)));
  const int argc = 1;
  Local<Value> argv[argc] = { External::New(isolate, handle) };
  return ctor->NewInstance(argc, argv);
}

void Process::New(const FunctionCallbackInfo<Value>& args) {
  auto isolate = args.GetIsolate();
  HandleScope scope(isolate);

  if (args.IsConstructCall()) {
    if (args.Length() != 1 || !args[0]->IsExternal()) {
      isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate,
          "Bad argument, expected raw handle")));
      return;
    }
    auto runtime = GetRuntimeFromConstructorArgs(args);
    auto wrapper = new Process(static_cast<FridaProcess*>(
        Local<External>::Cast(args[0])->Value()), runtime);
    auto obj = args.This();
    wrapper->Wrap(obj);
    args.GetReturnValue().Set(obj);
  } else {
    args.GetReturnValue().Set(args.Callee()->NewInstance(0, NULL));
  }
}

void Process::GetPid(Local<String> property,
    const PropertyCallbackInfo<Value>& info) {
  auto isolate = info.GetIsolate();
  HandleScope scope(isolate);
  auto handle = ObjectWrap::Unwrap<Process>(
      info.Holder())->GetHandle<FridaProcess>();

  info.GetReturnValue().Set(
      Integer::New(isolate, frida_process_get_pid(handle)));
}

void Process::GetName(Local<String> property,
    const PropertyCallbackInfo<Value>& info) {
  auto isolate = info.GetIsolate();
  HandleScope scope(isolate);
  auto handle = ObjectWrap::Unwrap<Process>(
      info.Holder())->GetHandle<FridaProcess>();

  info.GetReturnValue().Set(
      String::NewFromUtf8(isolate, frida_process_get_name(handle)));
}

void Process::GetSmallIcon(Local<String> property,
    const PropertyCallbackInfo<Value>& info) {
  auto isolate = info.GetIsolate();
  HandleScope scope(isolate);
  auto wrapper = ObjectWrap::Unwrap<Process>(info.Holder());
  auto handle = wrapper->GetHandle<FridaProcess>();

  info.GetReturnValue().Set(
      Icon::New(frida_process_get_small_icon(handle), wrapper->runtime_));
}

void Process::GetLargeIcon(Local<String> property,
    const PropertyCallbackInfo<Value>& info) {
  auto isolate = info.GetIsolate();
  HandleScope scope(isolate);
  auto wrapper = ObjectWrap::Unwrap<Process>(info.Holder());
  auto handle = wrapper->GetHandle<FridaProcess>();

  info.GetReturnValue().Set(
      Icon::New(frida_process_get_large_icon(handle), wrapper->runtime_));
}

}
