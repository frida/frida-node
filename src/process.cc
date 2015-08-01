#include "process.h"

#include "icon.h"

#include <nan.h>

#define PROCESS_DATA_CONSTRUCTOR "process:ctor"

using v8::AccessorSignature;
using v8::DEFAULT;
using v8::Exception;
using v8::External;
using v8::Function;
using v8::Handle;
using v8::Integer;
using v8::Isolate;
using v8::Local;
using v8::Object;
using v8::Persistent;
using v8::ReadOnly;
using v8::String;
using v8::Value;
using Nan::HandleScope;

namespace frida {

Process::Process(FridaProcess* handle, Runtime* runtime)
    : GLibObject(handle, runtime) {
  g_object_ref(handle_);
}

Process::~Process() {
  g_object_unref(handle_);
}

void Process::Init(Handle<Object> exports, Runtime* runtime) {
  auto isolate = Isolate::GetCurrent();

  auto name = Nan::New("Process").ToLocalChecked();
  auto tpl = CreateTemplate(isolate, name, Process::New, runtime);

  auto instance_tpl = tpl->InstanceTemplate();
  auto data = Handle<Value>();
  auto signature = AccessorSignature::New(isolate, tpl);
  Nan::SetAccessor(instance_tpl, Nan::New("pid").ToLocalChecked(),
      GetPid, 0, data, DEFAULT, ReadOnly, signature);
  Nan::SetAccessor(instance_tpl, Nan::New("name").ToLocalChecked(),
      GetName, 0, data, DEFAULT, ReadOnly, signature);
  Nan::SetAccessor(instance_tpl, Nan::New("smallIcon").ToLocalChecked(),
      GetSmallIcon, 0, data, DEFAULT, ReadOnly, signature);
  Nan::SetAccessor(instance_tpl, Nan::New("largeIcon").ToLocalChecked(),
      GetLargeIcon, 0, data, DEFAULT, ReadOnly, signature);

  auto ctor = Nan::GetFunction(tpl).ToLocalChecked();
  Nan::Set(exports, name, ctor);
  runtime->SetDataPointer(PROCESS_DATA_CONSTRUCTOR,
      new v8::Persistent<Function>(isolate, ctor));
}

Local<Object> Process::New(gpointer handle, Runtime* runtime) {
  auto isolate = Isolate::GetCurrent();

  auto ctor = Local<Function>::New(isolate,
      *static_cast<v8::Persistent<Function>*>(
      runtime->GetDataPointer(PROCESS_DATA_CONSTRUCTOR)));
  const int argc = 1;
  Local<Value> argv[argc] = { External::New(isolate, handle) };
  return ctor->NewInstance(argc, argv);
}

void Process::New(const Nan::FunctionCallbackInfo<Value>& info) {
  HandleScope();

  if (info.IsConstructCall()) {
    if (info.Length() != 1 || !info[0]->IsExternal()) {
      Nan::ThrowTypeError("Bad argument, expected raw handle");
      return;
    }
    auto runtime = GetRuntimeFromConstructorArgs(info);

    auto handle = static_cast<FridaProcess*>(
        Local<External>::Cast(info[0])->Value());
    auto wrapper = new Process(handle, runtime);
    auto obj = info.This();
    wrapper->Wrap(obj);

    info.GetReturnValue().Set(obj);
  } else {
    info.GetReturnValue().Set(info.Callee()->NewInstance(0, NULL));
  }
}

void Process::GetPid(Local<String> property,
    const Nan::PropertyCallbackInfo<Value>& info) {
  HandleScope();

  auto isolate = info.GetIsolate();
  auto handle = ObjectWrap::Unwrap<Process>(
      info.Holder())->GetHandle<FridaProcess>();

  info.GetReturnValue().Set(
      Integer::New(isolate, frida_process_get_pid(handle)));
}

void Process::GetName(Local<String> property,
    const Nan::PropertyCallbackInfo<Value>& info) {
  HandleScope();

  auto handle = ObjectWrap::Unwrap<Process>(
      info.Holder())->GetHandle<FridaProcess>();

  info.GetReturnValue().Set(
      Nan::New(frida_process_get_name(handle)).ToLocalChecked());
}

void Process::GetSmallIcon(Local<String> property,
    const Nan::PropertyCallbackInfo<Value>& info) {
  HandleScope();

  auto wrapper = ObjectWrap::Unwrap<Process>(info.Holder());
  auto handle = wrapper->GetHandle<FridaProcess>();

  info.GetReturnValue().Set(
      Icon::New(frida_process_get_small_icon(handle), wrapper->runtime_));
}

void Process::GetLargeIcon(Local<String> property,
    const Nan::PropertyCallbackInfo<Value>& info) {
  HandleScope();

  auto wrapper = ObjectWrap::Unwrap<Process>(info.Holder());
  auto handle = wrapper->GetHandle<FridaProcess>();

  info.GetReturnValue().Set(
      Icon::New(frida_process_get_large_icon(handle), wrapper->runtime_));
}

}
