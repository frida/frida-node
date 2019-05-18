#include "process.h"

#include "icon.h"

#include <nan.h>

#define PROCESS_DATA_CONSTRUCTOR "process:ctor"

using v8::AccessorSignature;
using v8::DEFAULT;
using v8::External;
using v8::Function;
using v8::Isolate;
using v8::Local;
using v8::Object;
using v8::ReadOnly;
using v8::Value;

namespace frida {

Process::Process(FridaProcess* handle, Runtime* runtime)
    : GLibObject(handle, runtime) {
  g_object_ref(handle_);
}

Process::~Process() {
  g_object_unref(handle_);
}

void Process::Init(Local<Object> exports, Runtime* runtime) {
  auto isolate = Isolate::GetCurrent();

  auto name = Nan::New("Process").ToLocalChecked();
  auto tpl = CreateTemplate(name, Process::New, runtime);

  auto instance_tpl = tpl->InstanceTemplate();
  auto data = Local<Value>();
  auto signature = AccessorSignature::New(isolate, tpl);
  Nan::SetAccessor(instance_tpl, Nan::New("largeIcon").ToLocalChecked(),
      GetLargeIcon, 0, data, DEFAULT, ReadOnly, signature);
  Nan::SetAccessor(instance_tpl, Nan::New("smallIcon").ToLocalChecked(),
      GetSmallIcon, 0, data, DEFAULT, ReadOnly, signature);
  Nan::SetAccessor(instance_tpl, Nan::New("name").ToLocalChecked(),
      GetName, 0, data, DEFAULT, ReadOnly, signature);
  Nan::SetAccessor(instance_tpl, Nan::New("pid").ToLocalChecked(),
      GetPid, 0, data, DEFAULT, ReadOnly, signature);

  auto ctor = Nan::GetFunction(tpl).ToLocalChecked();
  Nan::Set(exports, name, ctor);
  runtime->SetDataPointer(PROCESS_DATA_CONSTRUCTOR,
      new v8::Persistent<Function>(isolate, ctor));
}

Local<Object> Process::New(gpointer handle, Runtime* runtime) {
  auto ctor = Nan::New<Function>(
      *static_cast<v8::Persistent<Function>*>(
      runtime->GetDataPointer(PROCESS_DATA_CONSTRUCTOR)));
  const int argc = 1;
  Local<Value> argv[argc] = { Nan::New<v8::External>(handle) };
  return Nan::NewInstance(ctor, argc, argv).ToLocalChecked();
}

NAN_METHOD(Process::New) {
  if (!info.IsConstructCall()) {
    Nan::ThrowError("Use the `new` keyword to create a new instance");
    return;
  }

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
}

NAN_PROPERTY_GETTER(Process::GetPid) {
  auto handle = ObjectWrap::Unwrap<Process>(
      info.Holder())->GetHandle<FridaProcess>();

  info.GetReturnValue().Set(Nan::New<v8::Integer>(
      frida_process_get_pid(handle)));
}

NAN_PROPERTY_GETTER(Process::GetName) {
  auto handle = ObjectWrap::Unwrap<Process>(
      info.Holder())->GetHandle<FridaProcess>();

  info.GetReturnValue().Set(
      Nan::New(frida_process_get_name(handle)).ToLocalChecked());
}

NAN_PROPERTY_GETTER(Process::GetSmallIcon) {
  auto wrapper = ObjectWrap::Unwrap<Process>(info.Holder());
  auto handle = wrapper->GetHandle<FridaProcess>();

  info.GetReturnValue().Set(
      Icon::New(frida_process_get_small_icon(handle), wrapper->runtime_));
}

NAN_PROPERTY_GETTER(Process::GetLargeIcon) {
  auto wrapper = ObjectWrap::Unwrap<Process>(info.Holder());
  auto handle = wrapper->GetHandle<FridaProcess>();

  info.GetReturnValue().Set(
      Icon::New(frida_process_get_large_icon(handle), wrapper->runtime_));
}

}
