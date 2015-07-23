#include "process.h"

#include "icon.h"

#include <nan.h>

#define PROCESS_DATA_CONSTRUCTOR "process:ctor"

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

Process::Process(FridaProcess* handle, Runtime* runtime)
    : GLibObject(handle, runtime) {
  g_object_ref(handle_);
}

Process::~Process() {
  g_object_unref(handle_);
}

void Process::Init(Handle<Object> exports, Runtime* runtime) {
  auto isolate = Isolate::GetCurrent();

  auto name = NanNew("Process");
  auto tpl = CreateTemplate(isolate, name, New, runtime);

  auto instance_tpl = tpl->InstanceTemplate();
  auto data = Handle<Value>();
  auto signature = AccessorSignature::New(isolate, tpl);
  instance_tpl->SetAccessor(NanNew("pid"),
      GetPid, 0, data, DEFAULT, ReadOnly, signature);
  instance_tpl->SetAccessor(NanNew("name"),
      GetName, 0, data, DEFAULT, ReadOnly, signature);
  instance_tpl->SetAccessor(NanNew("smallIcon"),
      GetSmallIcon, 0, data, DEFAULT, ReadOnly, signature);
  instance_tpl->SetAccessor(NanNew("largeIcon"),
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
  NanScope();

  if (args.IsConstructCall()) {
    if (args.Length() != 1 || !args[0]->IsExternal()) {
      NanThrowTypeError("Bad argument, expected raw handle");
      NanReturnUndefined();
    }
    auto runtime = GetRuntimeFromConstructorArgs(args);

    auto handle = static_cast<FridaProcess*>(
        Local<External>::Cast(args[0])->Value());
    auto wrapper = new Process(handle, runtime);
    auto obj = args.This();
    wrapper->Wrap(obj);

    NanReturnValue(obj);
  } else {
    NanReturnValue(args.Callee()->NewInstance(0, NULL));
  }
}

void Process::GetPid(Local<String> property,
    const PropertyCallbackInfo<Value>& args) {
  NanScope();

  auto isolate = args.GetIsolate();
  auto handle = ObjectWrap::Unwrap<Process>(
      args.Holder())->GetHandle<FridaProcess>();

  NanReturnValue(
      Integer::New(isolate, frida_process_get_pid(handle)));
}

void Process::GetName(Local<String> property,
    const PropertyCallbackInfo<Value>& args) {
  NanScope();

  auto handle = ObjectWrap::Unwrap<Process>(
      args.Holder())->GetHandle<FridaProcess>();

  NanReturnValue(
      NanNew(frida_process_get_name(handle)));
}

void Process::GetSmallIcon(Local<String> property,
    const PropertyCallbackInfo<Value>& args) {
  NanScope();

  auto wrapper = ObjectWrap::Unwrap<Process>(args.Holder());
  auto handle = wrapper->GetHandle<FridaProcess>();

  NanReturnValue(
      Icon::New(frida_process_get_small_icon(handle), wrapper->runtime_));
}

void Process::GetLargeIcon(Local<String> property,
    const PropertyCallbackInfo<Value>& args) {
  NanScope();

  auto wrapper = ObjectWrap::Unwrap<Process>(args.Holder());
  auto handle = wrapper->GetHandle<FridaProcess>();

  NanReturnValue(
      Icon::New(frida_process_get_large_icon(handle), wrapper->runtime_));
}

}
