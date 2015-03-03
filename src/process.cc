#include "process.h"

using v8::AccessorSignature;
using v8::DEFAULT;
using v8::Exception;
using v8::External;
using v8::Function;
using v8::FunctionCallbackInfo;
using v8::FunctionTemplate;
using v8::Handle;
using v8::HandleScope;
using v8::Integer;
using v8::Isolate;
using v8::Local;
using v8::None;
using v8::Object;
using v8::Persistent;
using v8::PropertyCallbackInfo;
using v8::String;
using v8::Value;

namespace frida {

Persistent<Function> Process::constructor_;

Process::Process(FridaProcess* handle) : handle_(handle) {
}

Process::~Process() {
  g_object_unref(handle_);
}

void Process::Init(Handle<Object> exports) {
  auto isolate = Isolate::GetCurrent();

  auto tpl = FunctionTemplate::New(isolate, New);
  tpl->SetClassName(String::NewFromUtf8(isolate, "Process"));
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  auto instance_tpl = tpl->InstanceTemplate();
  auto data = Handle<Value>();
  auto signature = AccessorSignature::New(isolate, tpl);
  instance_tpl->SetAccessor(String::NewFromUtf8(isolate, "pid"), GetPid, 0,
      data, DEFAULT, None, signature);
  instance_tpl->SetAccessor(String::NewFromUtf8(isolate, "name"), GetName, 0,
      data, DEFAULT, None, signature);

  exports->Set(String::NewFromUtf8(isolate, "Process"), tpl->GetFunction());

  constructor_.Reset(isolate, tpl->GetFunction());
}

Local<Object> Process::Create(gpointer handle) {
  auto isolate = Isolate::GetCurrent();

  auto constructor = Local<Function>::New(isolate, constructor_);
  const int argc = 1;
  Local<Value> argv[argc] = { External::New(isolate, handle) };
  return constructor->NewInstance(argc, argv);
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
    auto wrapper = new Process(static_cast<FridaProcess*>(
        Local<External>::Cast(args[0])->Value()));
    auto obj = args.This();
    wrapper->Wrap(obj);
    args.GetReturnValue().Set(obj);
  } else {
    auto constructor = Local<Function>::New(isolate, constructor_);
    args.GetReturnValue().Set(constructor->NewInstance(0, NULL));
  }
}

void Process::GetPid(Local<String> property,
    const PropertyCallbackInfo<Value>& info) {
  auto isolate = info.GetIsolate();
  HandleScope scope(isolate);
  auto handle = ObjectWrap::Unwrap<Process>(info.Holder())->handle_;

  info.GetReturnValue().Set(
      Integer::New(isolate, frida_process_get_pid(handle)));
}

void Process::GetName(Local<String> property,
    const PropertyCallbackInfo<Value>& info) {
  auto isolate = info.GetIsolate();
  HandleScope scope(isolate);
  auto handle = ObjectWrap::Unwrap<Process>(info.Holder())->handle_;

  info.GetReturnValue().Set(
      String::NewFromUtf8(isolate, frida_process_get_name(handle)));
}

}
