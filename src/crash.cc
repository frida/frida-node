#include "crash.h"

#define CRASH_DATA_CONSTRUCTOR "crash:ctor"

using v8::DEFAULT;
using v8::External;
using v8::Function;
using v8::Integer;
using v8::Isolate;
using v8::Local;
using v8::Object;
using v8::Persistent;
using v8::ReadOnly;
using v8::Value;

namespace frida {

Crash::Crash(FridaCrash* handle, Runtime* runtime)
    : GLibObject(handle, runtime) {
  g_object_ref(handle_);
}

Crash::~Crash() {
  g_object_unref(handle_);
}

void Crash::Init(Local<Object> exports, Runtime* runtime) {
  auto isolate = Isolate::GetCurrent();

  auto name = Nan::New("Crash").ToLocalChecked();
  auto tpl = CreateTemplate(name, Crash::New, runtime);

  auto instance_tpl = tpl->InstanceTemplate();
  auto data = Local<Value>();
  Nan::SetAccessor(instance_tpl, Nan::New("parameters").ToLocalChecked(),
      GetParameters, 0, data, DEFAULT, ReadOnly);
  Nan::SetAccessor(instance_tpl, Nan::New("report").ToLocalChecked(),
      GetReport, 0, data, DEFAULT, ReadOnly);
  Nan::SetAccessor(instance_tpl, Nan::New("summary").ToLocalChecked(),
      GetSummary, 0, data, DEFAULT, ReadOnly);
  Nan::SetAccessor(instance_tpl, Nan::New("processName").ToLocalChecked(),
      GetProcessName, 0, data, DEFAULT, ReadOnly);
  Nan::SetAccessor(instance_tpl, Nan::New("pid").ToLocalChecked(),
      GetPid, 0, data, DEFAULT, ReadOnly);

  auto ctor = Nan::GetFunction(tpl).ToLocalChecked();
  Nan::Set(exports, name, ctor);
  runtime->SetDataPointer(CRASH_DATA_CONSTRUCTOR,
      new Persistent<Function>(isolate, ctor));
}

Local<Object> Crash::New(gpointer handle, Runtime* runtime) {
  auto ctor = Nan::New<Function>(
      *static_cast<Persistent<Function>*>(
      runtime->GetDataPointer(CRASH_DATA_CONSTRUCTOR)));
  const int argc = 1;
  Local<Value> argv[argc] = { Nan::New<External>(handle) };
  return Nan::NewInstance(ctor, argc, argv).ToLocalChecked();
}

NAN_METHOD(Crash::New) {
  if (!info.IsConstructCall()) {
    Nan::ThrowError("Use the `new` keyword to create a new instance");
    return;
  }

  if (info.Length() != 1 || !info[0]->IsExternal()) {
    Nan::ThrowTypeError("Bad argument, expected raw handle");
    return;
  }

  auto runtime = GetRuntimeFromConstructorArgs(info);

  auto handle = static_cast<FridaCrash*>(
      Local<External>::Cast(info[0])->Value());
  auto wrapper = new Crash(handle, runtime);
  auto obj = info.This();
  wrapper->Wrap(obj);

  info.GetReturnValue().Set(obj);
}

NAN_PROPERTY_GETTER(Crash::GetPid) {
  auto handle = ObjectWrap::Unwrap<Crash>(
      info.Holder())->GetHandle<FridaCrash>();

  info.GetReturnValue().Set(Nan::New<Integer>(frida_crash_get_pid(handle)));
}

NAN_PROPERTY_GETTER(Crash::GetProcessName) {
  auto handle = ObjectWrap::Unwrap<Crash>(
      info.Holder())->GetHandle<FridaCrash>();

  info.GetReturnValue().Set(
      Nan::New(frida_crash_get_process_name(handle)).ToLocalChecked());
}

NAN_PROPERTY_GETTER(Crash::GetSummary) {
  auto handle = ObjectWrap::Unwrap<Crash>(
      info.Holder())->GetHandle<FridaCrash>();

  info.GetReturnValue().Set(
      Nan::New(frida_crash_get_summary(handle)).ToLocalChecked());
}

NAN_PROPERTY_GETTER(Crash::GetReport) {
  auto handle = ObjectWrap::Unwrap<Crash>(
      info.Holder())->GetHandle<FridaCrash>();

  info.GetReturnValue().Set(
      Nan::New(frida_crash_get_report(handle)).ToLocalChecked());
}

NAN_PROPERTY_GETTER(Crash::GetParameters) {
  auto handle = ObjectWrap::Unwrap<Crash>(
      info.Holder())->GetHandle<FridaCrash>();

  GHashTable* parameters = frida_crash_get_parameters(handle);
  info.GetReturnValue().Set(Runtime::ValueFromParametersDict(parameters));
}

}
