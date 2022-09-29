#include "process.h"

#include <cstring>

#define PROCESS_DATA_CONSTRUCTOR "process:ctor"

using std::strcmp;
using v8::DEFAULT;
using v8::External;
using v8::Function;
using v8::Integer;
using v8::Isolate;
using v8::Local;
using v8::Object;
using v8::Persistent;
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

void Process::Init(Local<Object> exports, Runtime* runtime) {
  auto isolate = Isolate::GetCurrent();

  auto name = Nan::New("Process").ToLocalChecked();
  auto tpl = CreateTemplate(name, Process::New, runtime);

  auto instance_tpl = tpl->InstanceTemplate();
  auto data = Local<Value>();
  Nan::SetAccessor(instance_tpl, Nan::New("parameters").ToLocalChecked(),
      GetParameters, 0, data, DEFAULT, ReadOnly);
  Nan::SetAccessor(instance_tpl, Nan::New("name").ToLocalChecked(),
      GetName, 0, data, DEFAULT, ReadOnly);
  Nan::SetAccessor(instance_tpl, Nan::New("pid").ToLocalChecked(),
      GetPid, 0, data, DEFAULT, ReadOnly);

  auto ctor = Nan::GetFunction(tpl).ToLocalChecked();
  Nan::Set(exports, name, ctor);
  runtime->SetDataPointer(PROCESS_DATA_CONSTRUCTOR,
      new Persistent<Function>(isolate, ctor));
}

Local<Object> Process::New(gpointer handle, Runtime* runtime) {
  auto ctor = Nan::New<Function>(
      *static_cast<Persistent<Function>*>(
      runtime->GetDataPointer(PROCESS_DATA_CONSTRUCTOR)));
  const int argc = 1;
  Local<Value> argv[argc] = { Nan::New<External>(handle) };
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

  info.GetReturnValue().Set(Nan::New<Integer>(frida_process_get_pid(handle)));
}

NAN_PROPERTY_GETTER(Process::GetName) {
  auto handle = ObjectWrap::Unwrap<Process>(
      info.Holder())->GetHandle<FridaProcess>();

  info.GetReturnValue().Set(
      Nan::New(frida_process_get_name(handle)).ToLocalChecked());
}

NAN_PROPERTY_GETTER(Process::GetParameters) {
  auto wrapper = ObjectWrap::Unwrap<Process>(info.Holder());
  auto handle = wrapper->GetHandle<FridaProcess>();

  GHashTable* parameters = frida_process_get_parameters(handle);
  info.GetReturnValue().Set(ParseParameters(parameters));
}

Local<Value> Process::ParseParameters(GHashTable* dict) {
  auto result = Nan::New<Object>();

  GHashTableIter iter;
  gpointer raw_key, raw_value;

  g_hash_table_iter_init(&iter, dict);

  while (g_hash_table_iter_next(&iter, &raw_key, &raw_value)) {
    char* canonicalized_key =
        Runtime::ParameterNameFromC(static_cast<char*>(raw_key));
    GVariant* var_value = static_cast<GVariant*>(raw_value);

    Local<String> key = Nan::New(canonicalized_key).ToLocalChecked();
    Local<Value> value;
    if (strcmp(canonicalized_key, "started") == 0 &&
        g_variant_is_of_type(var_value, G_VARIANT_TYPE_STRING)) {
      value = Runtime::ValueFromDatetime(g_variant_get_string(var_value, NULL));
    } else {
      value = Runtime::ValueFromVariant(var_value);
    }
    Nan::Set(result, key, value);

    g_free(canonicalized_key);
  }

  return result;
}

}
