#include "application.h"

#include <cstring>

#define APPLICATION_DATA_CONSTRUCTOR "application:ctor"

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
  Nan::SetAccessor(instance_tpl, Nan::New("parameters").ToLocalChecked(),
      GetParameters, 0, data, DEFAULT, ReadOnly);
  Nan::SetAccessor(instance_tpl, Nan::New("pid").ToLocalChecked(),
      GetPid, 0, data, DEFAULT, ReadOnly);
  Nan::SetAccessor(instance_tpl, Nan::New("name").ToLocalChecked(),
      GetName, 0, data, DEFAULT, ReadOnly);
  Nan::SetAccessor(instance_tpl, Nan::New("identifier").ToLocalChecked(),
      GetIdentifier, 0, data, DEFAULT, ReadOnly);

  auto ctor = Nan::GetFunction(tpl).ToLocalChecked();
  Nan::Set(exports, name, ctor);
  runtime->SetDataPointer(APPLICATION_DATA_CONSTRUCTOR,
      new Persistent<Function>(isolate, ctor));
}

Local<Object> Application::New(gpointer handle, Runtime* runtime) {
  auto ctor = Nan::New<Function>(
    *static_cast<Persistent<Function>*>(
      runtime->GetDataPointer(APPLICATION_DATA_CONSTRUCTOR)));

  const int argc = 1;
  Local<Value> argv[argc] = { Nan::New<External>(handle) };
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

NAN_PROPERTY_GETTER(Application::GetParameters) {
  auto wrapper = ObjectWrap::Unwrap<Application>(info.Holder());
  auto handle = wrapper->GetHandle<FridaApplication>();

  GHashTable* parameters = frida_application_get_parameters(handle);
  info.GetReturnValue().Set(ParseParameters(parameters));
}

Local<Value> Application::ParseParameters(GHashTable* dict) {
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
