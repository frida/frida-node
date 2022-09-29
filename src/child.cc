#include "child.h"

#define CHILD_DATA_CONSTRUCTOR "child:ctor"

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

Child::Child(FridaChild* handle, Runtime* runtime)
    : GLibObject(handle, runtime) {
  g_object_ref(handle_);
}

Child::~Child() {
  g_object_unref(handle_);
}

void Child::Init(Local<Object> exports, Runtime* runtime) {
  auto isolate = Isolate::GetCurrent();

  auto name = Nan::New("Child").ToLocalChecked();
  auto tpl = CreateTemplate(name, Child::New, runtime);

  auto instance_tpl = tpl->InstanceTemplate();
  auto data = Local<Value>();
  Nan::SetAccessor(instance_tpl, Nan::New("envp").ToLocalChecked(),
      GetEnvp, 0, data, DEFAULT, ReadOnly);
  Nan::SetAccessor(instance_tpl, Nan::New("argv").ToLocalChecked(),
      GetArgv, 0, data, DEFAULT, ReadOnly);
  Nan::SetAccessor(instance_tpl, Nan::New("path").ToLocalChecked(),
      GetPath, 0, data, DEFAULT, ReadOnly);
  Nan::SetAccessor(instance_tpl, Nan::New("identifier").ToLocalChecked(),
      GetIdentifier, 0, data, DEFAULT, ReadOnly);
  Nan::SetAccessor(instance_tpl, Nan::New("origin").ToLocalChecked(),
      GetOrigin, 0, data, DEFAULT, ReadOnly);
  Nan::SetAccessor(instance_tpl, Nan::New("parentPid").ToLocalChecked(),
      GetParentPid, 0, data, DEFAULT, ReadOnly);
  Nan::SetAccessor(instance_tpl, Nan::New("pid").ToLocalChecked(),
      GetPid, 0, data, DEFAULT, ReadOnly);

  auto ctor = Nan::GetFunction(tpl).ToLocalChecked();
  Nan::Set(exports, name, ctor);
  runtime->SetDataPointer(CHILD_DATA_CONSTRUCTOR,
      new Persistent<Function>(isolate, ctor));
}

Local<Object> Child::New(gpointer handle, Runtime* runtime) {
  auto ctor = Nan::New<Function>(
      *static_cast<Persistent<Function>*>(
      runtime->GetDataPointer(CHILD_DATA_CONSTRUCTOR)));
  const int argc = 1;
  Local<Value> argv[argc] = { Nan::New<External>(handle) };
  return Nan::NewInstance(ctor, argc, argv).ToLocalChecked();
}

NAN_METHOD(Child::New) {
  if (!info.IsConstructCall()) {
    Nan::ThrowError("Use the `new` keyword to create a new instance");
    return;
  }

  if (info.Length() != 1 || !info[0]->IsExternal()) {
    Nan::ThrowTypeError("Bad argument, expected raw handle");
    return;
  }

  auto runtime = GetRuntimeFromConstructorArgs(info);

  auto handle = static_cast<FridaChild*>(
      Local<External>::Cast(info[0])->Value());
  auto wrapper = new Child(handle, runtime);
  auto obj = info.This();
  wrapper->Wrap(obj);

  info.GetReturnValue().Set(obj);
}

NAN_PROPERTY_GETTER(Child::GetPid) {
  auto handle = ObjectWrap::Unwrap<Child>(
      info.Holder())->GetHandle<FridaChild>();

  info.GetReturnValue().Set(Nan::New<Integer>(frida_child_get_pid(handle)));
}

NAN_PROPERTY_GETTER(Child::GetParentPid) {
  auto handle = ObjectWrap::Unwrap<Child>(
      info.Holder())->GetHandle<FridaChild>();

  info.GetReturnValue().Set(
      Nan::New<Integer>(frida_child_get_parent_pid(handle)));
}

NAN_PROPERTY_GETTER(Child::GetOrigin) {
  auto handle = ObjectWrap::Unwrap<Child>(
      info.Holder())->GetHandle<FridaChild>();

  info.GetReturnValue().Set(Runtime::ValueFromEnum(
      frida_child_get_origin(handle), FRIDA_TYPE_CHILD_ORIGIN));
}

NAN_PROPERTY_GETTER(Child::GetIdentifier) {
  auto handle = ObjectWrap::Unwrap<Child>(
      info.Holder())->GetHandle<FridaChild>();

  auto identifier = frida_child_get_identifier(handle);
  if (identifier != NULL)
    info.GetReturnValue().Set(Nan::New(identifier).ToLocalChecked());
  else
    info.GetReturnValue().Set(Nan::Null());
}

NAN_PROPERTY_GETTER(Child::GetPath) {
  auto handle = ObjectWrap::Unwrap<Child>(
      info.Holder())->GetHandle<FridaChild>();

  auto path = frida_child_get_path(handle);
  if (path != NULL)
    info.GetReturnValue().Set(Nan::New(path).ToLocalChecked());
  else
    info.GetReturnValue().Set(Nan::Null());
}

NAN_PROPERTY_GETTER(Child::GetArgv) {
  auto handle = ObjectWrap::Unwrap<Child>(
      info.Holder())->GetHandle<FridaChild>();

  gint length;
  auto argv = frida_child_get_argv(handle, &length);
  info.GetReturnValue().Set(Runtime::ValueFromStrv(argv, length));
}

NAN_PROPERTY_GETTER(Child::GetEnvp) {
  auto handle = ObjectWrap::Unwrap<Child>(
      info.Holder())->GetHandle<FridaChild>();

  gint length;
  auto envp = frida_child_get_envp(handle, &length);
  info.GetReturnValue().Set(Runtime::ValueFromEnvp(envp, length));
}

}
