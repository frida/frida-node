#include "spawn.h"

#define SPAWN_DATA_CONSTRUCTOR "spawn:ctor"

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

Spawn::Spawn(FridaSpawn* handle, Runtime* runtime)
    : GLibObject(handle, runtime) {
  g_object_ref(handle_);
}

Spawn::~Spawn() {
  g_object_unref(handle_);
}

void Spawn::Init(Local<Object> exports, Runtime* runtime) {
  auto isolate = Isolate::GetCurrent();

  auto name = Nan::New("Spawn").ToLocalChecked();
  auto tpl = CreateTemplate(name, Spawn::New, runtime);

  auto instance_tpl = tpl->InstanceTemplate();
  auto data = Local<Value>();
  Nan::SetAccessor(instance_tpl, Nan::New("identifier").ToLocalChecked(),
      GetIdentifier, 0, data, DEFAULT, ReadOnly);
  Nan::SetAccessor(instance_tpl, Nan::New("pid").ToLocalChecked(),
      GetPid, 0, data, DEFAULT, ReadOnly);

  auto ctor = Nan::GetFunction(tpl).ToLocalChecked();
  Nan::Set(exports, name, ctor);
  runtime->SetDataPointer(SPAWN_DATA_CONSTRUCTOR,
      new Persistent<Function>(isolate, ctor));
}

Local<Object> Spawn::New(gpointer handle, Runtime* runtime) {
  auto ctor = Nan::New<Function>(
      *static_cast<Persistent<Function>*>(
      runtime->GetDataPointer(SPAWN_DATA_CONSTRUCTOR)));
  const int argc = 1;
  Local<Value> argv[argc] = { Nan::New<External>(handle) };
  return Nan::NewInstance(ctor, argc, argv).ToLocalChecked();
}

NAN_METHOD(Spawn::New) {
  if (!info.IsConstructCall()) {
    Nan::ThrowError("Use the `new` keyword to create a new instance");
    return;
  }

  if (info.Length() != 1 || !info[0]->IsExternal()) {
    Nan::ThrowTypeError("Bad argument, expected raw handle");
    return;
  }

  auto runtime = GetRuntimeFromConstructorArgs(info);

  auto handle = static_cast<FridaSpawn*>(
      Local<External>::Cast(info[0])->Value());
  auto wrapper = new Spawn(handle, runtime);
  auto obj = info.This();
  wrapper->Wrap(obj);

  info.GetReturnValue().Set(obj);
}

NAN_PROPERTY_GETTER(Spawn::GetPid) {
  auto handle = ObjectWrap::Unwrap<Spawn>(
      info.Holder())->GetHandle<FridaSpawn>();

  info.GetReturnValue().Set(Nan::New<Integer>(frida_spawn_get_pid(handle)));
}

NAN_PROPERTY_GETTER(Spawn::GetIdentifier) {
  auto handle = ObjectWrap::Unwrap<Spawn>(
      info.Holder())->GetHandle<FridaSpawn>();

  auto identifier = frida_spawn_get_identifier(handle);
  if (identifier != NULL)
    info.GetReturnValue().Set(Nan::New(identifier).ToLocalChecked());
  else
    info.GetReturnValue().Set(Nan::Null());
}

}
