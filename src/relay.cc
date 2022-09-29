#include "relay.h"

#define RELAY_DATA_TEMPLATE "relay:tpl"

using v8::DEFAULT;
using v8::Function;
using v8::FunctionTemplate;
using v8::Isolate;
using v8::Local;
using v8::Object;
using v8::Persistent;
using v8::ReadOnly;
using v8::Value;

namespace frida {

Relay::Relay(FridaRelay* handle, Runtime* runtime)
    : GLibObject(handle, runtime) {
  g_object_ref(handle_);
}

Relay::~Relay() {
  g_object_unref(handle_);
}

void Relay::Init(Local<Object> exports, Runtime* runtime) {
  auto isolate = Isolate::GetCurrent();

  auto name = Nan::New("Relay").ToLocalChecked();
  auto tpl = CreateTemplate(name, Relay::New, runtime);

  auto instance_tpl = tpl->InstanceTemplate();
  auto data = Local<Value>();
  Nan::SetAccessor(instance_tpl, Nan::New("kind").ToLocalChecked(),
      GetKind, 0, data, DEFAULT, ReadOnly);
  Nan::SetAccessor(instance_tpl, Nan::New("password").ToLocalChecked(),
      GetPassword, 0, data, DEFAULT, ReadOnly);
  Nan::SetAccessor(instance_tpl, Nan::New("username").ToLocalChecked(),
      GetUsername, 0, data, DEFAULT, ReadOnly);
  Nan::SetAccessor(instance_tpl, Nan::New("address").ToLocalChecked(),
      GetAddress, 0, data, DEFAULT, ReadOnly);

  auto ctor = Nan::GetFunction(tpl).ToLocalChecked();
  Nan::Set(exports, name, ctor);
  runtime->SetDataPointer(RELAY_DATA_TEMPLATE,
      new Persistent<FunctionTemplate>(isolate, tpl));
}

FridaRelay* Relay::TryParse(Local<Value> value, Runtime* runtime) {
  if (!value->IsObject())
    return NULL;

  auto impl = Nan::Get(value.As<Object>(), Nan::New("impl").ToLocalChecked())
      .ToLocalChecked();
  if (!HasInstance(impl, runtime))
    return NULL;

  return ObjectWrap::Unwrap<Relay>(impl.As<Object>())->GetHandle<FridaRelay>();
}

bool Relay::HasInstance(Local<Value> value, Runtime* runtime) {
  auto tpl = Nan::New<FunctionTemplate>(
      *static_cast<Persistent<FunctionTemplate>*>(
      runtime->GetDataPointer(RELAY_DATA_TEMPLATE)));
  return tpl->HasInstance(value);
}

NAN_METHOD(Relay::New) {
  if (!info.IsConstructCall()) {
    Nan::ThrowError("Use the `new` keyword to create a new instance");
    return;
  }

  if (info.Length() < 4) {
    Nan::ThrowTypeError("Missing one or more arguments");
    return;
  }

  auto address_value = info[0];
  auto username_value = info[1];
  auto password_value = info[2];
  if (!address_value->IsString() ||
      !username_value->IsString() ||
      !password_value->IsString()) {
    Nan::ThrowTypeError("Bad argument");
    return;
  }
  Nan::Utf8String address(address_value);
  Nan::Utf8String username(username_value);
  Nan::Utf8String password(password_value);

  FridaRelayKind kind;
  if (!Runtime::ValueToEnum(info[3], FRIDA_TYPE_RELAY_KIND, &kind))
    return;

  auto runtime = GetRuntimeFromConstructorArgs(info);

  auto handle = frida_relay_new(*address, *username, *password, kind);
  auto wrapper = new Relay(handle, runtime);
  g_object_unref(handle);
  auto obj = info.This();
  wrapper->Wrap(obj);

  info.GetReturnValue().Set(obj);
}

NAN_PROPERTY_GETTER(Relay::GetAddress) {
  auto handle = ObjectWrap::Unwrap<Relay>(
      info.Holder())->GetHandle<FridaRelay>();

  info.GetReturnValue().Set(
      Nan::New(frida_relay_get_address(handle)).ToLocalChecked());
}

NAN_PROPERTY_GETTER(Relay::GetUsername) {
  auto handle = ObjectWrap::Unwrap<Relay>(
      info.Holder())->GetHandle<FridaRelay>();

  info.GetReturnValue().Set(
      Nan::New(frida_relay_get_username(handle)).ToLocalChecked());
}

NAN_PROPERTY_GETTER(Relay::GetPassword) {
  auto handle = ObjectWrap::Unwrap<Relay>(
      info.Holder())->GetHandle<FridaRelay>();

  info.GetReturnValue().Set(
      Nan::New(frida_relay_get_password(handle)).ToLocalChecked());
}

NAN_PROPERTY_GETTER(Relay::GetKind) {
  auto handle = ObjectWrap::Unwrap<Relay>(
      info.Holder())->GetHandle<FridaRelay>();

  info.GetReturnValue().Set(Runtime::ValueFromEnum(
      frida_relay_get_kind(handle), FRIDA_TYPE_RELAY_KIND));
}

}
