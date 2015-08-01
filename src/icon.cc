#include "icon.h"

#include <nan.h>
#include <node.h>

#define ICON_DATA_CONSTRUCTOR "icon:ctor"

using v8::AccessorSignature;
using v8::DEFAULT;
using v8::DontEnum;
using v8::Exception;
using v8::External;
using v8::Function;
using v8::Handle;
using v8::Integer;
using v8::Isolate;
using v8::Local;
using v8::Object;
using v8::Persistent;
using v8::PropertyAttribute;
using v8::ReadOnly;
using v8::String;
using v8::Value;
using Nan::HandleScope;

namespace frida {

Icon::Icon(FridaIcon* handle, Runtime* runtime)
    : GLibObject(handle, runtime) {
  g_object_ref(handle_);
}

Icon::~Icon() {
  g_object_unref(handle_);
}

void Icon::Init(Handle<Object> exports, Runtime* runtime) {
  auto isolate = Isolate::GetCurrent();

  auto name = Nan::New("Icon").ToLocalChecked();
  auto tpl = CreateTemplate(isolate, name, New, runtime);

  auto instance_tpl = tpl->InstanceTemplate();
  auto data = Handle<Value>();
  auto signature = AccessorSignature::New(isolate, tpl);
  Nan::SetAccessor(instance_tpl, Nan::New("width").ToLocalChecked(),
      GetWidth, 0, data, DEFAULT, ReadOnly, signature);
  Nan::SetAccessor(instance_tpl, Nan::New("height").ToLocalChecked(),
      GetHeight, 0, data, DEFAULT, ReadOnly, signature);
  Nan::SetAccessor(instance_tpl, Nan::New("rowstride").ToLocalChecked(),
      GetRowstride, 0, data, DEFAULT, ReadOnly, signature);
  Nan::SetAccessor(instance_tpl, Nan::New("pixels").ToLocalChecked(),
      GetPixels, 0, data, DEFAULT, ReadOnly, signature);

  auto ctor = Nan::GetFunction(tpl).ToLocalChecked();
  Nan::Set(exports, name, ctor);
  runtime->SetDataPointer(ICON_DATA_CONSTRUCTOR,
      new v8::Persistent<Function>(isolate, ctor));
}

Local<Value> Icon::New(gpointer handle, Runtime* runtime) {
  auto isolate = Isolate::GetCurrent();

  if (handle == NULL)
    return Null(isolate);

  auto ctor = Local<Function>::New(isolate,
      *static_cast<v8::Persistent<Function>*>(
      runtime->GetDataPointer(ICON_DATA_CONSTRUCTOR)));
  const int argc = 1;
  Local<Value> argv[argc] = { External::New(isolate, handle) };
  return ctor->NewInstance(argc, argv);
}

void Icon::New(const Nan::FunctionCallbackInfo<Value>& info) {
  HandleScope();

  if (info.IsConstructCall()) {
    if (info.Length() != 1 || !info[0]->IsExternal()) {
      Nan::ThrowTypeError("Bad argument, expected raw handle");
      return;
    }
    auto runtime = GetRuntimeFromConstructorArgs(info);

    auto handle = static_cast<FridaIcon*>(
        Local<External>::Cast(info[0])->Value());
    auto wrapper = new Icon(handle, runtime);
    auto obj = info.This();
    wrapper->Wrap(obj);

    info.GetReturnValue().Set(obj);
  } else {
    info.GetReturnValue().Set(info.Callee()->NewInstance(0, NULL));
  }
}

void Icon::GetWidth(Local<String> property,
    const Nan::PropertyCallbackInfo<Value>& info) {
  HandleScope();

  auto isolate = info.GetIsolate();
  auto handle = ObjectWrap::Unwrap<Icon>(
      info.Holder())->GetHandle<FridaIcon>();

  info.GetReturnValue().Set(
      Integer::New(isolate, frida_icon_get_width(handle)));
}

void Icon::GetHeight(Local<String> property,
    const Nan::PropertyCallbackInfo<Value>& info) {
  HandleScope();

  auto isolate = info.GetIsolate();
  auto handle = ObjectWrap::Unwrap<Icon>(
      info.Holder())->GetHandle<FridaIcon>();

  info.GetReturnValue().Set(
      Integer::New(isolate, frida_icon_get_height(handle)));
}

void Icon::GetRowstride(Local<String> property,
    const Nan::PropertyCallbackInfo<Value>& info) {
  HandleScope();

  auto isolate = info.GetIsolate();
  auto handle = ObjectWrap::Unwrap<Icon>(
      info.Holder())->GetHandle<FridaIcon>();

  info.GetReturnValue().Set(
      Integer::New(isolate, frida_icon_get_rowstride(handle)));
}

void Icon::GetPixels(Local<String> property,
    const Nan::PropertyCallbackInfo<Value>& info) {
  HandleScope();

  auto handle = ObjectWrap::Unwrap<Icon>(
      info.Holder())->GetHandle<FridaIcon>();

  int len;
  auto buf = frida_icon_get_pixels(handle, &len);
  auto pixels = Nan::NewBuffer(reinterpret_cast<char*>(buf), len).ToLocalChecked();

  info.GetReturnValue().Set(pixels);
}

}
