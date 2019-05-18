#include "icon.h"

#include <nan.h>
#include <node.h>

#define ICON_DATA_CONSTRUCTOR "icon:ctor"

using v8::AccessorSignature;
using v8::DEFAULT;
using v8::External;
using v8::Function;
using v8::Integer;
using v8::Isolate;
using v8::Local;
using v8::Object;
using v8::ReadOnly;
using v8::Value;

namespace frida {

Icon::Icon(FridaIcon* handle, Runtime* runtime)
    : GLibObject(handle, runtime) {
  g_object_ref(handle_);
}

Icon::~Icon() {
  g_object_unref(handle_);
}

void Icon::Init(Local<Object> exports, Runtime* runtime) {
  auto isolate = Isolate::GetCurrent();

  auto name = Nan::New("Icon").ToLocalChecked();
  auto tpl = CreateTemplate(name, New, runtime);

  auto instance_tpl = tpl->InstanceTemplate();
  auto data = Local<Value>();
  auto signature = AccessorSignature::New(isolate, tpl);
  Nan::SetAccessor(instance_tpl, Nan::New("pixels").ToLocalChecked(),
      GetPixels, 0, data, DEFAULT, ReadOnly, signature);
  Nan::SetAccessor(instance_tpl, Nan::New("rowstride").ToLocalChecked(),
      GetRowstride, 0, data, DEFAULT, ReadOnly, signature);
  Nan::SetAccessor(instance_tpl, Nan::New("height").ToLocalChecked(),
      GetHeight, 0, data, DEFAULT, ReadOnly, signature);
  Nan::SetAccessor(instance_tpl, Nan::New("width").ToLocalChecked(),
      GetWidth, 0, data, DEFAULT, ReadOnly, signature);

  auto ctor = Nan::GetFunction(tpl).ToLocalChecked();
  Nan::Set(exports, name, ctor);
  runtime->SetDataPointer(ICON_DATA_CONSTRUCTOR,
      new v8::Persistent<Function>(isolate, ctor));
}

Local<Value> Icon::New(gpointer handle, Runtime* runtime) {
  if (handle == NULL)
    return Nan::Null();

  auto ctor = Nan::New<Function>(
      *static_cast<v8::Persistent<Function>*>(
      runtime->GetDataPointer(ICON_DATA_CONSTRUCTOR)));
  const int argc = 1;
  Local<Value> argv[argc] = { Nan::New<v8::External>(handle) };
  return Nan::NewInstance(ctor, argc, argv).ToLocalChecked();
}

NAN_METHOD(Icon::New) {
  if (!info.IsConstructCall()) {
    Nan::ThrowError("Use the `new` keyword to create a new instance");
    return;
  }

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
}

NAN_PROPERTY_GETTER(Icon::GetWidth) {
  auto handle = ObjectWrap::Unwrap<Icon>(
      info.Holder())->GetHandle<FridaIcon>();

  info.GetReturnValue().Set(Nan::New<v8::Integer>(
    frida_icon_get_width(handle)));
}

NAN_PROPERTY_GETTER(Icon::GetHeight) {
  auto handle = ObjectWrap::Unwrap<Icon>(
      info.Holder())->GetHandle<FridaIcon>();

  info.GetReturnValue().Set(Nan::New<v8::Integer>(
    frida_icon_get_height(handle)));
}

NAN_PROPERTY_GETTER(Icon::GetRowstride) {
  auto handle = ObjectWrap::Unwrap<Icon>(
      info.Holder())->GetHandle<FridaIcon>();

  info.GetReturnValue().Set(Nan::New<v8::Integer>(
    frida_icon_get_rowstride(handle)));
}

static void icon_pixels_free(char* data, void* hint) {
  auto bytes = static_cast<GBytes*>(hint);
  g_bytes_unref(bytes);
}

NAN_PROPERTY_GETTER(Icon::GetPixels) {
  auto handle = ObjectWrap::Unwrap<Icon>(
      info.Holder())->GetHandle<FridaIcon>();

  auto bytes = frida_icon_get_pixels(handle);
  gsize size;
  auto data = g_bytes_get_data(bytes, &size);
  auto pixels = Nan::NewBuffer(static_cast<char*>(const_cast<void*>(data)),
      size, icon_pixels_free, g_bytes_ref(bytes)).ToLocalChecked();

  info.GetReturnValue().Set(pixels);
}

}
