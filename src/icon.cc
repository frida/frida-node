#include "icon.h"

#include <node.h>
#include <nan.h>

#define ICON_DATA_CONSTRUCTOR "icon:ctor"

using v8::AccessorSignature;
using v8::DEFAULT;
using v8::DontEnum;
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
using v8::PropertyAttribute;
using v8::PropertyCallbackInfo;
using v8::ReadOnly;
using v8::String;
using v8::Value;

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

  auto name = NanNew("Icon");
  auto tpl = CreateTemplate(isolate, name, New, runtime);

  auto instance_tpl = tpl->InstanceTemplate();
  auto data = Handle<Value>();
  auto signature = AccessorSignature::New(isolate, tpl);
  instance_tpl->SetAccessor(NanNew("width"),
      GetWidth, 0, data, DEFAULT, ReadOnly, signature);
  instance_tpl->SetAccessor(NanNew("height"),
      GetHeight, 0, data, DEFAULT, ReadOnly, signature);
  instance_tpl->SetAccessor(NanNew("rowstride"),
      GetRowstride, 0, data, DEFAULT, ReadOnly, signature);
  instance_tpl->SetAccessor(NanNew("pixels"),
      GetPixels, 0, data, DEFAULT, ReadOnly, signature);

  auto ctor = tpl->GetFunction();
  exports->Set(name, ctor);
  runtime->SetDataPointer(ICON_DATA_CONSTRUCTOR,
      new Persistent<Function>(isolate, ctor));
}

Local<Value> Icon::New(gpointer handle, Runtime* runtime) {
  auto isolate = Isolate::GetCurrent();

  if (handle == NULL)
    return Null(isolate);

  auto ctor = Local<Function>::New(isolate,
      *static_cast<Persistent<Function>*>(
      runtime->GetDataPointer(ICON_DATA_CONSTRUCTOR)));
  const int argc = 1;
  Local<Value> argv[argc] = { External::New(isolate, handle) };
  return ctor->NewInstance(argc, argv);
}

void Icon::New(const FunctionCallbackInfo<Value>& args) {

  NanScope();

  if (args.IsConstructCall()) {
    if (args.Length() != 1 || !args[0]->IsExternal()) {
      NanThrowTypeError("Bad argument, expected raw handle");
      NanReturnUndefined();
    }
    auto runtime = GetRuntimeFromConstructorArgs(args);

    auto handle = static_cast<FridaIcon*>(
        Local<External>::Cast(args[0])->Value());
    auto wrapper = new Icon(handle, runtime);
    auto obj = args.This();
    wrapper->Wrap(obj);

    NanReturnValue(obj);
  } else {
    NanReturnValue(args.Callee()->NewInstance(0, NULL));
  }
}

void Icon::GetWidth(Local<String> property,
    const PropertyCallbackInfo<Value>& args) {

  NanScope();

  auto isolate = args.GetIsolate();
  auto handle = ObjectWrap::Unwrap<Icon>(
      args.Holder())->GetHandle<FridaIcon>();

  NanReturnValue(
      Integer::New(isolate, frida_icon_get_width(handle)));
}

void Icon::GetHeight(Local<String> property,
    const PropertyCallbackInfo<Value>& args) {

  NanScope();

  auto isolate = args.GetIsolate();
  auto handle = ObjectWrap::Unwrap<Icon>(
      args.Holder())->GetHandle<FridaIcon>();

  NanReturnValue(
      Integer::New(isolate, frida_icon_get_height(handle)));
}

void Icon::GetRowstride(Local<String> property,
    const PropertyCallbackInfo<Value>& args) {

  NanScope();

  auto isolate = args.GetIsolate();
  auto handle = ObjectWrap::Unwrap<Icon>(
      args.Holder())->GetHandle<FridaIcon>();

  NanReturnValue(
      Integer::New(isolate, frida_icon_get_rowstride(handle)));
}

void Icon::GetPixels(Local<String> property,
    const PropertyCallbackInfo<Value>& args) {

  NanScope();

  auto isolate = args.GetIsolate();
  auto handle = ObjectWrap::Unwrap<Icon>(
      args.Holder())->GetHandle<FridaIcon>();

  int len;
  auto buf = frida_icon_get_pixels(handle, &len);
  auto pixels = node::Encode(isolate, buf, len, node::BUFFER);

  NanReturnValue(pixels);
}

}
