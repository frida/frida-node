#include "script.h"

#include "events.h"
#include "operation.h"
#include "usage_monitor.h"

#include <cstring>
#include <nan.h>
#include <node.h>

#define SCRIPT_DATA_CONSTRUCTOR "script:ctor"

using v8::External;
using v8::Function;
using v8::Handle;
using v8::Isolate;
using v8::Local;
using v8::Object;
using v8::String;
using v8::Value;

namespace frida {

Script::Script(FridaScript* handle, Runtime* runtime)
    : GLibObject(handle, runtime) {
  g_object_ref(handle_);
}

Script::~Script() {
  events_.Reset();
  frida_unref(handle_);
}

void Script::Init(Handle<Object> exports, Runtime* runtime) {
  auto isolate = Isolate::GetCurrent();

  auto name = Nan::New("Script").ToLocalChecked();
  auto tpl = CreateTemplate(name, New, runtime);

  Nan::SetPrototypeMethod(tpl, "load", Load);
  Nan::SetPrototypeMethod(tpl, "unload", Unload);
  Nan::SetPrototypeMethod(tpl, "post", Post);

  auto ctor = Nan::GetFunction(tpl).ToLocalChecked();
  Nan::Set(exports, name, ctor);
  runtime->SetDataPointer(SCRIPT_DATA_CONSTRUCTOR,
      new v8::Persistent<Function>(isolate, ctor));
}

Local<Object> Script::New(gpointer handle, Runtime* runtime) {
  auto ctor = Nan::New<v8::Function>(
      *static_cast<v8::Persistent<Function>*>(
      runtime->GetDataPointer(SCRIPT_DATA_CONSTRUCTOR)));
  const int argc = 1;
  Local<Value> argv[argc] = { Nan::New<v8::External>(handle) };
  return Nan::NewInstance(ctor, argc, argv).ToLocalChecked();
}

NAN_METHOD(Script::New) {
  if (!info.IsConstructCall()) {
    Nan::ThrowError("Use the `new` keyword to create a new instance");
    return;
  }

  if (info.Length() != 1 || !info[0]->IsExternal()) {
    Nan::ThrowTypeError("Bad argument, expected raw handle");
    return;
  }

  auto runtime = GetRuntimeFromConstructorArgs(info);

  auto handle = static_cast<FridaScript*>(
      Local<External>::Cast(info[0])->Value());
  auto wrapper = new Script(handle, runtime);
  auto obj = info.This();
  wrapper->Wrap(obj);
  Nan::Set(obj, Nan::New("events").ToLocalChecked(),
      Events::New(handle, runtime, TransformMessageEvent, wrapper));

  auto monitor =
      new UsageMonitor<FridaScript>(frida_script_is_destroyed, "destroyed");
  monitor->Enable(wrapper);

  info.GetReturnValue().Set(obj);
}

class LoadOperation : public Operation<FridaScript> {
 public:
  void Begin() {
    frida_script_load(handle_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    frida_script_load_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    return Nan::Undefined();
  }
};

NAN_METHOD(Script::Load) {
  auto isolate = info.GetIsolate();
  auto obj = info.Holder();
  auto wrapper = ObjectWrap::Unwrap<Script>(obj);

  auto operation = new LoadOperation();
  operation->Schedule(isolate, wrapper);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

class UnloadOperation : public Operation<FridaScript> {
 public:
  void Begin() {
    frida_script_unload(handle_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    frida_script_unload_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    return Nan::Undefined();
  }
};

NAN_METHOD(Script::Unload) {
  auto isolate = info.GetIsolate();
  auto obj = info.Holder();
  auto wrapper = ObjectWrap::Unwrap<Script>(obj);

  auto operation = new UnloadOperation();
  operation->Schedule(isolate, wrapper);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

class PostOperation : public Operation<FridaScript> {
 public:
  PostOperation(gchar* message, GBytes* data) : message_(message), data_(data) {
  }

  ~PostOperation() {
    g_free(message_);
    g_bytes_unref(data_);
  }

  void Begin() {
    frida_script_post(handle_, message_, data_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    frida_script_post_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    return Nan::Undefined();
  }

  gchar* message_;
  GBytes* data_;
};

NAN_METHOD(Script::Post) {
  auto isolate = info.GetIsolate();
  auto obj = info.Holder();
  auto wrapper = ObjectWrap::Unwrap<Script>(obj);

  auto num_args = info.Length();
  if (num_args < 2) {
    Nan::ThrowTypeError("Expected message and data");
    return;
  }

  String::Utf8Value message(
      wrapper->runtime_->ValueToJson(info[0]));

  GBytes* data = NULL;
  auto buffer = info[1];
  if (!buffer->IsNull()) {
    if (!node::Buffer::HasInstance(buffer)) {
      Nan::ThrowTypeError("Expected a buffer");
      return;
    }
    data = g_bytes_new(node::Buffer::Data(buffer),
        node::Buffer::Length(buffer));
  }

  auto operation = new PostOperation(g_strdup(*message), data);
  operation->Schedule(isolate, wrapper);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

Local<Value> Script::TransformMessageEvent(const gchar* name, guint index,
    const GValue* value, gpointer user_data) {
  if (index != 0 || strcmp(name, "message") != 0)
    return Local<Value>();
  auto self = static_cast<Script*>(user_data);
  auto json = Nan::New(g_value_get_string(value)).ToLocalChecked();
  return self->runtime_->ValueFromJson(json);
}

}
