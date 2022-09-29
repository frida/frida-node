#include "script.h"

#include "operation.h"
#include "signals.h"
#include "usage_monitor.h"

#include <cstring>

#define SCRIPT_DATA_CONSTRUCTOR "script:ctor"

using std::strcmp;
using v8::DEFAULT;
using v8::External;
using v8::Function;
using v8::Isolate;
using v8::Local;
using v8::Object;
using v8::Persistent;
using v8::ReadOnly;
using v8::String;
using v8::Value;

namespace frida {

Script::Script(FridaScript* handle, Runtime* runtime)
    : GLibObject(handle, runtime) {
  g_object_ref(handle_);
}

Script::~Script() {
  frida_unref(handle_);
}

void Script::Init(Local<Object> exports, Runtime* runtime) {
  auto isolate = Isolate::GetCurrent();

  auto name = Nan::New("Script").ToLocalChecked();
  auto tpl = CreateTemplate(name, New, runtime);

  auto instance_tpl = tpl->InstanceTemplate();
  auto data = Local<Value>();
  Nan::SetAccessor(instance_tpl, Nan::New("isDestroyed").ToLocalChecked(),
      IsDestroyed, 0, data, DEFAULT, ReadOnly);

  Nan::SetPrototypeMethod(tpl, "load", Load);
  Nan::SetPrototypeMethod(tpl, "unload", Unload);
  Nan::SetPrototypeMethod(tpl, "eternalize", Eternalize);
  Nan::SetPrototypeMethod(tpl, "post", Post);
  Nan::SetPrototypeMethod(tpl, "enableDebugger", EnableDebugger);
  Nan::SetPrototypeMethod(tpl, "disableDebugger", DisableDebugger);

  auto ctor = Nan::GetFunction(tpl).ToLocalChecked();
  Nan::Set(exports, name, ctor);
  runtime->SetDataPointer(SCRIPT_DATA_CONSTRUCTOR,
      new Persistent<Function>(isolate, ctor));
}

Local<Object> Script::New(gpointer handle, Runtime* runtime) {
  auto ctor = Nan::New<Function>(
      *static_cast<Persistent<Function>*>(
      runtime->GetDataPointer(SCRIPT_DATA_CONSTRUCTOR)));
  const int argc = 1;
  Local<Value> argv[argc] = { Nan::New<External>(handle) };
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
  Nan::Set(obj, Nan::New("signals").ToLocalChecked(),
      Signals::New(handle, runtime, TransformMessageSignal, runtime));

  auto monitor =
      new UsageMonitor<FridaScript>(frida_script_is_destroyed, "destroyed");
  monitor->Enable(wrapper);

  info.GetReturnValue().Set(obj);
}

NAN_PROPERTY_GETTER(Script::IsDestroyed) {
  auto handle = ObjectWrap::Unwrap<Script>(
      info.Holder())->GetHandle<FridaScript>();

  info.GetReturnValue().Set(
      Nan::New(static_cast<bool>(frida_script_is_destroyed(handle))));
}

namespace {

class LoadOperation : public Operation<FridaScript> {
 protected:
  void Begin() {
    frida_script_load(handle_, cancellable_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    frida_script_load_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    return Nan::Undefined();
  }
};

}

NAN_METHOD(Script::Load) {
  auto isolate = info.GetIsolate();
  auto wrapper = ObjectWrap::Unwrap<Script>(info.Holder());

  auto operation = new LoadOperation();
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

namespace {

class UnloadOperation : public Operation<FridaScript> {
 protected:
  void Begin() {
    frida_script_unload(handle_, cancellable_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    frida_script_unload_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    return Nan::Undefined();
  }
};

}

NAN_METHOD(Script::Unload) {
  auto isolate = info.GetIsolate();
  auto wrapper = ObjectWrap::Unwrap<Script>(info.Holder());

  auto operation = new UnloadOperation();
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

namespace {

class EternalizeOperation : public Operation<FridaScript> {
 protected:
  void Begin() {
    frida_script_eternalize(handle_, cancellable_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    frida_script_eternalize_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    return Nan::Undefined();
  }
};

}

NAN_METHOD(Script::Eternalize) {
  auto isolate = info.GetIsolate();
  auto wrapper = ObjectWrap::Unwrap<Script>(info.Holder());

  auto operation = new EternalizeOperation();
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

NAN_METHOD(Script::Post) {
  auto wrapper = ObjectWrap::Unwrap<Script>(info.Holder());

  auto num_args = info.Length();
  if (num_args < 2) {
    Nan::ThrowTypeError("Expected message and data");
    return;
  }

  Nan::Utf8String message(wrapper->runtime_->ValueToJson(info[0]));

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

  frida_script_post(wrapper->GetHandle<FridaScript>(), *message, data);

  g_bytes_unref(data);
}

namespace {

class EnableDebuggerOperation : public Operation<FridaScript> {
 public:
  EnableDebuggerOperation(guint16 port) : port_(port) {
  }

 protected:
  void Begin() {
    frida_script_enable_debugger(handle_, port_, cancellable_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    frida_script_enable_debugger_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    return Nan::Undefined();
  }

 private:
  guint16 port_;
};

}

NAN_METHOD(Script::EnableDebugger) {
  auto isolate = info.GetIsolate();
  auto wrapper = ObjectWrap::Unwrap<Script>(info.Holder());

  if (info.Length() < 1 || !info[0]->IsNumber()) {
    Nan::ThrowTypeError("Bad argument, expected port number");
    return;
  }
  auto port = Nan::To<int32_t>(info[0]).FromMaybe(-1);
  if (port < 0 || port >= 65536) {
    Nan::ThrowTypeError("Bad argument, expected port number");
    return;
  }

  auto operation = new EnableDebuggerOperation(static_cast<guint16>(port));
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

namespace {

class DisableDebuggerOperation : public Operation<FridaScript> {
 protected:
  void Begin() {
    frida_script_disable_debugger(handle_, cancellable_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    frida_script_disable_debugger_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    return Nan::Undefined();
  }
};

}

NAN_METHOD(Script::DisableDebugger) {
  auto isolate = info.GetIsolate();
  auto wrapper = ObjectWrap::Unwrap<Script>(info.Holder());

  auto operation = new DisableDebuggerOperation();
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

Local<Value> Script::TransformMessageSignal(const gchar* name, guint index,
    const GValue* value, gpointer user_data) {
  if (index != 0 || strcmp(name, "message") != 0)
    return Local<Value>();
  auto runtime = static_cast<Runtime*>(user_data);
  auto json = Nan::New(g_value_get_string(value)).ToLocalChecked();
  return runtime->ValueFromJson(json);
}

}
