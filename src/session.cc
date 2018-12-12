#include "session.h"

#include "crash.h"
#include "operation.h"
#include "script.h"
#include "signals.h"
#include "usage_monitor.h"

#include <nan.h>
#include <node.h>

#define SESSION_DATA_CONSTRUCTOR "session:ctor"

using v8::AccessorSignature;
using v8::DEFAULT;
using v8::External;
using v8::Function;
using v8::Handle;
using v8::Isolate;
using v8::Local;
using v8::Object;
using v8::ReadOnly;
using v8::String;
using v8::Value;

namespace frida {

Session::Session(FridaSession* handle, Runtime* runtime)
    : GLibObject(handle, runtime) {
  g_object_ref(handle_);
}

Session::~Session() {
  signals_.Reset();
  frida_unref(handle_);
}

void Session::Init(Handle<Object> exports, Runtime* runtime) {
  auto isolate = Isolate::GetCurrent();

  auto name = Nan::New("Session").ToLocalChecked();
  auto tpl = CreateTemplate(name, Session::New, runtime);

  auto instance_tpl = tpl->InstanceTemplate();
  auto data = Handle<Value>();
  auto signature = AccessorSignature::New(isolate, tpl);
  Nan::SetAccessor(instance_tpl, Nan::New("pid").ToLocalChecked(), GetPid, 0,
      data, DEFAULT, ReadOnly, signature);

  Nan::SetPrototypeMethod(tpl, "detach", Detach);
  Nan::SetPrototypeMethod(tpl, "enableChildGating", EnableChildGating);
  Nan::SetPrototypeMethod(tpl, "disableChildGating", DisableChildGating);
  Nan::SetPrototypeMethod(tpl, "createScript", CreateScript);
  Nan::SetPrototypeMethod(tpl, "createScriptFromBytes", CreateScriptFromBytes);
  Nan::SetPrototypeMethod(tpl, "compileScript", CompileScript);
  Nan::SetPrototypeMethod(tpl, "enableDebugger", EnableDebugger);
  Nan::SetPrototypeMethod(tpl, "disableDebugger", DisableDebugger);
  Nan::SetPrototypeMethod(tpl, "enableJit", EnableJit);

  auto ctor = Nan::GetFunction(tpl).ToLocalChecked();
  Nan::Set(exports, name, ctor);
  runtime->SetDataPointer(SESSION_DATA_CONSTRUCTOR,
      new v8::Persistent<Function>(isolate, ctor));
}

Local<Object> Session::New(gpointer handle, Runtime* runtime) {
  auto ctor = Nan::New<v8::Function>(
    *static_cast<v8::Persistent<Function>*>(
      runtime->GetDataPointer(SESSION_DATA_CONSTRUCTOR)));
  const int argc = 1;
  Local<Value> argv[argc] = { Nan::New<v8::External>(handle) };
  return Nan::NewInstance(ctor, argc, argv).ToLocalChecked();
}

NAN_METHOD(Session::New) {
  if (!info.IsConstructCall()) {
    Nan::ThrowError("Use the `new` keyword to create a new instance");
    return;
  }

  if (info.Length() != 1 || !info[0]->IsExternal()) {
    Nan::ThrowTypeError("Bad argument, expected raw handle");
    return;
  }

  auto runtime = GetRuntimeFromConstructorArgs(info);

  auto handle = static_cast<FridaSession*>(
      Local<External>::Cast(info[0])->Value());
  auto wrapper = new Session(handle, runtime);
  auto obj = info.This();
  wrapper->Wrap(obj);
  Nan::Set(obj, Nan::New("signals").ToLocalChecked(),
      Signals::New(handle, runtime, TransformSignal, wrapper));

  info.GetReturnValue().Set(obj);
}

NAN_PROPERTY_GETTER(Session::GetPid) {
  auto handle = ObjectWrap::Unwrap<Session>(
      info.Holder())->GetHandle<FridaSession>();

  info.GetReturnValue().Set(Nan::New<v8::Uint32>(
      frida_session_get_pid(handle)));
}

class DetachOperation : public Operation<FridaSession> {
 public:
  void Begin() {
    frida_session_detach(handle_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    frida_session_detach_finish(handle_, result);
  }

  Local<Value> Result(Isolate* isolate) {
    return Nan::Undefined();
  }
};

NAN_METHOD(Session::Detach) {
  auto isolate = info.GetIsolate();
  auto obj = info.Holder();
  auto wrapper = ObjectWrap::Unwrap<Session>(obj);

  auto operation = new DetachOperation();
  operation->Schedule(isolate, wrapper);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

class CreateScriptOperation : public Operation<FridaSession> {
 public:
  CreateScriptOperation(gchar* name, gchar* source)
    : name_(name),
      source_(source) {
  }

  ~CreateScriptOperation() {
    g_free(source_);
    g_free(name_);
  }

  void Begin() {
    frida_session_create_script(handle_, name_, source_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    script_ = frida_session_create_script_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    auto wrapper = Script::New(script_, runtime_);
    g_object_unref(script_);
    return wrapper;
  }

  gchar* name_;
  gchar* source_;
  FridaScript* script_;
};

class EnableChildGatingOperation : public Operation<FridaSession> {
 public:
  void Begin() {
    frida_session_enable_child_gating(handle_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    frida_session_enable_child_gating_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    return Nan::Undefined();
  }
};

NAN_METHOD(Session::EnableChildGating) {
  auto isolate = info.GetIsolate();
  auto obj = info.Holder();
  auto wrapper = ObjectWrap::Unwrap<Session>(obj);

  auto operation = new EnableChildGatingOperation();
  operation->Schedule(isolate, wrapper);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

class DisableChildGatingOperation : public Operation<FridaSession> {
 public:
  void Begin() {
    frida_session_disable_child_gating(handle_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    frida_session_disable_child_gating_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    return Nan::Undefined();
  }
};

NAN_METHOD(Session::DisableChildGating) {
  auto isolate = info.GetIsolate();
  auto obj = info.Holder();
  auto wrapper = ObjectWrap::Unwrap<Session>(obj);

  auto operation = new DisableChildGatingOperation();
  operation->Schedule(isolate, wrapper);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

NAN_METHOD(Session::CreateScript) {
  auto isolate = info.GetIsolate();
  auto obj = info.Holder();
  auto wrapper = ObjectWrap::Unwrap<Session>(obj);

  if (info.Length() < 2 ||
      !(info[0]->IsString() || info[0]->IsNull()) ||
      !info[1]->IsString()) {
    Nan::ThrowTypeError("Bad argument, expected string|null and string");
    return;
  }
  gchar* name = NULL;
  if (info[0]->IsString()) {
    Nan::Utf8String val(Local<String>::Cast(info[0]));
    name = g_strdup(*val);
  }
  Nan::Utf8String source(Local<String>::Cast(info[1]));

  auto operation = new CreateScriptOperation(name, g_strdup(*source));
  operation->Schedule(isolate, wrapper);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

class CreateScriptFromBytesOperation : public Operation<FridaSession> {
 public:
  CreateScriptFromBytesOperation(GBytes* bytes)
    : bytes_(bytes) {
  }

  ~CreateScriptFromBytesOperation() {
    g_bytes_unref(bytes_);
  }

  void Begin() {
    frida_session_create_script_from_bytes(handle_, bytes_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    script_ = frida_session_create_script_from_bytes_finish(handle_, result,
        error);
  }

  Local<Value> Result(Isolate* isolate) {
    auto wrapper = Script::New(script_, runtime_);
    g_object_unref(script_);
    return wrapper;
  }

  GBytes* bytes_;
  FridaScript* script_;
};

NAN_METHOD(Session::CreateScriptFromBytes) {
  auto isolate = info.GetIsolate();
  auto obj = info.Holder();
  auto wrapper = ObjectWrap::Unwrap<Session>(obj);

  if (info.Length() == 0 || !node::Buffer::HasInstance(info[0])) {
    Nan::ThrowTypeError("Bad argument, expected Buffer");
    return;
  }
  auto buffer = info[0];
  auto bytes = g_bytes_new(node::Buffer::Data(buffer),
      node::Buffer::Length(buffer));

  auto operation = new CreateScriptFromBytesOperation(bytes);
  operation->Schedule(isolate, wrapper);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

static void bytes_buffer_free(char* data, void* hint) {
  g_bytes_unref(static_cast<GBytes*>(hint));
}

class CompileScriptOperation : public Operation<FridaSession> {
 public:
  CompileScriptOperation(gchar* name, gchar* source)
    : name_(name),
      source_(source) {
  }

  ~CompileScriptOperation() {
    g_free(source_);
    g_free(name_);
  }

  void Begin() {
    frida_session_compile_script(handle_, name_, source_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    bytes_ = frida_session_compile_script_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    gsize size;
    auto data = g_bytes_get_data(bytes_, &size);
    return Nan::NewBuffer(static_cast<char*>(const_cast<void*>(data)), size,
        bytes_buffer_free, bytes_).ToLocalChecked();
  }

  gchar* name_;
  gchar* source_;
  GBytes* bytes_;
};

NAN_METHOD(Session::CompileScript) {
  auto isolate = info.GetIsolate();
  auto obj = info.Holder();
  auto wrapper = ObjectWrap::Unwrap<Session>(obj);

  if (info.Length() < 2 ||
      !(info[0]->IsString() || info[0]->IsNull()) ||
      !info[1]->IsString()) {
    Nan::ThrowTypeError("Bad argument, expected string|null and string");
    return;
  }
  gchar* name = NULL;
  if (info[0]->IsString()) {
    Nan::Utf8String val(Local<String>::Cast(info[0]));
    name = g_strdup(*val);
  }
  Nan::Utf8String source(Local<String>::Cast(info[1]));

  auto operation = new CompileScriptOperation(name, g_strdup(*source));
  operation->Schedule(isolate, wrapper);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

class EnableDebuggerOperation : public Operation<FridaSession> {
 public:
  EnableDebuggerOperation(guint16 port) : port_(port) {
  }

  void Begin() {
    frida_session_enable_debugger(handle_, port_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    frida_session_enable_debugger_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    return Nan::Undefined();
  }

  guint16 port_;
};

NAN_METHOD(Session::EnableDebugger) {
  auto isolate = info.GetIsolate();
  auto obj = info.Holder();
  auto wrapper = ObjectWrap::Unwrap<Session>(obj);

  if (info.Length() < 1 || !info[0]->IsNumber()) {
    Nan::ThrowTypeError("Bad argument, expected port number");
    return;
  }
  guint16 port = static_cast<guint16>(info[0]->ToInteger()->Value());

  auto operation = new EnableDebuggerOperation(port);
  operation->Schedule(isolate, wrapper);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

class DisableDebuggerOperation : public Operation<FridaSession> {
 public:
  void Begin() {
    frida_session_disable_debugger(handle_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    frida_session_disable_debugger_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    return Nan::Undefined();
  }
};

NAN_METHOD(Session::DisableDebugger) {
  auto isolate = info.GetIsolate();
  auto obj = info.Holder();
  auto wrapper = ObjectWrap::Unwrap<Session>(obj);

  auto operation = new DisableDebuggerOperation();
  operation->Schedule(isolate, wrapper);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

class EnableJitOperation : public Operation<FridaSession> {
 public:
  void Begin() {
    frida_session_enable_jit(handle_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    frida_session_enable_jit_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    return Nan::Undefined();
  }
};

NAN_METHOD(Session::EnableJit) {
  auto isolate = info.GetIsolate();
  auto obj = info.Holder();
  auto wrapper = ObjectWrap::Unwrap<Session>(obj);

  auto operation = new EnableJitOperation();
  operation->Schedule(isolate, wrapper);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

Local<Value> Session::TransformSignal(const gchar* name, guint index,
    const GValue* value, gpointer user_data) {
  auto self = static_cast<Session*>(user_data);

  if (index == 1 && strcmp(name, "detached") == 0) {
    auto crash = g_value_get_object(value);
    if (crash == NULL)
      return Nan::Null();
    return Crash::New(crash, self->runtime_);
  }

  return Local<Value>();
}

}
