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
using v8::Isolate;
using v8::Local;
using v8::Object;
using v8::ReadOnly;
using v8::String;
using v8::Value;

namespace frida {

static FridaScriptOptions* ParseScriptOptions(Local<Value> name_value,
    Local<Value> runtime_value);
static void UnrefGBytes(char* data, void* hint);

Session::Session(FridaSession* handle, Runtime* runtime)
    : GLibObject(handle, runtime) {
  g_object_ref(handle_);
}

Session::~Session() {
  signals_.Reset();
  frida_unref(handle_);
}

void Session::Init(Local<Object> exports, Runtime* runtime) {
  auto isolate = Isolate::GetCurrent();

  auto name = Nan::New("Session").ToLocalChecked();
  auto tpl = CreateTemplate(name, Session::New, runtime);

  auto instance_tpl = tpl->InstanceTemplate();
  auto data = Local<Value>();
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

namespace {

class DetachOperation : public Operation<FridaSession> {
 public:
  void Begin() {
    frida_session_detach(handle_, cancellable_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    frida_session_detach_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    return Nan::Undefined();
  }
};

}

NAN_METHOD(Session::Detach) {
  auto isolate = info.GetIsolate();
  auto obj = info.Holder();
  auto wrapper = ObjectWrap::Unwrap<Session>(obj);

  auto operation = new DetachOperation();
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

namespace {

class EnableChildGatingOperation : public Operation<FridaSession> {
 public:
  void Begin() {
    frida_session_enable_child_gating(handle_, cancellable_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    frida_session_enable_child_gating_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    return Nan::Undefined();
  }
};

}

NAN_METHOD(Session::EnableChildGating) {
  auto isolate = info.GetIsolate();
  auto obj = info.Holder();
  auto wrapper = ObjectWrap::Unwrap<Session>(obj);

  auto operation = new EnableChildGatingOperation();
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

namespace {

class DisableChildGatingOperation : public Operation<FridaSession> {
 public:
  void Begin() {
    frida_session_disable_child_gating(handle_, cancellable_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    frida_session_disable_child_gating_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    return Nan::Undefined();
  }
};

}

NAN_METHOD(Session::DisableChildGating) {
  auto isolate = info.GetIsolate();
  auto obj = info.Holder();
  auto wrapper = ObjectWrap::Unwrap<Session>(obj);

  auto operation = new DisableChildGatingOperation();
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

namespace {

class CreateScriptOperation : public Operation<FridaSession> {
 public:
  CreateScriptOperation(gchar* source, FridaScriptOptions* options)
    : source_(source),
      options_(options) {
  }

  ~CreateScriptOperation() {
    g_object_unref(options_);
    g_free(source_);
  }

  void Begin() {
    frida_session_create_script(handle_, source_, options_, cancellable_,
        OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    script_ = frida_session_create_script_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    auto wrapper = Script::New(script_, runtime_);
    g_object_unref(script_);
    return wrapper;
  }

  gchar* source_;
  FridaScriptOptions* options_;
  FridaScript* script_;
};

}


NAN_METHOD(Session::CreateScript) {
  auto isolate = info.GetIsolate();
  auto obj = info.Holder();
  auto wrapper = ObjectWrap::Unwrap<Session>(obj);

  if (info.Length() < 3) {
    Nan::ThrowTypeError("Missing one or more arguments");
    return;
  }

  auto source_value = info[0];
  auto name_value = info[1];
  auto runtime_value = info[2];

  bool valid = true;

  gchar* source;
  Nan::Utf8String val(source_value);
  source = g_strdup(*val);
  if (source == NULL) {
    Nan::ThrowTypeError("Bad argument, 'source' must be a string");
    valid = false;
  }

  FridaScriptOptions* options = NULL;
  if (valid) {
    options = ParseScriptOptions(name_value, runtime_value);
    valid = options != NULL;
  }

  if (!valid) {
    g_free(source);
    g_clear_object(&options);
    return;
  }

  auto operation = new CreateScriptOperation(source, options);
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

namespace {

class CreateScriptFromBytesOperation : public Operation<FridaSession> {
 public:
  CreateScriptFromBytesOperation(GBytes* bytes, FridaScriptOptions* options)
    : bytes_(bytes),
      options_(options) {
  }

  ~CreateScriptFromBytesOperation() {
    g_object_unref(options_);
    g_bytes_unref(bytes_);
  }

  void Begin() {
    frida_session_create_script_from_bytes(handle_, bytes_, options_,
        cancellable_, OnReady, this);
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
  FridaScriptOptions* options_;
  FridaScript* script_;
};

}

NAN_METHOD(Session::CreateScriptFromBytes) {
  auto isolate = info.GetIsolate();
  auto obj = info.Holder();
  auto wrapper = ObjectWrap::Unwrap<Session>(obj);

  if (info.Length() < 3) {
    Nan::ThrowTypeError("Missing one or more arguments");
    return;
  }

  auto bytes_value = info[0];
  auto name_value = info[1];
  auto runtime_value = info[2];

  bool valid = true;

  GBytes* bytes = NULL;
  if (node::Buffer::HasInstance(bytes_value)) {
    bytes = g_bytes_new(node::Buffer::Data(bytes_value),
        node::Buffer::Length(bytes_value));
  } else {
    Nan::ThrowTypeError("Bad argument, 'bytes' must be a Buffer");
    valid = false;
  }

  FridaScriptOptions* options = NULL;
  if (valid) {
    options = ParseScriptOptions(name_value, runtime_value);
    valid = options != NULL;
  }

  if (!valid) {
    g_bytes_unref(bytes);
    g_clear_object(&options);
    return;
  }

  auto operation = new CreateScriptFromBytesOperation(bytes, options);
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

namespace {

class CompileScriptOperation : public Operation<FridaSession> {
 public:
  CompileScriptOperation(gchar* source, FridaScriptOptions* options)
    : source_(source),
      options_(options) {
  }

  ~CompileScriptOperation() {
    g_object_unref(options_);
    g_free(source_);
  }

  void Begin() {
    frida_session_compile_script(handle_, source_, options_, cancellable_,
        OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    bytes_ = frida_session_compile_script_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    gsize size;
    auto data = g_bytes_get_data(bytes_, &size);
    return Nan::NewBuffer(static_cast<char*>(const_cast<void*>(data)), size,
        UnrefGBytes, bytes_).ToLocalChecked();
  }

  gchar* source_;
  FridaScriptOptions* options_;
  GBytes* bytes_;
};

}

NAN_METHOD(Session::CompileScript) {
  auto isolate = info.GetIsolate();
  auto obj = info.Holder();
  auto wrapper = ObjectWrap::Unwrap<Session>(obj);

  if (info.Length() < 3) {
    Nan::ThrowTypeError("Missing one or more arguments");
    return;
  }

  auto source_value = info[0];
  auto name_value = info[1];
  auto runtime_value = info[2];

  bool valid = true;

  gchar* source;
  Nan::Utf8String val(source_value);
  source = g_strdup(*val);
  if (source == NULL) {
    Nan::ThrowTypeError("Bad argument, 'source' must be a string");
    valid = false;
  }

  FridaScriptOptions* options = NULL;
  if (valid) {
    options = ParseScriptOptions(name_value, runtime_value);
    valid = options != NULL;
  }

  if (!valid) {
    g_free(source);
    g_clear_object(&options);
    return;
  }

  auto operation = new CompileScriptOperation(source, options);
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

static FridaScriptOptions* ParseScriptOptions(Local<Value> name_value,
    Local<Value> runtime_value) {
  auto options = frida_script_options_new();
  bool valid = true;

  if (!name_value->IsNull()) {
    Nan::Utf8String val(name_value);
    const gchar* name = *val;
    if (name != NULL) {
      frida_script_options_set_name(options, name);
    } else {
      Nan::ThrowTypeError("Bad argument, 'name' must be a string");
      valid = false;
    }
  }

  if (valid && !runtime_value->IsNull()) {
    FridaScriptRuntime runtime;
    valid = Runtime::ValueToEnum(runtime_value, FRIDA_TYPE_SCRIPT_RUNTIME,
        &runtime);
    if (valid) {
      frida_script_options_set_runtime(options, runtime);
    }
  }

  if (!valid) {
    g_object_unref(options);
    return NULL;
  }

  return options;
}

namespace {

class EnableDebuggerOperation : public Operation<FridaSession> {
 public:
  EnableDebuggerOperation(guint16 port) : port_(port) {
  }

  void Begin() {
    frida_session_enable_debugger(handle_, port_, cancellable_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    frida_session_enable_debugger_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    return Nan::Undefined();
  }

  guint16 port_;
};

}

NAN_METHOD(Session::EnableDebugger) {
  auto isolate = info.GetIsolate();
  auto obj = info.Holder();
  auto wrapper = ObjectWrap::Unwrap<Session>(obj);

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

class DisableDebuggerOperation : public Operation<FridaSession> {
 public:
  void Begin() {
    frida_session_disable_debugger(handle_, cancellable_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    frida_session_disable_debugger_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    return Nan::Undefined();
  }
};

}

NAN_METHOD(Session::DisableDebugger) {
  auto isolate = info.GetIsolate();
  auto obj = info.Holder();
  auto wrapper = ObjectWrap::Unwrap<Session>(obj);

  auto operation = new DisableDebuggerOperation();
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

namespace {

class EnableJitOperation : public Operation<FridaSession> {
 public:
  void Begin() {
    frida_session_enable_jit(handle_, cancellable_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    frida_session_enable_jit_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    return Nan::Undefined();
  }
};

}

NAN_METHOD(Session::EnableJit) {
  auto isolate = info.GetIsolate();
  auto obj = info.Holder();
  auto wrapper = ObjectWrap::Unwrap<Session>(obj);

  auto operation = new EnableJitOperation();
  operation->Schedule(isolate, wrapper, info);

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

static void UnrefGBytes(char* data, void* hint) {
  g_bytes_unref(static_cast<GBytes*>(hint));
}

}
