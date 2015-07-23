#include "session.h"

#include "events.h"
#include "operation.h"
#include "script.h"
#include "usage_monitor.h"

#include <node.h>
#include <nan.h>

#define SESSION_DATA_CONSTRUCTOR "session:ctor"

using v8::AccessorSignature;
using v8::DEFAULT;
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
using v8::PropertyCallbackInfo;
using v8::ReadOnly;
using v8::String;
using v8::Value;

namespace frida {

Session::Session(FridaSession* handle, Runtime* runtime)
    : GLibObject(handle, runtime) {
  g_object_ref(handle_);
}

Session::~Session() {
  events_.Reset();
  frida_unref(handle_);
}

void Session::Init(Handle<Object> exports, Runtime* runtime) {
  auto isolate = Isolate::GetCurrent();

  auto name = NanNew("Session");
  auto tpl = CreateTemplate(isolate, name, New, runtime);

  auto instance_tpl = tpl->InstanceTemplate();
  auto data = Handle<Value>();
  auto signature = AccessorSignature::New(isolate, tpl);
  instance_tpl->SetAccessor(NanNew("pid"), GetPid, 0,
      data, DEFAULT, ReadOnly, signature);

  NODE_SET_PROTOTYPE_METHOD(tpl, "detach", Detach);
  NODE_SET_PROTOTYPE_METHOD(tpl, "createScript", CreateScript);
  NODE_SET_PROTOTYPE_METHOD(tpl, "enableDebugger", EnableDebugger);
  NODE_SET_PROTOTYPE_METHOD(tpl, "disableDebugger", DisableDebugger);

  auto ctor = tpl->GetFunction();
  exports->Set(name, ctor);
  runtime->SetDataPointer(SESSION_DATA_CONSTRUCTOR,
      new Persistent<Function>(isolate, ctor));
}

Local<Object> Session::New(gpointer handle, Runtime* runtime) {
  auto isolate = Isolate::GetCurrent();

  auto ctor = Local<Function>::New(isolate,
      *static_cast<Persistent<Function>*>(
      runtime->GetDataPointer(SESSION_DATA_CONSTRUCTOR)));
  const int argc = 1;
  Local<Value> argv[argc] = { External::New(isolate, handle) };
  return ctor->NewInstance(argc, argv);
}

void Session::New(const FunctionCallbackInfo<Value>& args) {

  NanScope();

  if (args.IsConstructCall()) {
    if (args.Length() != 1 || !args[0]->IsExternal()) {
      NanThrowTypeError("Bad argument, expected raw handle");
      NanReturnUndefined();
    }
    auto runtime = GetRuntimeFromConstructorArgs(args);

    auto handle = static_cast<FridaSession*>(
        Local<External>::Cast(args[0])->Value());
    auto wrapper = new Session(handle, runtime);
    auto obj = args.This();
    wrapper->Wrap(obj);
    obj->Set(NanNew("events"),
        Events::New(handle, runtime));

    auto monitor =
        new UsageMonitor<FridaSession>(frida_session_is_detached, "detached");
    monitor->Enable(wrapper);

    NanReturnValue(obj);
  } else {
    NanReturnValue(args.Callee()->NewInstance(0, NULL));
  }
}

void Session::GetPid(Local<String> property,
    const PropertyCallbackInfo<Value>& args) {

  NanScope();

  auto isolate = args.GetIsolate();
  auto handle = ObjectWrap::Unwrap<Session>(
      args.Holder())->GetHandle<FridaSession>();

  NanReturnValue(
      Integer::NewFromUnsigned(isolate, frida_session_get_pid(handle)));
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
    return Undefined(isolate);
  }
};

void Session::Detach(const FunctionCallbackInfo<Value>& args) {

  NanScope();

  auto isolate = args.GetIsolate();
  auto obj = args.Holder();
  auto wrapper = ObjectWrap::Unwrap<Session>(obj);

  auto operation = new DetachOperation();
  operation->Schedule(isolate, wrapper);

  NanReturnValue(operation->GetPromise(isolate));
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

void Session::CreateScript(const FunctionCallbackInfo<Value>& args) {

  NanScope();

  auto isolate = args.GetIsolate();
  auto obj = args.Holder();
  auto wrapper = ObjectWrap::Unwrap<Session>(obj);

  if (args.Length() < 2 ||
      !(args[0]->IsString() || args[0]->IsNull()) ||
      !args[1]->IsString()) {
    NanThrowTypeError("Bad argument, expected string|null and string");
    NanReturnUndefined();
  }
  gchar* name = NULL;
  if (args[0]->IsString()) {
    String::Utf8Value val(Local<String>::Cast(args[0]));
    name = g_strdup(*val);
  }
  String::Utf8Value source(Local<String>::Cast(args[1]));

  auto operation = new CreateScriptOperation(name, g_strdup(*source));
  operation->Schedule(isolate, wrapper);

  NanReturnValue(operation->GetPromise(isolate));
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
    return Undefined(isolate);
  }

  guint16 port_;
};

void Session::EnableDebugger(const FunctionCallbackInfo<Value>& args) {

  NanScope();

  auto isolate = args.GetIsolate();
  auto obj = args.Holder();
  auto wrapper = ObjectWrap::Unwrap<Session>(obj);

  if (args.Length() < 1 || !args[0]->IsNumber()) {
    NanThrowTypeError("Bad argument, expected port number");
    NanReturnUndefined();
  }
  guint16 port = static_cast<guint16>(args[0]->ToInteger()->Value());

  auto operation = new EnableDebuggerOperation(port);
  operation->Schedule(isolate, wrapper);

  NanReturnValue(operation->GetPromise(isolate));
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
    return Undefined(isolate);
  }
};

void Session::DisableDebugger(const FunctionCallbackInfo<Value>& args) {

  NanScope();

  auto isolate = args.GetIsolate();
  auto obj = args.Holder();
  auto wrapper = ObjectWrap::Unwrap<Session>(obj);

  auto operation = new DisableDebuggerOperation();
  operation->Schedule(isolate, wrapper);

  NanReturnValue(operation->GetPromise(isolate));
}

}
