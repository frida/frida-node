#include "session.h"

#include "events.h"
#include "operation.h"
#include "script.h"

#include <node.h>

#define SESSION_DATA_CONSTRUCTOR "session:ctor"

using v8::AccessorSignature;
using v8::DEFAULT;
using v8::Exception;
using v8::External;
using v8::Function;
using v8::FunctionCallbackInfo;
using v8::Handle;
using v8::HandleScope;
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
}

Session::~Session() {
  events_.Reset();
  frida_unref(handle_);
}

void Session::Init(Handle<Object> exports, Runtime* runtime) {
  auto isolate = Isolate::GetCurrent();

  auto name = String::NewFromUtf8(isolate, "Session");
  auto tpl = CreateTemplate(isolate, name, New, runtime);

  auto instance_tpl = tpl->InstanceTemplate();
  auto data = Handle<Value>();
  auto signature = AccessorSignature::New(isolate, tpl);
  instance_tpl->SetAccessor(String::NewFromUtf8(isolate, "pid"), GetPid, 0,
      data, DEFAULT, ReadOnly, signature);

  NODE_SET_PROTOTYPE_METHOD(tpl, "detach", Detach);
  NODE_SET_PROTOTYPE_METHOD(tpl, "createScript", CreateScript);

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
  auto isolate = args.GetIsolate();
  HandleScope scope(isolate);

  if (args.IsConstructCall()) {
    if (args.Length() != 1 || !args[0]->IsExternal()) {
      isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate,
          "Bad argument, expected raw handle")));
      return;
    }
    auto runtime = GetRuntimeFromConstructorArgs(args);
    auto wrapper = new Session(static_cast<FridaSession*>(
        Local<External>::Cast(args[0])->Value()), runtime);
    auto obj = args.This();
    wrapper->Wrap(obj);
    obj->Set(String::NewFromUtf8(isolate, "events"),
        Events::New(g_object_ref(wrapper->handle_), runtime));
    args.GetReturnValue().Set(obj);
  } else {
    args.GetReturnValue().Set(args.Callee()->NewInstance(0, NULL));
  }
}

void Session::GetPid(Local<String> property,
    const PropertyCallbackInfo<Value>& info) {
  auto isolate = info.GetIsolate();
  HandleScope scope(isolate);
  auto handle = ObjectWrap::Unwrap<Session>(
      info.Holder())->GetHandle<FridaSession>();

  info.GetReturnValue().Set(
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
  auto isolate = args.GetIsolate();
  HandleScope scope(isolate);
  auto obj = args.Holder();
  auto wrapper = ObjectWrap::Unwrap<Session>(obj);

  auto operation = new DetachOperation();
  operation->Schedule(isolate, wrapper);

  args.GetReturnValue().Set(operation->GetPromise(isolate));
}

class CreateScriptOperation : public Operation<FridaSession> {
 public:
  CreateScriptOperation(gchar* source) : source_(source) {
  }

  ~CreateScriptOperation() {
    g_free(source_);
  }

  void Begin() {
    frida_session_create_script(handle_, source_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    script_ = frida_session_create_script_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    return Script::New(script_, runtime_);
  }

  gchar* source_;
  FridaScript* script_;
};

void Session::CreateScript(const FunctionCallbackInfo<Value>& args) {
  auto isolate = args.GetIsolate();
  HandleScope scope(isolate);
  auto obj = args.Holder();
  auto wrapper = ObjectWrap::Unwrap<Session>(obj);

  if (args.Length() < 1 || !args[0]->IsString()) {
    isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate,
        "Bad argument, expected string")));
    return;
  }
  String::Utf8Value source(Local<String>::Cast(args[0]));

  auto operation = new CreateScriptOperation(g_strdup(*source));
  operation->Schedule(isolate, wrapper);

  args.GetReturnValue().Set(operation->GetPromise(isolate));
}

}
