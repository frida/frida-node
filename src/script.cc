#include "script.h"

#include "events.h"
#include "operation.h"

#include <node.h>

#define SCRIPT_DATA_CONSTRUCTOR "script:ctor"

using v8::Exception;
using v8::External;
using v8::Function;
using v8::FunctionCallbackInfo;
using v8::Handle;
using v8::HandleScope;
using v8::Isolate;
using v8::Local;
using v8::Object;
using v8::Persistent;
using v8::String;
using v8::Value;

namespace frida {

Script::Script(FridaScript* handle, Runtime* runtime)
    : GLibObject(handle, runtime) {
}

Script::~Script() {
  events_.Reset();
  frida_unref(handle_);
}

void Script::Init(Handle<Object> exports, Runtime* runtime) {
  auto isolate = Isolate::GetCurrent();

  auto name = String::NewFromUtf8(isolate, "Script");
  auto tpl = CreateTemplate(isolate, name, New, runtime);

  NODE_SET_PROTOTYPE_METHOD(tpl, "load", Load);

  auto ctor = tpl->GetFunction();
  exports->Set(name, ctor);
  runtime->SetDataPointer(SCRIPT_DATA_CONSTRUCTOR,
      new Persistent<Function>(isolate, ctor));
}

Local<Object> Script::New(gpointer handle, Runtime* runtime) {
  auto isolate = Isolate::GetCurrent();

  auto ctor = Local<Function>::New(isolate,
      *static_cast<Persistent<Function>*>(
      runtime->GetDataPointer(SCRIPT_DATA_CONSTRUCTOR)));
  const int argc = 1;
  Local<Value> argv[argc] = { External::New(isolate, handle) };
  return ctor->NewInstance(argc, argv);
}

void Script::New(const FunctionCallbackInfo<Value>& args) {
  auto isolate = args.GetIsolate();
  HandleScope scope(isolate);

  if (args.IsConstructCall()) {
    if (args.Length() != 1 || !args[0]->IsExternal()) {
      isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate,
          "Bad argument, expected raw handle")));
      return;
    }
    auto runtime = GetRuntimeFromConstructorArgs(args);
    auto wrapper = new Script(static_cast<FridaScript*>(
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

class LoadOperation : public Operation<FridaScript> {
 public:
  void Begin() {
    frida_script_load(handle_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    frida_script_load_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    return Undefined(isolate);
  }
};

void Script::Load(const FunctionCallbackInfo<Value>& args) {
  auto isolate = args.GetIsolate();
  HandleScope scope(isolate);
  auto obj = args.Holder();
  auto wrapper = ObjectWrap::Unwrap<Script>(obj);

  auto operation = new LoadOperation();
  operation->Schedule(isolate, wrapper);

  args.GetReturnValue().Set(operation->GetPromise(isolate));
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
    return Undefined(isolate);
  }
};

void Script::Unload(const FunctionCallbackInfo<Value>& args) {
  auto isolate = args.GetIsolate();
  HandleScope scope(isolate);
  auto obj = args.Holder();
  auto wrapper = ObjectWrap::Unwrap<Script>(obj);

  auto operation = new UnloadOperation();
  operation->Schedule(isolate, wrapper);

  args.GetReturnValue().Set(operation->GetPromise(isolate));
}

class PostMessageOperation : public Operation<FridaScript> {
 public:
  PostMessageOperation(gchar* message) : message_(message) {
  }

  ~PostMessageOperation() {
    g_free(message_);
  }

  void Begin() {
    frida_script_post_message(handle_, message_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    frida_script_post_message_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    return Undefined(isolate);
  }

  gchar* message_;
};

void Script::PostMessage(const FunctionCallbackInfo<Value>& args) {
  auto isolate = args.GetIsolate();
  HandleScope scope(isolate);
  auto obj = args.Holder();
  auto wrapper = ObjectWrap::Unwrap<Script>(obj);

  if (args.Length() < 1 || !args[0]->IsObject()) {
    isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate,
        "Bad argument, expected object")));
    return;
  }
  auto message_obj = Local<Object>::Cast(args[0]);
  String::Utf8Value message(
      wrapper->runtime_->ValueToJson(isolate, message_obj));

  auto operation = new PostMessageOperation(g_strdup(*message));
  operation->Schedule(isolate, wrapper);

  args.GetReturnValue().Set(operation->GetPromise(isolate));
}

}
