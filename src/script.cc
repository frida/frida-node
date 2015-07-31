#include "script.h"

#include "events.h"
#include "operation.h"
#include "usage_monitor.h"

#include <cstring>
#include <nan.h>
#include <node.h>

#define SCRIPT_DATA_CONSTRUCTOR "script:ctor"

using v8::Exception;
using v8::External;
using v8::Function;
using v8::FunctionCallbackInfo;
using v8::Handle;
using v8::Isolate;
using v8::Local;
using v8::Object;
using v8::Persistent;
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

  auto name = NanNew("Script");
  auto tpl = CreateTemplate(isolate, name, New, runtime);

  NODE_SET_PROTOTYPE_METHOD(tpl, "load", Load);
  NODE_SET_PROTOTYPE_METHOD(tpl, "unload", Unload);
  NODE_SET_PROTOTYPE_METHOD(tpl, "postMessage", PostMessage);

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
  NanScope();

  if (args.IsConstructCall()) {
    if (args.Length() != 1 || !args[0]->IsExternal()) {
      NanThrowTypeError("Bad argument, expected raw handle");
      NanReturnUndefined();
    }
    auto runtime = GetRuntimeFromConstructorArgs(args);

    auto handle = static_cast<FridaScript*>(
        Local<External>::Cast(args[0])->Value());
    auto wrapper = new Script(handle, runtime);
    auto obj = args.This();
    wrapper->Wrap(obj);
    obj->Set(NanNew("events"),
        Events::New(handle, runtime, TransformMessageEvent, wrapper));

    auto monitor =
        new UsageMonitor<FridaScript>(frida_script_is_destroyed, "destroyed");
    monitor->Enable(wrapper);

    NanReturnValue(obj);
  } else {
    NanReturnValue(args.Callee()->NewInstance(0, NULL));
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
  NanScope();

  auto isolate = args.GetIsolate();
  auto obj = args.Holder();
  auto wrapper = ObjectWrap::Unwrap<Script>(obj);

  auto operation = new LoadOperation();
  operation->Schedule(isolate, wrapper);

  NanReturnValue(operation->GetPromise(isolate));
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
  NanScope();

  auto isolate = args.GetIsolate();
  auto obj = args.Holder();
  auto wrapper = ObjectWrap::Unwrap<Script>(obj);

  auto operation = new UnloadOperation();
  operation->Schedule(isolate, wrapper);

  NanReturnValue(operation->GetPromise(isolate));
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
  NanScope();

  auto isolate = args.GetIsolate();
  auto obj = args.Holder();
  auto wrapper = ObjectWrap::Unwrap<Script>(obj);

  if (args.Length() < 1) {
    NanThrowTypeError("Expected value serializable to JSON");
    NanReturnUndefined();
  }
  String::Utf8Value message(
      wrapper->runtime_->ValueToJson(isolate, args[0]));

  auto operation = new PostMessageOperation(g_strdup(*message));
  operation->Schedule(isolate, wrapper);

  NanReturnValue(operation->GetPromise(isolate));
}

Local<Value> Script::TransformMessageEvent(Isolate* isolate,
    const gchar* name, guint index, const GValue* value, gpointer user_data) {
  if (index != 0 || strcmp(name, "message") != 0)
    return Local<Value>();
  auto self = static_cast<Script*>(user_data);
  auto json = NanNew(g_value_get_string(value));
  return self->runtime_->ValueFromJson(isolate, json);
}

}
