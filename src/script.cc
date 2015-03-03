#include "script.h"

#include "events.h"
#include "operation.h"

using v8::Exception;
using v8::External;
using v8::Function;
using v8::FunctionCallbackInfo;
using v8::FunctionTemplate;
using v8::Handle;
using v8::HandleScope;
using v8::Isolate;
using v8::Local;
using v8::Object;
using v8::Persistent;
using v8::String;
using v8::Value;

namespace frida {

Persistent<Function> Script::constructor_;

Script::Script(FridaScript* handle) : handle_(handle) {
}

Script::~Script() {
  events_.Reset();
  frida_unref(handle_);
}

void Script::Init(Handle<Object> exports) {
  auto isolate = Isolate::GetCurrent();

  auto tpl = FunctionTemplate::New(isolate, New);
  tpl->SetClassName(String::NewFromUtf8(isolate, "Script"));
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  NODE_SET_PROTOTYPE_METHOD(tpl, "load", Load);

  exports->Set(String::NewFromUtf8(isolate, "Script"),
      tpl->GetFunction());

  constructor_.Reset(isolate, tpl->GetFunction());
}

Local<Object> Script::Create(gpointer handle) {
  auto isolate = Isolate::GetCurrent();

  auto constructor = Local<Function>::New(isolate, constructor_);
  const int argc = 1;
  Local<Value> argv[argc] = { External::New(isolate, handle) };
  return constructor->NewInstance(argc, argv);
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
    auto wrapper = new Script(static_cast<FridaScript*>(
        Local<External>::Cast(args[0])->Value()));
    auto obj = args.This();
    wrapper->Wrap(obj);
    obj->Set(String::NewFromUtf8(isolate, "events"),
        Events::Create(g_object_ref(wrapper->handle_)));
    args.GetReturnValue().Set(obj);
  } else {
    auto constructor = Local<Function>::New(isolate, constructor_);
    args.GetReturnValue().Set(constructor->NewInstance(0, NULL));
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
  operation->Schedule(isolate, obj, wrapper->handle_);

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
  operation->Schedule(isolate, obj, wrapper->handle_);

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

  auto operation = new PostMessageOperation(g_strdup("TODO"));
  operation->Schedule(isolate, obj, wrapper->handle_);

  args.GetReturnValue().Set(operation->GetPromise(isolate));
}

}
