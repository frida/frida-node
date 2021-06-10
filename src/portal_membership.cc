#include "portal_membership.h"

#include "operation.h"

#define PORTAL_MEMBERSHIP_DATA_CONSTRUCTOR "portal_membership:ctor"

using v8::External;
using v8::Function;
using v8::Isolate;
using v8::Local;
using v8::Object;
using v8::Persistent;
using v8::Value;

namespace frida {

PortalMembership::PortalMembership(FridaPortalMembership* handle, Runtime* runtime)
    : GLibObject(handle, runtime) {
  g_object_ref(handle_);
}

PortalMembership::~PortalMembership() {
  frida_unref(handle_);
}

void PortalMembership::Init(Local<Object> exports, Runtime* runtime) {
  auto isolate = Isolate::GetCurrent();

  auto name = Nan::New("PortalMembership").ToLocalChecked();
  auto tpl = CreateTemplate(name, New, runtime);

  Nan::SetPrototypeMethod(tpl, "terminate", Terminate);

  auto ctor = Nan::GetFunction(tpl).ToLocalChecked();
  Nan::Set(exports, name, ctor);
  runtime->SetDataPointer(PORTAL_MEMBERSHIP_DATA_CONSTRUCTOR,
      new Persistent<Function>(isolate, ctor));
}

Local<Object> PortalMembership::New(gpointer handle, Runtime* runtime) {
  auto ctor = Nan::New<Function>(
      *static_cast<Persistent<Function>*>(
      runtime->GetDataPointer(PORTAL_MEMBERSHIP_DATA_CONSTRUCTOR)));
  const int argc = 1;
  Local<Value> argv[argc] = { Nan::New<External>(handle) };
  return Nan::NewInstance(ctor, argc, argv).ToLocalChecked();
}

NAN_METHOD(PortalMembership::New) {
  if (!info.IsConstructCall()) {
    Nan::ThrowError("Use the `new` keyword to create a new instance");
    return;
  }

  if (info.Length() != 1 || !info[0]->IsExternal()) {
    Nan::ThrowTypeError("Bad argument, expected raw handle");
    return;
  }

  auto runtime = GetRuntimeFromConstructorArgs(info);

  auto handle = static_cast<FridaPortalMembership*>(
      Local<External>::Cast(info[0])->Value());
  auto wrapper = new PortalMembership(handle, runtime);
  auto obj = info.This();
  wrapper->Wrap(obj);

  info.GetReturnValue().Set(obj);
}

namespace {

class TerminateOperation : public Operation<FridaPortalMembership> {
 protected:
  void Begin() {
    frida_portal_membership_terminate(handle_, cancellable_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    frida_portal_membership_terminate_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    return Nan::Undefined();
  }
};

}

NAN_METHOD(PortalMembership::Terminate) {
  auto isolate = info.GetIsolate();
  auto wrapper = ObjectWrap::Unwrap<PortalMembership>(info.Holder());

  auto operation = new TerminateOperation();
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

}
