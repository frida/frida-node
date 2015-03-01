#include "device_manager.h"

using namespace v8;

namespace frida {

Persistent<Function> DeviceManager::constructor;

DeviceManager::DeviceManager(FridaDeviceManager* handle) : handle_(handle) {
}

DeviceManager::~DeviceManager() {
  g_object_unref(handle_);
}

void DeviceManager::Init(Handle<Object> exports) {
  auto isolate = Isolate::GetCurrent();

  auto tpl = FunctionTemplate::New(isolate, New);
  tpl->SetClassName(String::NewFromUtf8(isolate, "DeviceManager"));
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  NODE_SET_PROTOTYPE_METHOD(tpl, "enumerateDevices", EnumerateDevices);

  constructor.Reset(isolate, tpl->GetFunction());
  exports->Set(String::NewFromUtf8(isolate, "DeviceManager"),
               tpl->GetFunction());
}

void DeviceManager::New(const FunctionCallbackInfo<Value>& args) {
  auto isolate = Isolate::GetCurrent();
  HandleScope scope(isolate);

  if (args.IsConstructCall()) {
    auto obj = new DeviceManager(frida_device_manager_new());
    obj->Wrap(args.This());
    args.GetReturnValue().Set(args.This());
  } else {
    auto cons = Local<Function>::New(isolate, constructor);
    args.GetReturnValue().Set(cons->NewInstance(0, 0));
  }
}

void DeviceManager::EnumerateDevices(const FunctionCallbackInfo<Value>& args) {
  auto isolate = Isolate::GetCurrent();
  HandleScope scope(isolate);
  auto self = ObjectWrap::Unwrap<DeviceManager>(args.Holder());
  auto resolver = Promise::Resolver::New(isolate);

  args.GetReturnValue().Set(resolver->GetPromise());
}

}
