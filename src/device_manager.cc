#include "device_manager.h"

#include "operation.h"

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

class EnumerateDevicesOperation : public Operation<DeviceManager> {
 public:
  void Begin() {
    frida_device_manager_enumerate_devices(wrapper_->handle_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    devices_ = frida_device_manager_enumerate_devices_finish(wrapper_->handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    auto size = frida_device_list_size(devices_);
    g_object_unref(devices_);
    return Number::New(isolate, size);
  }

  FridaDeviceList* devices_;
};

void DeviceManager::EnumerateDevices(const FunctionCallbackInfo<Value>& args) {
  auto isolate = Isolate::GetCurrent();
  HandleScope scope(isolate);
  auto wrapper = ObjectWrap::Unwrap<DeviceManager>(args.Holder());

  auto operation = new EnumerateDevicesOperation();
  operation->Schedule(isolate, wrapper);

  args.GetReturnValue().Set(operation->GetPromise(isolate));
}

}
