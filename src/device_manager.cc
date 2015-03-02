#include "device_manager.h"

#include "events.h"
#include "operation.h"

using namespace v8;

namespace frida {

Persistent<Function> DeviceManager::constructor_;

DeviceManager::DeviceManager(FridaDeviceManager* handle)
    : handle_(handle) {
}

DeviceManager::~DeviceManager() {
  events_.Reset();
  frida_unref(handle_);
}

void DeviceManager::Init(Handle<Object> exports) {
  auto isolate = Isolate::GetCurrent();

  auto tpl = FunctionTemplate::New(isolate, New);
  tpl->SetClassName(String::NewFromUtf8(isolate, "DeviceManager"));
  tpl->InstanceTemplate()->SetInternalFieldCount(1);
  NODE_SET_PROTOTYPE_METHOD(tpl, "enumerateDevices", EnumerateDevices);
  exports->Set(String::NewFromUtf8(isolate, "DeviceManager"),
      tpl->GetFunction());

  constructor_.Reset(isolate, tpl->GetFunction());
}

void DeviceManager::New(const FunctionCallbackInfo<Value>& args) {
  auto isolate = args.GetIsolate();
  HandleScope scope(isolate);

  if (args.IsConstructCall()) {
    auto wrapper = new DeviceManager(frida_device_manager_new());
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

class EnumerateDevicesOperation : public Operation<FridaDeviceManager> {
 public:
  void Begin() {
    frida_device_manager_enumerate_devices(handle_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    devices_ = frida_device_manager_enumerate_devices_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    auto size = frida_device_list_size(devices_);
    g_object_unref(devices_);
    return Number::New(isolate, size);
  }

  FridaDeviceList* devices_;
};

void DeviceManager::EnumerateDevices(const FunctionCallbackInfo<Value>& args) {
  auto isolate = args.GetIsolate();
  HandleScope scope(isolate);
  auto obj = args.Holder();
  auto wrapper = ObjectWrap::Unwrap<DeviceManager>(obj);

  auto operation = new EnumerateDevicesOperation();
  operation->Schedule(isolate, obj, wrapper->handle_);

  args.GetReturnValue().Set(operation->GetPromise(isolate));
}

}
