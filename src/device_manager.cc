#include "device_manager.h"

#include "device.h"
#include "events.h"
#include "operation.h"

#include <node.h>

#define DEVICE_MANAGER_DATA_WRAPPERS "device_manager:wrappers"

using v8::Array;
using v8::FunctionCallbackInfo;
using v8::Handle;
using v8::HandleScope;
using v8::Isolate;
using v8::Local;
using v8::Object;
using v8::String;
using v8::Value;

namespace frida {

DeviceManager::DeviceManager(FridaDeviceManager* handle, Runtime* runtime)
    : GLibObject(handle, runtime) {
  g_object_ref(handle_);

  runtime_->SetDataPointer(DEVICE_MANAGER_DATA_WRAPPERS, g_slist_prepend(
      static_cast<GSList*>(
      runtime_->GetDataPointer(DEVICE_MANAGER_DATA_WRAPPERS)), this));
}

DeviceManager::~DeviceManager() {
  runtime_->SetDataPointer(DEVICE_MANAGER_DATA_WRAPPERS, g_slist_remove(
      static_cast<GSList*>(
      runtime_->GetDataPointer(DEVICE_MANAGER_DATA_WRAPPERS)), this));

  events_.Reset();
  frida_unref(handle_);
}

void DeviceManager::Init(Handle<Object> exports, Runtime* runtime) {
  auto isolate = Isolate::GetCurrent();

  auto name = String::NewFromUtf8(isolate, "DeviceManager");
  auto tpl = CreateTemplate(isolate, name, New, runtime);

  NODE_SET_PROTOTYPE_METHOD(tpl, "close", Close);
  NODE_SET_PROTOTYPE_METHOD(tpl, "enumerateDevices", EnumerateDevices);

  exports->Set(name, tpl->GetFunction());
}

void DeviceManager::Dispose(Runtime* runtime) {
  auto wrappers = static_cast<GSList*>(
      runtime->GetDataPointer(DEVICE_MANAGER_DATA_WRAPPERS));
  while (wrappers != NULL) {
    auto wrapper = static_cast<DeviceManager*>(wrappers->data);
    frida_device_manager_close_sync(wrapper->GetHandle<FridaDeviceManager>());
    wrappers = g_slist_delete_link(wrappers, wrappers);
  }
  runtime->SetDataPointer(DEVICE_MANAGER_DATA_WRAPPERS, NULL);
}

void DeviceManager::New(const FunctionCallbackInfo<Value>& args) {
  auto isolate = args.GetIsolate();
  HandleScope scope(isolate);

  if (args.IsConstructCall()) {
    auto runtime = GetRuntimeFromConstructorArgs(args);

    auto handle = frida_device_manager_new();
    auto wrapper = new DeviceManager(handle, runtime);
    auto obj = args.This();
    wrapper->Wrap(obj);
    auto events_obj = Events::New(handle, runtime);
    obj->Set(String::NewFromUtf8(isolate, "events"), events_obj);
    g_object_unref(handle);

    auto events_wrapper = ObjectWrap::Unwrap<Events>(events_obj);
    events_wrapper->SetListenCallback(OnListen, wrapper);
    events_wrapper->SetUnlistenCallback(OnUnlisten, wrapper);

    args.GetReturnValue().Set(obj);
  } else {
    args.GetReturnValue().Set(args.Callee()->NewInstance(0, NULL));
  }
}

class CloseOperation : public Operation<FridaDeviceManager> {
 public:
  void Begin() {
    frida_device_manager_close(handle_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    frida_device_manager_close_finish(handle_, result);
  }

  Local<Value> Result(Isolate* isolate) {
    return Undefined(isolate);
  }
};

void DeviceManager::Close(const FunctionCallbackInfo<Value>& args) {
  auto isolate = args.GetIsolate();
  HandleScope scope(isolate);
  auto obj = args.Holder();
  auto wrapper = ObjectWrap::Unwrap<DeviceManager>(obj);

  auto operation = new CloseOperation();
  operation->Schedule(isolate, wrapper);

  args.GetReturnValue().Set(operation->GetPromise(isolate));
}

class EnumerateDevicesOperation : public Operation<FridaDeviceManager> {
 public:
  void Begin() {
    frida_device_manager_enumerate_devices(handle_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    devices_ = frida_device_manager_enumerate_devices_finish(handle_, result,
        error);
  }

  Local<Value> Result(Isolate* isolate) {
    auto size = frida_device_list_size(devices_);
    auto devices = Array::New(isolate, size);
    for (auto i = 0; i != size; i++) {
      auto handle = frida_device_list_get(devices_, i);
      auto device = Device::New(handle, runtime_);
      devices->Set(i, device);
      g_object_unref(handle);
    }

    frida_unref(devices_);

    return devices;
  }

  FridaDeviceList* devices_;
};

void DeviceManager::EnumerateDevices(const FunctionCallbackInfo<Value>& args) {
  auto isolate = args.GetIsolate();
  HandleScope scope(isolate);
  auto obj = args.Holder();
  auto wrapper = ObjectWrap::Unwrap<DeviceManager>(obj);

  auto operation = new EnumerateDevicesOperation();
  operation->Schedule(isolate, wrapper);

  args.GetReturnValue().Set(operation->GetPromise(isolate));
}

void DeviceManager::OnListen(const gchar* signal, gpointer user_data) {
  auto wrapper = static_cast<DeviceManager*>(user_data);

  if (strcmp(signal, "changed") == 0) {
    wrapper->runtime_->GetUVContext()->IncreaseUsage();
  }
}

void DeviceManager::OnUnlisten(const gchar* signal, gpointer user_data) {
  auto wrapper = static_cast<DeviceManager*>(user_data);

  if (strcmp(signal, "changed") == 0) {
    wrapper->runtime_->GetUVContext()->DecreaseUsage();
  }
}

}
