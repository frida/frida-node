#include "device_manager.h"

#include "device.h"
#include "events.h"
#include "operation.h"

#include <cstring>
#include <nan.h>
#include <node.h>

#define DEVICE_MANAGER_DATA_WRAPPERS "device_manager:wrappers"

using v8::Array;
using v8::FunctionCallbackInfo;
using v8::Handle;
using v8::Isolate;
using v8::Local;
using v8::Object;
using v8::String;
using v8::Value;
using Nan::HandleScope;
using Nan::New;
using Nan::NewInstance;
using Nan::Set;

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

  Local<v8::String> name = Nan::New("DeviceManager").ToLocalChecked();

  auto tpl = CreateTemplate(isolate, name, DeviceManager::New, runtime);

  Nan::SetPrototypeMethod(tpl, "close", Close);
  Nan::SetPrototypeMethod(tpl, "enumerateDevices", EnumerateDevices);

  Nan::Set(exports, name, Nan::GetFunction(tpl).ToLocalChecked());
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

void DeviceManager::New(const Nan::FunctionCallbackInfo<Value>& info) {
  HandleScope();

  if (info.IsConstructCall()) {
    auto runtime = GetRuntimeFromConstructorArgs(info);

    auto handle = frida_device_manager_new();
    auto wrapper = new DeviceManager(handle, runtime);
    auto obj = info.This();
    wrapper->Wrap(obj);
    auto events_obj = Events::New(handle, runtime);

    Nan::Set(obj, Nan::New("events").ToLocalChecked(), events_obj);
    g_object_unref(handle);

    auto events_wrapper = ObjectWrap::Unwrap<Events>(events_obj);
    events_wrapper->SetListenCallback(OnListen, wrapper);
    events_wrapper->SetUnlistenCallback(OnUnlisten, wrapper);

    info.GetReturnValue().Set(obj);
  } else {
    info.GetReturnValue().Set(info.Callee()->NewInstance(0, NULL));
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

void DeviceManager::Close(const Nan::FunctionCallbackInfo<Value>& info) {
  HandleScope();

  auto isolate = info.GetIsolate();
  auto obj = info.Holder();
  auto wrapper = ObjectWrap::Unwrap<DeviceManager>(obj);

  auto operation = new CloseOperation();
  operation->Schedule(isolate, wrapper);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
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
      Nan::Set(devices, i, device);
      g_object_unref(handle);
    }

    frida_unref(devices_);

    return devices;
  }

  FridaDeviceList* devices_;
};

void DeviceManager::EnumerateDevices(const Nan::FunctionCallbackInfo<Value>& info) {
  HandleScope();

  auto isolate = info.GetIsolate();
  auto obj = info.Holder();
  auto wrapper = ObjectWrap::Unwrap<DeviceManager>(obj);

  auto operation = new EnumerateDevicesOperation();
  operation->Schedule(isolate, wrapper);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
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
