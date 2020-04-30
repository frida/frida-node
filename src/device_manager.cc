#include "device_manager.h"

#include "device.h"
#include "operation.h"
#include "signals.h"

#include <cstring>
#include <nan.h>
#include <node.h>

#define DEVICE_MANAGER_DATA_WRAPPERS "device_manager:wrappers"

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

  signals_.Reset();
  frida_unref(handle_);
}

void DeviceManager::Init(Local<Object> exports, Runtime* runtime) {
  Local<v8::String> name = Nan::New("DeviceManager").ToLocalChecked();

  auto tpl = CreateTemplate(name, DeviceManager::New, runtime);

  Nan::SetPrototypeMethod(tpl, "close", Close);
  Nan::SetPrototypeMethod(tpl, "enumerateDevices", EnumerateDevices);
  Nan::SetPrototypeMethod(tpl, "addRemoteDevice", AddRemoteDevice);
  Nan::SetPrototypeMethod(tpl, "removeRemoteDevice", RemoveRemoteDevice);

  Nan::Set(exports, name, Nan::GetFunction(tpl).ToLocalChecked());
}

void DeviceManager::Dispose(Runtime* runtime) {
  auto wrappers = static_cast<GSList*>(
      runtime->GetDataPointer(DEVICE_MANAGER_DATA_WRAPPERS));
  while (wrappers != NULL) {
    auto wrapper = static_cast<DeviceManager*>(wrappers->data);
    frida_device_manager_close_sync(wrapper->GetHandle<FridaDeviceManager>(),
        NULL, NULL);
    wrappers = g_slist_delete_link(wrappers, wrappers);
  }
  runtime->SetDataPointer(DEVICE_MANAGER_DATA_WRAPPERS, NULL);
}

NAN_METHOD(DeviceManager::New) {
  if (!info.IsConstructCall()) {
    Nan::ThrowError("Use the `new` keyword to create a new instance");
    return;
  }

  auto runtime = GetRuntimeFromConstructorArgs(info);

  auto handle = frida_device_manager_new();

  auto wrapper = new DeviceManager(handle, runtime);
  auto obj = info.This();
  wrapper->Wrap(obj);

  auto signals_obj = Signals::New(handle, runtime, TransformDeviceSignals,
      runtime);
  Nan::Set(obj, Nan::New("signals").ToLocalChecked(), signals_obj);

  g_object_unref(handle);

  auto signals_wrapper = ObjectWrap::Unwrap<Signals>(signals_obj);
  signals_wrapper->SetConnectCallback(OnConnect, wrapper);
  signals_wrapper->SetDisconnectCallback(OnDisconnect, wrapper);

  info.GetReturnValue().Set(obj);
}

namespace {

class CloseOperation : public Operation<FridaDeviceManager> {
 public:
  void Begin() {
    frida_device_manager_close(handle_, cancellable_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    frida_device_manager_close_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    return Nan::Undefined();
  }
};

}

NAN_METHOD(DeviceManager::Close) {
  auto isolate = info.GetIsolate();
  auto obj = info.Holder();
  auto wrapper = ObjectWrap::Unwrap<DeviceManager>(obj);

  auto operation = new CloseOperation();
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

namespace {

class EnumerateDevicesOperation : public Operation<FridaDeviceManager> {
 public:
  void Begin() {
    frida_device_manager_enumerate_devices(handle_, cancellable_, OnReady,
        this);
  }

  void End(GAsyncResult* result, GError** error) {
    devices_ = frida_device_manager_enumerate_devices_finish(handle_, result,
        error);
  }

  Local<Value> Result(Isolate* isolate) {
    auto size = frida_device_list_size(devices_);
    Local<v8::Array> devices = Nan::New<v8::Array>(size);
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

}

NAN_METHOD(DeviceManager::EnumerateDevices) {
  auto isolate = info.GetIsolate();
  auto obj = info.Holder();
  auto wrapper = ObjectWrap::Unwrap<DeviceManager>(obj);

  auto operation = new EnumerateDevicesOperation();
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

namespace {

class AddRemoteDeviceOperation : public Operation<FridaDeviceManager> {
 public:
  AddRemoteDeviceOperation(gchar* location) : location_(location) {
  }

  ~AddRemoteDeviceOperation() {
    g_free(location_);
  }

  void Begin() {
    frida_device_manager_add_remote_device(handle_, location_, cancellable_,
        OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    device_ = frida_device_manager_add_remote_device_finish(handle_, result,
        error);
  }

  Local<Value> Result(Isolate* isolate) {
    auto wrapper = Device::New(device_, runtime_);
    g_object_unref(device_);
    return wrapper;
  }

  gchar* location_;
  FridaDevice* device_;
};

}

NAN_METHOD(DeviceManager::AddRemoteDevice) {
  auto isolate = info.GetIsolate();
  auto obj = info.Holder();
  auto wrapper = ObjectWrap::Unwrap<DeviceManager>(obj);

  if (info.Length() < 1 || !info[0]->IsString()) {
    Nan::ThrowTypeError("Expected location");
    return;
  }

  Nan::Utf8String location(info[0]);

  auto operation = new AddRemoteDeviceOperation(g_strdup(*location));
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

namespace {

class RemoveRemoteDeviceOperation : public Operation<FridaDeviceManager> {
 public:
  RemoveRemoteDeviceOperation(gchar* location) : location_(location) {
  }

  ~RemoveRemoteDeviceOperation() {
    g_free(location_);
  }

  void Begin() {
    frida_device_manager_remove_remote_device(handle_, location_, cancellable_,
        OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    frida_device_manager_remove_remote_device_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    return Nan::Undefined();
  }

  gchar* location_;
};

}

NAN_METHOD(DeviceManager::RemoveRemoteDevice) {
  auto isolate = info.GetIsolate();
  auto obj = info.Holder();
  auto wrapper = ObjectWrap::Unwrap<DeviceManager>(obj);

  if (info.Length() < 1 || !info[0]->IsString()) {
    Nan::ThrowTypeError("Expected location");
    return;
  }

  Nan::Utf8String location(info[0]);

  auto operation = new RemoveRemoteDeviceOperation(g_strdup(*location));
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

Local<Value> DeviceManager::TransformDeviceSignals(const gchar* name,
    guint index, const GValue* value, gpointer user_data) {
  if (index == 0 && (strcmp(name, "added") == 0 ||
      strcmp(name, "removed") == 0)) {
    auto runtime = static_cast<Runtime*>(user_data);
    return Device::New(g_value_get_object(value), runtime);
  }
  return Local<Value>();
}

static bool IsDeviceChangeSignal(const gchar* name) {
  return strcmp(name, "added") == 0 ||
      strcmp(name, "removed") == 0 ||
      strcmp(name, "changed") == 0;
}

void DeviceManager::OnConnect(const gchar* name, gpointer user_data) {
  auto wrapper = static_cast<DeviceManager*>(user_data);

  if (IsDeviceChangeSignal(name)) {
    wrapper->runtime_->GetUVContext()->IncreaseUsage();
  }
}

void DeviceManager::OnDisconnect(const gchar* name, gpointer user_data) {
  auto wrapper = static_cast<DeviceManager*>(user_data);

  if (IsDeviceChangeSignal(name)) {
    wrapper->runtime_->GetUVContext()->DecreaseUsage();
  }
}

}
