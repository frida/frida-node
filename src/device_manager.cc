#include "device_manager.h"

#include "device.h"
#include "operation.h"
#include "signals.h"

#include <cstring>

#define DEVICE_MANAGER_DATA_WRAPPERS "device_manager:wrappers"

using std::strcmp;
using v8::Array;
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

  frida_unref(handle_);
}

void DeviceManager::Init(Local<Object> exports, Runtime* runtime) {
  Local<String> name = Nan::New("DeviceManager").ToLocalChecked();

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
  signals_wrapper->SetConnectCallback(OnConnect, runtime);
  signals_wrapper->SetDisconnectCallback(OnDisconnect, runtime);

  info.GetReturnValue().Set(obj);
}

namespace {

class CloseOperation : public Operation<FridaDeviceManager> {
 protected:
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
  auto wrapper = ObjectWrap::Unwrap<DeviceManager>(info.Holder());

  auto operation = new CloseOperation();
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

namespace {

class EnumerateDevicesOperation : public Operation<FridaDeviceManager> {
 protected:
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
    Local<Array> devices = Nan::New<Array>(size);
    for (auto i = 0; i != size; i++) {
      auto handle = frida_device_list_get(devices_, i);
      auto device = Device::New(handle, runtime_);
      Nan::Set(devices, i, device);
      g_object_unref(handle);
    }

    frida_unref(devices_);

    return devices;
  }

 private:
  FridaDeviceList* devices_;
};

}

NAN_METHOD(DeviceManager::EnumerateDevices) {
  auto isolate = info.GetIsolate();
  auto wrapper = ObjectWrap::Unwrap<DeviceManager>(info.Holder());

  auto operation = new EnumerateDevicesOperation();
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

namespace {

class AddRemoteDeviceOperation : public Operation<FridaDeviceManager> {
 public:
  AddRemoteDeviceOperation(gchar* address, FridaRemoteDeviceOptions* options)
    : address_(address),
      options_(options) {
  }

  ~AddRemoteDeviceOperation() {
    g_object_unref(options_);
    g_free(address_);
  }

 protected:
  void Begin() {
    frida_device_manager_add_remote_device(handle_, address_, options_,
        cancellable_, OnReady, this);
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

 private:
  gchar* address_;
  FridaRemoteDeviceOptions* options_;
  FridaDevice* device_;
};

}

NAN_METHOD(DeviceManager::AddRemoteDevice) {
  auto isolate = info.GetIsolate();
  auto wrapper = ObjectWrap::Unwrap<DeviceManager>(info.Holder());

  if (info.Length() < 5) {
    Nan::ThrowTypeError("Missing one or more arguments");
    return;
  }

  auto address_value = info[0];
  auto certificate_value = info[1];
  auto origin_value = info[2];
  auto token_value = info[3];
  auto keepalive_interval_value = info[4];

  if (!address_value->IsString()) {
    Nan::ThrowTypeError("Bad argument, 'address' must be a string");
    return;
  }
  Nan::Utf8String address(address_value);

  auto options = frida_remote_device_options_new();
  bool valid = true;

  if (!certificate_value->IsNull()) {
    GTlsCertificate* certificate;
    valid = Runtime::ValueToCertificate(certificate_value, &certificate);
    if (valid) {
      frida_remote_device_options_set_certificate(options, certificate);
      g_object_unref(certificate);
    }
  }

  if (valid && !origin_value->IsNull()) {
    if (origin_value->IsString()) {
      Nan::Utf8String origin(origin_value);
      frida_remote_device_options_set_origin(options, *origin);
    } else {
      Nan::ThrowTypeError("Bad argument, 'origin' must be a string");
      valid = false;
    }
  }

  if (valid && !token_value->IsNull()) {
    if (token_value->IsString()) {
      Nan::Utf8String token(token_value);
      frida_remote_device_options_set_token(options, *token);
    } else {
      Nan::ThrowTypeError("Bad argument, 'token' must be a string");
      valid = false;
    }
  }

  if (valid && !keepalive_interval_value->IsNull()) {
    if (keepalive_interval_value->IsNumber()) {
      auto keepalive_interval =
          Nan::To<int32_t>(keepalive_interval_value).FromMaybe(-1);
      if (keepalive_interval >= -1) {
        frida_remote_device_options_set_keepalive_interval(options,
            keepalive_interval);
      } else {
        Nan::ThrowTypeError("Bad argument, invalid 'keepaliveInterval'");
        valid = false;
      }
    } else {
      Nan::ThrowTypeError("Bad argument, 'keepaliveInterval' must be a number");
      valid = false;
    }
  }

  if (!valid) {
    g_object_unref(options);
    return;
  }

  auto operation = new AddRemoteDeviceOperation(g_strdup(*address), options);
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

namespace {

class RemoveRemoteDeviceOperation : public Operation<FridaDeviceManager> {
 public:
  RemoveRemoteDeviceOperation(gchar* address) : address_(address) {
  }

  ~RemoveRemoteDeviceOperation() {
    g_free(address_);
  }

 protected:
  void Begin() {
    frida_device_manager_remove_remote_device(handle_, address_, cancellable_,
        OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    frida_device_manager_remove_remote_device_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    return Nan::Undefined();
  }

 private:
  gchar* address_;
};

}

NAN_METHOD(DeviceManager::RemoveRemoteDevice) {
  auto isolate = info.GetIsolate();
  auto wrapper = ObjectWrap::Unwrap<DeviceManager>(info.Holder());

  if (info.Length() < 1 || !info[0]->IsString()) {
    Nan::ThrowTypeError("Expected an address");
    return;
  }

  Nan::Utf8String address(info[0]);

  auto operation = new RemoveRemoteDeviceOperation(g_strdup(*address));
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

void DeviceManager::OnConnect(const gchar* name, gpointer user_data) {
  auto runtime = static_cast<Runtime*>(user_data);

  if (ShouldStayAliveToEmit(name))
    runtime->GetUVContext()->IncreaseUsage();
}

void DeviceManager::OnDisconnect(const gchar* name, gpointer user_data) {
  auto runtime = static_cast<Runtime*>(user_data);

  if (ShouldStayAliveToEmit(name))
    runtime->GetUVContext()->DecreaseUsage();
}

bool DeviceManager::ShouldStayAliveToEmit(const gchar* name) {
  return strcmp(name, "added") == 0 ||
      strcmp(name, "removed") == 0 ||
      strcmp(name, "changed") == 0;
}

}
