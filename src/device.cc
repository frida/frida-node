#include "device.h"

#include "events.h"
#include "operation.h"
#include "process.h"
#include "session.h"

using v8::AccessorSignature;
using v8::Array;
using v8::DEFAULT;
using v8::Exception;
using v8::External;
using v8::Function;
using v8::FunctionCallbackInfo;
using v8::FunctionTemplate;
using v8::Handle;
using v8::HandleScope;
using v8::Integer;
using v8::Isolate;
using v8::Local;
using v8::None;
using v8::Number;
using v8::Object;
using v8::Persistent;
using v8::PropertyCallbackInfo;
using v8::String;
using v8::Value;

namespace frida {

Persistent<Function> Device::constructor_;

Device::Device(FridaDevice* handle)
    : handle_(handle) {
}

Device::~Device() {
  events_.Reset();
  frida_unref(handle_);
}

void Device::Init(Handle<Object> exports) {
  auto isolate = Isolate::GetCurrent();

  auto tpl = FunctionTemplate::New(isolate, New);
  tpl->SetClassName(String::NewFromUtf8(isolate, "Device"));
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  auto instance_tpl = tpl->InstanceTemplate();
  auto data = Handle<Value>();
  auto signature = AccessorSignature::New(isolate, tpl);
  instance_tpl->SetAccessor(String::NewFromUtf8(isolate, "id"), GetId, 0,
      data, DEFAULT, None, signature);
  instance_tpl->SetAccessor(String::NewFromUtf8(isolate, "name"), GetName, 0,
      data, DEFAULT, None, signature);
  instance_tpl->SetAccessor(String::NewFromUtf8(isolate, "type"), GetType, 0,
      data, DEFAULT, None, signature);

  NODE_SET_PROTOTYPE_METHOD(tpl, "enumerateProcesses", EnumerateProcesses);
  NODE_SET_PROTOTYPE_METHOD(tpl, "attach", Attach);

  exports->Set(String::NewFromUtf8(isolate, "Device"),
      tpl->GetFunction());

  constructor_.Reset(isolate, tpl->GetFunction());
}

Local<Object> Device::Create(gpointer handle) {
  auto isolate = Isolate::GetCurrent();

  auto constructor = Local<Function>::New(isolate, constructor_);
  const int argc = 1;
  Local<Value> argv[argc] = { External::New(isolate, handle) };
  return constructor->NewInstance(argc, argv);
}

void Device::New(const FunctionCallbackInfo<Value>& args) {
  auto isolate = args.GetIsolate();
  HandleScope scope(isolate);

  if (args.IsConstructCall()) {
    if (args.Length() != 1 || !args[0]->IsExternal()) {
      isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate,
          "Bad argument, expected raw handle")));
      return;
    }
    auto wrapper = new Device(static_cast<FridaDevice*>(
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

void Device::GetId(Local<String> property,
    const PropertyCallbackInfo<Value>& info) {
  auto isolate = info.GetIsolate();
  HandleScope scope(isolate);
  auto handle = ObjectWrap::Unwrap<Device>(info.Holder())->handle_;

  info.GetReturnValue().Set(
      Integer::NewFromUnsigned(isolate, frida_device_get_id(handle)));
}

void Device::GetName(Local<String> property,
    const PropertyCallbackInfo<Value>& info) {
  auto isolate = info.GetIsolate();
  HandleScope scope(isolate);
  auto handle = ObjectWrap::Unwrap<Device>(info.Holder())->handle_;

  info.GetReturnValue().Set(
      String::NewFromUtf8(isolate, frida_device_get_name(handle)));
}

void Device::GetType(Local<String> property,
    const PropertyCallbackInfo<Value>& info) {
  auto isolate = info.GetIsolate();
  HandleScope scope(isolate);
  auto handle = ObjectWrap::Unwrap<Device>(info.Holder())->handle_;

  const gchar* type;
  switch (frida_device_get_dtype(handle)) {
    case FRIDA_DEVICE_TYPE_LOCAL:
      type = "local";
      break;
    case FRIDA_DEVICE_TYPE_TETHER:
      type = "tether";
      break;
    case FRIDA_DEVICE_TYPE_REMOTE:
      type = "remote";
      break;
    default:
      g_assert_not_reached();
  }
  info.GetReturnValue().Set(String::NewFromUtf8(isolate, type));
}

class EnumerateProcessesOperation : public Operation<FridaDevice> {
 public:
  void Begin() {
    frida_device_enumerate_processes(handle_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    processes_ = frida_device_enumerate_processes_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    auto size = frida_process_list_size(processes_);
    auto processes = Array::New(isolate, size);
    for (auto i = 0; i != size; i++) {
      auto process = Process::Create(frida_process_list_get(processes_, i));
      processes->Set(i, process);
    }

    g_object_unref(processes_);

    return processes;
  }

  FridaProcessList* processes_;
};

void Device::EnumerateProcesses(const FunctionCallbackInfo<Value>& args) {
  auto isolate = args.GetIsolate();
  HandleScope scope(isolate);
  auto obj = args.Holder();
  auto wrapper = ObjectWrap::Unwrap<Device>(obj);

  auto operation = new EnumerateProcessesOperation();
  operation->Schedule(isolate, obj, wrapper->handle_);

  args.GetReturnValue().Set(operation->GetPromise(isolate));
}

class AttachOperation : public Operation<FridaDevice> {
 public:
  AttachOperation(guint pid) : pid_(pid) {
  }

  void Begin() {
    frida_device_attach(handle_, pid_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    session_ = frida_device_attach_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    return Session::Create(session_);
  }

  const guint pid_;
  FridaSession* session_;
};

void Device::Attach(const FunctionCallbackInfo<Value>& args) {
  auto isolate = args.GetIsolate();
  HandleScope scope(isolate);
  auto obj = args.Holder();
  auto wrapper = ObjectWrap::Unwrap<Device>(obj);

  if (args.Length() < 1 || !args[0]->IsNumber()) {
    isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate,
        "Bad argument, expected pid")));
    return;
  }
  auto pid = args[0]->ToInteger()->Value();
  if (pid <= 0) {
    isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate,
        "Bad argument, expected pid")));
    return;
  }

  auto operation = new AttachOperation(pid);
  operation->Schedule(isolate, obj, wrapper->handle_);

  args.GetReturnValue().Set(operation->GetPromise(isolate));
}

}
