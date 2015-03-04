#include "device.h"

#include "events.h"
#include "operation.h"
#include "process.h"
#include "session.h"

#include <node.h>

#define DEVICE_DATA_CONSTRUCTOR "device:ctor"

using v8::AccessorSignature;
using v8::Array;
using v8::DEFAULT;
using v8::Exception;
using v8::External;
using v8::Function;
using v8::FunctionCallbackInfo;
using v8::Handle;
using v8::HandleScope;
using v8::Integer;
using v8::Isolate;
using v8::Local;
using v8::None;
using v8::Object;
using v8::Persistent;
using v8::PropertyCallbackInfo;
using v8::String;
using v8::Value;

namespace frida {

Device::Device(FridaDevice* handle, Runtime* runtime)
    : GLibObject(handle, runtime) {
}

Device::~Device() {
  events_.Reset();
  frida_unref(handle_);
}

void Device::Init(Handle<Object> exports, Runtime* runtime) {
  auto isolate = Isolate::GetCurrent();

  auto name = String::NewFromUtf8(isolate, "Device");
  auto tpl = CreateTemplate(isolate, name, New, runtime);

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
  NODE_SET_PROTOTYPE_METHOD(tpl, "spawn", Spawn);
  NODE_SET_PROTOTYPE_METHOD(tpl, "resume", Resume);
  NODE_SET_PROTOTYPE_METHOD(tpl, "kill", Kill);
  NODE_SET_PROTOTYPE_METHOD(tpl, "attach", Attach);

  auto ctor = tpl->GetFunction();
  exports->Set(name, ctor);
  runtime->SetDataPointer(DEVICE_DATA_CONSTRUCTOR,
      new Persistent<Function>(isolate, ctor));
}

Local<Object> Device::New(gpointer handle, Runtime* runtime) {
  auto isolate = Isolate::GetCurrent();

  auto ctor = Local<Function>::New(isolate,
      *static_cast<Persistent<Function>*>(
      runtime->GetDataPointer(DEVICE_DATA_CONSTRUCTOR)));
  const int argc = 1;
  Local<Value> argv[argc] = { External::New(isolate, handle) };
  return ctor->NewInstance(argc, argv);
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
    auto runtime = GetRuntimeFromConstructorArgs(args);
    auto wrapper = new Device(static_cast<FridaDevice*>(
        Local<External>::Cast(args[0])->Value()), runtime);
    auto obj = args.This();
    wrapper->Wrap(obj);
    obj->Set(String::NewFromUtf8(isolate, "events"),
        Events::New(g_object_ref(wrapper->handle_), runtime));
    args.GetReturnValue().Set(obj);
  } else {
    args.GetReturnValue().Set(args.Callee()->NewInstance(0, NULL));
  }
}

void Device::GetId(Local<String> property,
    const PropertyCallbackInfo<Value>& info) {
  auto isolate = info.GetIsolate();
  HandleScope scope(isolate);
  auto handle = ObjectWrap::Unwrap<Device>(
      info.Holder())->GetHandle<FridaDevice>();

  info.GetReturnValue().Set(
      Integer::NewFromUnsigned(isolate, frida_device_get_id(handle)));
}

void Device::GetName(Local<String> property,
    const PropertyCallbackInfo<Value>& info) {
  auto isolate = info.GetIsolate();
  HandleScope scope(isolate);
  auto handle = ObjectWrap::Unwrap<Device>(
      info.Holder())->GetHandle<FridaDevice>();

  info.GetReturnValue().Set(
      String::NewFromUtf8(isolate, frida_device_get_name(handle)));
}

void Device::GetType(Local<String> property,
    const PropertyCallbackInfo<Value>& info) {
  auto isolate = info.GetIsolate();
  HandleScope scope(isolate);
  auto handle = ObjectWrap::Unwrap<Device>(
      info.Holder())->GetHandle<FridaDevice>();

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
    processes_ = frida_device_enumerate_processes_finish(handle_, result,
        error);
  }

  Local<Value> Result(Isolate* isolate) {
    auto size = frida_process_list_size(processes_);
    auto processes = Array::New(isolate, size);
    for (auto i = 0; i != size; i++) {
      auto process = Process::New(frida_process_list_get(processes_, i),
          runtime_);
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
  operation->Schedule(isolate, wrapper);

  args.GetReturnValue().Set(operation->GetPromise(isolate));
}

class SpawnOperation : public Operation<FridaDevice> {
 public:
  SpawnOperation(gchar* path, gchar** argv, gchar** envp)
    : path_(path),
      argv_(argv),
      envp_(envp) {
  }

  ~SpawnOperation() {
    g_strfreev(envp_);
    g_strfreev(argv_);
    g_free(path_);
  }

  void Begin() {
    frida_device_spawn(handle_, path_, argv_, g_strv_length(argv_),
        envp_, g_strv_length(envp_), OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    pid_ = frida_device_spawn_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    return Integer::NewFromUnsigned(isolate, pid_);
  }

  gchar* path_;
  gchar** argv_;
  gchar** envp_;
  guint pid_;
};

void Device::Spawn(const FunctionCallbackInfo<Value>& args) {
  auto isolate = args.GetIsolate();
  HandleScope scope(isolate);
  auto obj = args.Holder();
  auto wrapper = ObjectWrap::Unwrap<Device>(obj);

  gchar** argv = NULL;
  if (args.Length() >= 1) {
    if (args[0]->IsArray()) {
      auto elements = Local<Array>::Cast(args[0]);
      uint32_t length = elements->Length();
      argv = g_new0(gchar *, length + 1);
      for (uint32_t i = 0; i != length; i++) {
        auto element_value = elements->Get(i);
        if (element_value->IsString()) {
          String::Utf8Value element(Local<String>::Cast(element_value));
          argv[i] = g_strdup(*element);
        } else {
          g_strfreev(argv);
          argv = NULL;
          break;
        }
      }
    } else if (args[0]->IsString()) {
      String::Utf8Value command_line(Local<String>::Cast(args[0]));
      GError* error;
      if (!g_shell_parse_argv(*command_line, NULL, &argv, &error)) {
        gchar* message = g_strdup_printf("Bad argv string: %s", error->message);
        isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(
            isolate, message)));
        g_free(message);
        g_error_free(error);
        return;
      }
    }
  }
  if (argv == NULL) {
    isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate,
        "Bad argument, expected argv as a string or array of strings")));
    return;
  }

  gchar** envp = g_get_environ();

  gchar* path = g_strdup(argv[0]);

  auto operation = new SpawnOperation(path, argv, envp);
  operation->Schedule(isolate, wrapper);

  args.GetReturnValue().Set(operation->GetPromise(isolate));
}

class ResumeOperation : public Operation<FridaDevice> {
 public:
  ResumeOperation(guint pid) : pid_(pid) {
  }

  void Begin() {
    frida_device_resume(handle_, pid_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    frida_device_resume_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    return Undefined(isolate);
  }

  const guint pid_;
};

void Device::Resume(const FunctionCallbackInfo<Value>& args) {
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

  auto operation = new ResumeOperation(pid);
  operation->Schedule(isolate, wrapper);

  args.GetReturnValue().Set(operation->GetPromise(isolate));
}

class KillOperation : public Operation<FridaDevice> {
 public:
  KillOperation(guint pid) : pid_(pid) {
  }

  void Begin() {
    frida_device_kill(handle_, pid_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    frida_device_kill_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    return Undefined(isolate);
  }

  const guint pid_;
};

void Device::Kill(const FunctionCallbackInfo<Value>& args) {
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

  auto operation = new KillOperation(pid);
  operation->Schedule(isolate, wrapper);

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
    return Session::New(session_, runtime_);
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
  operation->Schedule(isolate, wrapper);

  args.GetReturnValue().Set(operation->GetPromise(isolate));
}

}
