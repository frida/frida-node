#include "device.h"

#include "application.h"
#include "child.h"
#include "crash.h"
#include "icon.h"
#include "operation.h"
#include "process.h"
#include "session.h"
#include "signals.h"
#include "spawn.h"

#include <nan.h>
#include <node.h>

#define DEVICE_DATA_CONSTRUCTOR "device:ctor"

using v8::AccessorSignature;
using v8::Array;
using v8::Boolean;
using v8::DEFAULT;
using v8::External;
using v8::Function;
using v8::Handle;
using v8::Isolate;
using v8::Local;
using v8::Number;
using v8::Object;
using v8::ReadOnly;
using v8::String;
using v8::Value;

namespace frida {

Device::Device(FridaDevice* handle, Runtime* runtime)
    : GLibObject(handle, runtime) {
  g_object_ref(handle_);
}

Device::~Device() {
  signals_.Reset();
  frida_unref(handle_);
}

void Device::Init(Handle<Object> exports, Runtime* runtime) {
  auto isolate = Isolate::GetCurrent();

  auto name = Nan::New("Device").ToLocalChecked();
  auto tpl = CreateTemplate(name, New, runtime);

  auto instance_tpl = tpl->InstanceTemplate();
  auto data = Handle<Value>();
  auto signature = AccessorSignature::New(isolate, tpl);
  Nan::SetAccessor(instance_tpl, Nan::New("type").ToLocalChecked(), GetType, 0,
      data, DEFAULT, ReadOnly, signature);
  Nan::SetAccessor(instance_tpl, Nan::New("icon").ToLocalChecked(), GetIcon, 0,
      data, DEFAULT, ReadOnly, signature);
  Nan::SetAccessor(instance_tpl, Nan::New("name").ToLocalChecked(), GetName, 0,
      data, DEFAULT, ReadOnly, signature);
  Nan::SetAccessor(instance_tpl, Nan::New("id").ToLocalChecked(), GetId, 0,
      data, DEFAULT, ReadOnly, signature);

  Nan::SetPrototypeMethod(tpl, "getFrontmostApplication",
      GetFrontmostApplication);
  Nan::SetPrototypeMethod(tpl, "enumerateApplications", EnumerateApplications);
  Nan::SetPrototypeMethod(tpl, "enumerateProcesses", EnumerateProcesses);
  Nan::SetPrototypeMethod(tpl, "enableSpawnGating", EnableSpawnGating);
  Nan::SetPrototypeMethod(tpl, "disableSpawnGating", DisableSpawnGating);
  Nan::SetPrototypeMethod(tpl, "enumeratePendingSpawn", EnumeratePendingSpawn);
  Nan::SetPrototypeMethod(tpl, "enumeratePendingChildren",
      EnumeratePendingChildren);
  Nan::SetPrototypeMethod(tpl, "spawn", Spawn);
  Nan::SetPrototypeMethod(tpl, "input", Input);
  Nan::SetPrototypeMethod(tpl, "resume", Resume);
  Nan::SetPrototypeMethod(tpl, "kill", Kill);
  Nan::SetPrototypeMethod(tpl, "attach", Attach);
  Nan::SetPrototypeMethod(tpl, "injectLibraryFile", InjectLibraryFile);
  Nan::SetPrototypeMethod(tpl, "injectLibraryBlob", InjectLibraryBlob);

  auto ctor = Nan::GetFunction(tpl).ToLocalChecked();
  Nan::Set(exports, name, ctor);
  runtime->SetDataPointer(DEVICE_DATA_CONSTRUCTOR,
      new v8::Persistent<v8::Function>(isolate, ctor));
}

Local<Object> Device::New(gpointer handle, Runtime* runtime) {
  auto ctor = Nan::New<Function>(
      *static_cast<v8::Persistent<Function>*>(
      runtime->GetDataPointer(DEVICE_DATA_CONSTRUCTOR)));
  const int argc = 1;
  Local<Value> argv[argc] = { Nan::New<v8::External>(handle) };
  return Nan::NewInstance(ctor, argc, argv).ToLocalChecked();
}

NAN_METHOD(Device::New) {
  if (!info.IsConstructCall()) {
    Nan::ThrowError("Use the `new` keyword to create a new instance");
    return;
  }

  if (info.Length() != 1 || !info[0]->IsExternal()) {
    Nan::ThrowTypeError("Bad argument, expected raw handle");
    return;
  }

  auto runtime = GetRuntimeFromConstructorArgs(info);

  auto handle = static_cast<FridaDevice*>(
      Local<External>::Cast(info[0])->Value());
  auto wrapper = new Device(handle, runtime);
  auto obj = info.This();
  wrapper->Wrap(obj);
  auto signals_obj = Signals::New(handle, runtime, TransformSignal, wrapper);

  Nan::Set(obj, Nan::New("signals").ToLocalChecked(), signals_obj);

  auto signals_wrapper = ObjectWrap::Unwrap<Signals>(signals_obj);
  signals_wrapper->SetConnectCallback(OnConnect, wrapper);
  signals_wrapper->SetDisconnectCallback(OnDisconnect, wrapper);

  info.GetReturnValue().Set(obj);
}

NAN_PROPERTY_GETTER(Device::GetId) {
  auto handle = ObjectWrap::Unwrap<Device>(
      info.Holder())->GetHandle<FridaDevice>();

  info.GetReturnValue().Set(
      Nan::New(frida_device_get_id(handle)).ToLocalChecked());
}

NAN_PROPERTY_GETTER(Device::GetName) {
  auto handle = ObjectWrap::Unwrap<Device>(
      info.Holder())->GetHandle<FridaDevice>();

  info.GetReturnValue().Set(
      Nan::New(frida_device_get_name(handle)).ToLocalChecked());
}

NAN_PROPERTY_GETTER(Device::GetIcon) {
  auto wrapper = ObjectWrap::Unwrap<Device>(info.Holder());
  auto handle = wrapper->GetHandle<FridaDevice>();

  info.GetReturnValue().Set(Icon::New(frida_device_get_icon(handle),
      wrapper->runtime_));
}

NAN_PROPERTY_GETTER(Device::GetType) {
  auto handle = ObjectWrap::Unwrap<Device>(
      info.Holder())->GetHandle<FridaDevice>();

  info.GetReturnValue().Set(Runtime::ValueFromEnum(
      frida_device_get_dtype(handle), FRIDA_TYPE_DEVICE_TYPE));
}

class GetFrontmostApplicationOperation : public Operation<FridaDevice> {
 public:
  void Begin() {
    frida_device_get_frontmost_application(handle_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    application_ = frida_device_get_frontmost_application_finish(handle_,
        result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    if (application_ != NULL) {
      auto application = Application::New(application_, runtime_);
      g_object_unref(application_);
      return application;
    } else {
      return Nan::Null();
    }
  }

  FridaApplication* application_;
};

NAN_METHOD(Device::GetFrontmostApplication) {
  auto isolate = info.GetIsolate();
  auto obj = info.Holder();
  auto wrapper = ObjectWrap::Unwrap<Device>(obj);

  auto operation = new GetFrontmostApplicationOperation();
  operation->Schedule(isolate, wrapper);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

class EnumerateApplicationsOperation : public Operation<FridaDevice> {
 public:
  void Begin() {
    frida_device_enumerate_applications(handle_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    applications_ = frida_device_enumerate_applications_finish(handle_, result,
        error);
  }

  Local<Value> Result(Isolate* isolate) {
    auto size = frida_application_list_size(applications_);
    auto applications = Nan::New<v8::Array>(size);
    for (auto i = 0; i != size; i++) {
      auto handle = frida_application_list_get(applications_, i);
      auto application = Application::New(handle, runtime_);
      Nan::Set(applications, i, application);
      g_object_unref(handle);
    }

    g_object_unref(applications_);

    return applications;
  }

  FridaApplicationList* applications_;
};

NAN_METHOD(Device::EnumerateApplications) {
  auto isolate = info.GetIsolate();
  auto obj = info.Holder();
  auto wrapper = ObjectWrap::Unwrap<Device>(obj);

  auto operation = new EnumerateApplicationsOperation();
  operation->Schedule(isolate, wrapper);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
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
    auto processes = Nan::New<v8::Array>(size);
    for (auto i = 0; i != size; i++) {
      auto handle = frida_process_list_get(processes_, i);
      auto process = Process::New(handle, runtime_);
      Nan::Set(processes, i, process);
      g_object_unref(handle);
    }

    g_object_unref(processes_);

    return processes;
  }

  FridaProcessList* processes_;
};

NAN_METHOD(Device::EnumerateProcesses) {
  auto isolate = info.GetIsolate();
  auto obj = info.Holder();
  auto wrapper = ObjectWrap::Unwrap<Device>(obj);

  auto operation = new EnumerateProcessesOperation();
  operation->Schedule(isolate, wrapper);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

class EnableSpawnGatingOperation : public Operation<FridaDevice> {
 public:
  void Begin() {
    frida_device_enable_spawn_gating(handle_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    frida_device_enable_spawn_gating_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    return Nan::Undefined();
  }
};

NAN_METHOD(Device::EnableSpawnGating) {
  auto isolate = info.GetIsolate();
  auto obj = info.Holder();
  auto wrapper = ObjectWrap::Unwrap<Device>(obj);

  auto operation = new EnableSpawnGatingOperation();
  operation->Schedule(isolate, wrapper);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

class DisableSpawnGatingOperation : public Operation<FridaDevice> {
 public:
  void Begin() {
    frida_device_disable_spawn_gating(handle_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    frida_device_disable_spawn_gating_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    return Nan::Undefined();
  }
};

NAN_METHOD(Device::DisableSpawnGating) {
  auto isolate = info.GetIsolate();
  auto obj = info.Holder();
  auto wrapper = ObjectWrap::Unwrap<Device>(obj);

  auto operation = new DisableSpawnGatingOperation();
  operation->Schedule(isolate, wrapper);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

class EnumeratePendingSpawnOperation : public Operation<FridaDevice> {
 public:
  void Begin() {
    frida_device_enumerate_pending_spawn(handle_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    pending_spawn_ = frida_device_enumerate_pending_spawn_finish(handle_,
        result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    auto size = frida_spawn_list_size(pending_spawn_);
    auto pending_spawn = Nan::New<v8::Array>(size);
    for (auto i = 0; i != size; i++) {
      auto handle = frida_spawn_list_get(pending_spawn_, i);
      auto spawn = Spawn::New(handle, runtime_);
      Nan::Set(pending_spawn, i, spawn);
      g_object_unref(handle);
    }

    g_object_unref(pending_spawn_);

    return pending_spawn;
  }

  FridaSpawnList* pending_spawn_;
};

NAN_METHOD(Device::EnumeratePendingSpawn) {
  auto isolate = info.GetIsolate();
  auto obj = info.Holder();
  auto wrapper = ObjectWrap::Unwrap<Device>(obj);

  auto operation = new EnumeratePendingSpawnOperation();
  operation->Schedule(isolate, wrapper);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

class EnumeratePendingChildrenOperation : public Operation<FridaDevice> {
 public:
  void Begin() {
    frida_device_enumerate_pending_children(handle_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    pending_children_ = frida_device_enumerate_pending_children_finish(handle_,
        result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    auto size = frida_child_list_size(pending_children_);
    auto pending_children = Nan::New<v8::Array>(size);
    for (auto i = 0; i != size; i++) {
      auto handle = frida_child_list_get(pending_children_, i);
      auto child = Child::New(handle, runtime_);
      Nan::Set(pending_children, i, child);
      g_object_unref(handle);
    }

    g_object_unref(pending_children_);

    return pending_children;
  }

  FridaChildList* pending_children_;
};

NAN_METHOD(Device::EnumeratePendingChildren) {
  auto isolate = info.GetIsolate();
  auto obj = info.Holder();
  auto wrapper = ObjectWrap::Unwrap<Device>(obj);

  auto operation = new EnumeratePendingChildrenOperation();
  operation->Schedule(isolate, wrapper);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

class SpawnOperation : public Operation<FridaDevice> {
 public:
  SpawnOperation(gchar* program, FridaSpawnOptions* options)
    : program_(program),
      options_(options) {
  }

  ~SpawnOperation() {
    g_object_unref(options_);
    g_free(program_);
  }

  void Begin() {
    frida_device_spawn(handle_, program_, options_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    pid_ = frida_device_spawn_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    return Nan::New<v8::Uint32>(pid_);
  }

  gchar* program_;
  FridaSpawnOptions* options_;
  guint pid_;
};

NAN_METHOD(Device::Spawn) {
  auto isolate = info.GetIsolate();
  auto context = isolate->GetCurrentContext();
  auto obj = info.Holder();
  auto wrapper = ObjectWrap::Unwrap<Device>(obj);

  if (info.Length() < 7) {
    Nan::ThrowTypeError("Missing one or more arguments");
    return;
  }

  auto program_value = info[0];
  auto argv_value = info[1];
  auto envp_value = info[2];
  auto env_value = info[3];
  auto cwd_value = info[4];
  auto stdio_value = info[5];
  auto aux_value = info[6];

  if (!program_value->IsString()) {
    Nan::ThrowTypeError("Bad argument, 'program' must be a string");
    return;
  }
  Nan::Utf8String program(Local<String>::Cast(program_value));

  auto options = frida_spawn_options_new();
  bool valid = true;

  if (!argv_value->IsNull()) {
    gchar** argv;
    gint argv_length;
    valid = Runtime::ValueToStrv(argv_value, &argv, &argv_length);
    if (valid) {
      frida_spawn_options_set_argv(options, argv, argv_length);
      g_strfreev(argv);
    }
  }

  if (valid && !envp_value->IsNull()) {
    gchar** envp;
    gint envp_length;
    valid = Runtime::ValueToEnvp(envp_value, &envp, &envp_length);
    if (valid) {
      frida_spawn_options_set_envp(options, envp, envp_length);
      g_strfreev(envp);
    }
  }

  if (valid && !env_value->IsNull()) {
    gchar** env;
    gint env_length;
    valid = Runtime::ValueToEnvp(env_value, &env, &env_length);
    if (valid) {
      frida_spawn_options_set_env(options, env, env_length);
      g_strfreev(env);
    }
  }

  if (valid && !cwd_value->IsNull()) {
    if (cwd_value->IsString()) {
      Nan::Utf8String cwd(Local<String>::Cast(cwd_value));
      frida_spawn_options_set_cwd(options, *cwd);
    } else {
      Nan::ThrowTypeError("Bad argument, 'cwd' must be a string");
      valid = false;
    }
  }

  if (valid && !stdio_value->IsNull()) {
    FridaStdio stdio;
    valid = Runtime::ValueToEnum(stdio_value, FRIDA_TYPE_STDIO, &stdio);
    if (valid)
      frida_spawn_options_set_stdio(options, stdio);
  }

  if (valid) {
    if (aux_value->IsObject()) {
      auto object = Local<v8::Object>::Cast(aux_value);

      Local<Array> keys(object->GetOwnPropertyNames(context).ToLocalChecked());
      uint32_t n = keys->Length();

      GVariantDict* aux = frida_spawn_options_get_aux(options);

      for (uint32_t i = 0; i != n; i++) {
        auto key = Nan::Get(keys, i).ToLocalChecked();
        auto value = Nan::Get(object, key).ToLocalChecked();

        Nan::Utf8String key_str(key->ToString());

        GVariant* raw_value;
        if (value->IsBoolean()) {
          Nan::Utf8String value_str(Local<String>::Cast(value));
          raw_value = g_variant_new_boolean(
              Local<Boolean>::Cast(value)->Value());
        } else if (value->IsNumber()) {
          raw_value = g_variant_new_int64(
              static_cast<gint64>(Local<Number>::Cast(value)->Value()));
        } else {
          Nan::Utf8String value_str(value->ToString());
          raw_value = g_variant_new_string(*value_str);
        }

        g_variant_dict_insert_value(aux, *key_str, raw_value);
      }
    } else {
      Nan::ThrowTypeError("Bad argument, 'aux' must be an object");
      valid = false;
    }
  }

  if (!valid) {
    g_object_unref(options);
    return;
  }

  auto operation = new SpawnOperation(g_strdup(*program), options);
  operation->Schedule(isolate, wrapper);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

class InputOperation : public Operation<FridaDevice> {
 public:
  InputOperation(guint pid, GBytes* data)
    : pid_(pid), data_(data) {
  }

  ~InputOperation() {
    g_bytes_unref(data_);
  }

  void Begin() {
    frida_device_input(handle_, pid_, data_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    frida_device_input_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    return Nan::Undefined();
  }

  const guint pid_;
  GBytes* data_;
};

NAN_METHOD(Device::Input) {
  auto isolate = info.GetIsolate();
  auto obj = info.Holder();
  auto wrapper = ObjectWrap::Unwrap<Device>(obj);

  if (info.Length() < 2 || !info[0]->IsNumber() ||
      !node::Buffer::HasInstance(info[1])) {
    Nan::ThrowTypeError("Bad argument, expected pid and data");
    return;
  }

  auto pid = info[0]->ToInteger()->Value();
  if (pid <= 0) {
    Nan::ThrowTypeError("Bad pid");
    return;
  }

  auto buffer = info[1];
  auto data = g_bytes_new(node::Buffer::Data(buffer),
      node::Buffer::Length(buffer));

  auto operation = new InputOperation(static_cast<guint>(pid), data);
  operation->Schedule(isolate, wrapper);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
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
    return Nan::Undefined();
  }

  const guint pid_;
};

NAN_METHOD(Device::Resume) {
  auto isolate = info.GetIsolate();
  auto obj = info.Holder();
  auto wrapper = ObjectWrap::Unwrap<Device>(obj);

  if (info.Length() < 1 || !info[0]->IsNumber()) {
    Nan::ThrowTypeError("Bad argument, expected pid");
    return;
  }
  auto pid = info[0]->ToInteger()->Value();
  if (pid <= 0) {
    Nan::ThrowTypeError("Bad argument, expected pid");
    return;
  }

  auto operation = new ResumeOperation(static_cast<guint>(pid));
  operation->Schedule(isolate, wrapper);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
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
    return Nan::Undefined();
  }

  const guint pid_;
};

NAN_METHOD(Device::Kill) {
  auto isolate = info.GetIsolate();
  auto obj = info.Holder();
  auto wrapper = ObjectWrap::Unwrap<Device>(obj);

  if (info.Length() < 1 || !info[0]->IsNumber()) {
    Nan::ThrowTypeError("Bad argument, expected pid");
    return;
  }
  auto pid = info[0]->ToInteger()->Value();
  if (pid <= 0) {
    Nan::ThrowTypeError("Bad argument, expected pid");
    return;
  }

  auto operation = new KillOperation(static_cast<guint>(pid));
  operation->Schedule(isolate, wrapper);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
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
    auto wrapper = Session::New(session_, runtime_);
    g_object_unref(session_);
    return wrapper;
  }

  const guint pid_;
  FridaSession* session_;
};

NAN_METHOD(Device::Attach) {
  auto isolate = info.GetIsolate();
  auto obj = info.Holder();
  auto wrapper = ObjectWrap::Unwrap<Device>(obj);

  if (info.Length() < 1 || !info[0]->IsNumber()) {
    Nan::ThrowTypeError("Bad argument, expected pid");
    return;
  }
  auto pid = info[0]->ToInteger()->Value();
  if (pid < 0) {
    Nan::ThrowTypeError("Bad argument, expected pid");
    return;
  }

  auto operation = new AttachOperation(static_cast<guint>(pid));
  operation->Schedule(isolate, wrapper);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

class InjectLibraryFileOperation : public Operation<FridaDevice> {
 public:
  InjectLibraryFileOperation(guint pid, gchar* path, gchar* entrypoint,
      gchar* data)
    : pid_(pid),
      path_(path),
      entrypoint_(entrypoint),
      data_(data) {
  }

  ~InjectLibraryFileOperation() {
    g_free(data_);
    g_free(entrypoint_);
    g_free(path_);
  }

  void Begin() {
    frida_device_inject_library_file(handle_, pid_, path_, entrypoint_, data_,
        OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    id_ = frida_device_inject_library_file_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    return Nan::New<v8::Uint32>(id_);
  }

  const guint pid_;
  gchar* path_;
  gchar* entrypoint_;
  gchar* data_;
  guint id_;
};

NAN_METHOD(Device::InjectLibraryFile) {
  auto isolate = info.GetIsolate();
  auto obj = info.Holder();
  auto wrapper = ObjectWrap::Unwrap<Device>(obj);

  if (info.Length() < 4 || !info[0]->IsNumber() || !info[1]->IsString() ||
      !info[2]->IsString() || !info[3]->IsString()) {
    Nan::ThrowTypeError("Bad argument");
    return;
  }

  auto pid = info[0]->ToInteger()->Value();
  if (pid < 0) {
    Nan::ThrowTypeError("Bad argument, expected pid");
    return;
  }
  Nan::Utf8String path(Local<String>::Cast(info[1]));
  Nan::Utf8String entrypoint(Local<String>::Cast(info[2]));
  Nan::Utf8String data(Local<String>::Cast(info[3]));

  auto operation = new InjectLibraryFileOperation(static_cast<guint>(pid),
      g_strdup(*path), g_strdup(*entrypoint), g_strdup(*data));
  operation->Schedule(isolate, wrapper);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

class InjectLibraryBlobOperation : public Operation<FridaDevice> {
 public:
  InjectLibraryBlobOperation(guint pid, GBytes* blob, gchar* entrypoint,
      gchar* data)
    : pid_(pid),
      blob_(blob),
      entrypoint_(entrypoint),
      data_(data) {
  }

  ~InjectLibraryBlobOperation() {
    g_free(data_);
    g_free(entrypoint_);
    g_bytes_unref(blob_);
  }

  void Begin() {
    frida_device_inject_library_blob(handle_, pid_, blob_, entrypoint_, data_,
        OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    id_ = frida_device_inject_library_blob_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    return Nan::New<v8::Uint32>(id_);
  }

  const guint pid_;
  GBytes* blob_;
  gchar* entrypoint_;
  gchar* data_;
  guint id_;
};

NAN_METHOD(Device::InjectLibraryBlob) {
  auto isolate = info.GetIsolate();
  auto obj = info.Holder();
  auto wrapper = ObjectWrap::Unwrap<Device>(obj);

  if (info.Length() < 4 || !info[0]->IsNumber() ||
      !node::Buffer::HasInstance(info[1]) || !info[2]->IsString() ||
      !info[3]->IsString()) {
    Nan::ThrowTypeError("Bad argument");
    return;
  }

  auto pid = info[0]->ToInteger()->Value();
  if (pid < 0) {
    Nan::ThrowTypeError("Bad argument, expected pid");
    return;
  }
  auto buffer = info[1];
  auto blob = g_bytes_new(node::Buffer::Data(buffer),
      node::Buffer::Length(buffer));
  Nan::Utf8String entrypoint(Local<String>::Cast(info[2]));
  Nan::Utf8String data(Local<String>::Cast(info[3]));

  auto operation = new InjectLibraryBlobOperation(static_cast<guint>(pid),
      blob, g_strdup(*entrypoint), g_strdup(*data));
  operation->Schedule(isolate, wrapper);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

Local<Value> Device::TransformSignal(const gchar* name, guint index,
    const GValue* value, gpointer user_data) {
  auto self = static_cast<Device*>(user_data);

  if (index == 0 && (strcmp(name, "spawn-added") == 0 ||
       strcmp(name, "spawn-removed") == 0))
    return Spawn::New(g_value_get_object(value), self->runtime_);

  if (index == 0 && (strcmp(name, "child-added") == 0 ||
       strcmp(name, "child-removed") == 0))
    return Child::New(g_value_get_object(value), self->runtime_);

  if (index == 0 && strcmp(name, "process-crashed") == 0)
    return Crash::New(g_value_get_object(value), self->runtime_);

  return Local<Value>();
}

void Device::OnConnect(const gchar* name, gpointer user_data) {
  auto wrapper = static_cast<Device*>(user_data);

  if (ShouldStayAliveToEmit(name))
    wrapper->runtime_->GetUVContext()->IncreaseUsage();
}

void Device::OnDisconnect(const gchar* name, gpointer user_data) {
  auto wrapper = static_cast<Device*>(user_data);

  if (ShouldStayAliveToEmit(name))
    wrapper->runtime_->GetUVContext()->DecreaseUsage();
}

bool Device::ShouldStayAliveToEmit(const gchar* name) {
  return strcmp(name, "spawn-added") == 0 ||
      strcmp(name, "spawn-removed") == 0 ||
      strcmp(name, "child-added") == 0 ||
      strcmp(name, "child-removed") == 0 ||
      strcmp(name, "process-crashed") == 0 ||
      strcmp(name, "output") == 0 ||
      strcmp(name, "uninjected") == 0;
}

}
