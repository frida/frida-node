#include "session.h"

#include "crash.h"
#include "operation.h"
#include "portal_membership.h"
#include "relay.h"
#include "script.h"
#include "signals.h"
#include "usage_monitor.h"

#include <cstring>

#define SESSION_DATA_CONSTRUCTOR "session:ctor"

using std::strcmp;
using v8::Array;
using v8::DEFAULT;
using v8::External;
using v8::Function;
using v8::Isolate;
using v8::Local;
using v8::Object;
using v8::Persistent;
using v8::ReadOnly;
using v8::String;
using v8::Uint32;
using v8::Value;

namespace frida {

static FridaScriptOptions* ParseScriptOptions(Local<Value> name_value,
    Local<Value> snapshot_value, Local<Value> runtime_value);
static FridaSnapshotOptions* ParseSnapshotOptions(
    Local<Value> warmup_script_value, Local<Value> runtime_value);
static void UnrefGBytes(char* data, void* hint);

Session::Session(FridaSession* handle, Runtime* runtime)
    : GLibObject(handle, runtime) {
  g_object_ref(handle_);
}

Session::~Session() {
  frida_unref(handle_);
}

void Session::Init(Local<Object> exports, Runtime* runtime) {
  auto isolate = Isolate::GetCurrent();

  auto name = Nan::New("Session").ToLocalChecked();
  auto tpl = CreateTemplate(name, Session::New, runtime);

  auto instance_tpl = tpl->InstanceTemplate();
  auto data = Local<Value>();
  Nan::SetAccessor(instance_tpl, Nan::New("isDetached").ToLocalChecked(),
      IsDetached, 0, data, DEFAULT, ReadOnly);
  Nan::SetAccessor(instance_tpl, Nan::New("persistTimeout").ToLocalChecked(),
      GetPersistTimeout, 0, data, DEFAULT, ReadOnly);
  Nan::SetAccessor(instance_tpl, Nan::New("pid").ToLocalChecked(), GetPid, 0,
      data, DEFAULT, ReadOnly);

  Nan::SetPrototypeMethod(tpl, "detach", Detach);
  Nan::SetPrototypeMethod(tpl, "resume", Resume);
  Nan::SetPrototypeMethod(tpl, "enableChildGating", EnableChildGating);
  Nan::SetPrototypeMethod(tpl, "disableChildGating", DisableChildGating);
  Nan::SetPrototypeMethod(tpl, "createScript", CreateScript);
  Nan::SetPrototypeMethod(tpl, "createScriptFromBytes", CreateScriptFromBytes);
  Nan::SetPrototypeMethod(tpl, "compileScript", CompileScript);
  Nan::SetPrototypeMethod(tpl, "snapshotScript", SnapshotScript);
  Nan::SetPrototypeMethod(tpl, "setupPeerConnection", SetupPeerConnection);
  Nan::SetPrototypeMethod(tpl, "joinPortal", JoinPortal);

  auto ctor = Nan::GetFunction(tpl).ToLocalChecked();
  Nan::Set(exports, name, ctor);
  runtime->SetDataPointer(SESSION_DATA_CONSTRUCTOR,
      new Persistent<Function>(isolate, ctor));
}

Local<Object> Session::New(gpointer handle, Runtime* runtime) {
  auto ctor = Nan::New<Function>(
    *static_cast<Persistent<Function>*>(
      runtime->GetDataPointer(SESSION_DATA_CONSTRUCTOR)));
  const int argc = 1;
  Local<Value> argv[argc] = { Nan::New<External>(handle) };
  return Nan::NewInstance(ctor, argc, argv).ToLocalChecked();
}

NAN_METHOD(Session::New) {
  if (!info.IsConstructCall()) {
    Nan::ThrowError("Use the `new` keyword to create a new instance");
    return;
  }

  if (info.Length() != 1 || !info[0]->IsExternal()) {
    Nan::ThrowTypeError("Bad argument, expected raw handle");
    return;
  }

  auto runtime = GetRuntimeFromConstructorArgs(info);

  auto handle = static_cast<FridaSession*>(
      Local<External>::Cast(info[0])->Value());
  auto wrapper = new Session(handle, runtime);
  auto obj = info.This();
  wrapper->Wrap(obj);
  Nan::Set(obj, Nan::New("signals").ToLocalChecked(),
      Signals::New(handle, runtime, TransformSignal, runtime));

  info.GetReturnValue().Set(obj);
}

NAN_PROPERTY_GETTER(Session::GetPid) {
  auto handle = ObjectWrap::Unwrap<Session>(
      info.Holder())->GetHandle<FridaSession>();

  info.GetReturnValue().Set(Nan::New<Uint32>(
      frida_session_get_pid(handle)));
}

NAN_PROPERTY_GETTER(Session::GetPersistTimeout) {
  auto handle = ObjectWrap::Unwrap<Session>(
      info.Holder())->GetHandle<FridaSession>();

  info.GetReturnValue().Set(Nan::New<Uint32>(
      frida_session_get_persist_timeout(handle)));
}

NAN_PROPERTY_GETTER(Session::IsDetached) {
  auto handle = ObjectWrap::Unwrap<Session>(
      info.Holder())->GetHandle<FridaSession>();

  info.GetReturnValue().Set(
      Nan::New(static_cast<bool>(frida_session_is_detached(handle))));
}

namespace {

class DetachOperation : public Operation<FridaSession> {
 protected:
  void Begin() {
    frida_session_detach(handle_, cancellable_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    frida_session_detach_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    return Nan::Undefined();
  }
};

}

NAN_METHOD(Session::Detach) {
  auto isolate = info.GetIsolate();
  auto wrapper = ObjectWrap::Unwrap<Session>(info.Holder());

  auto operation = new DetachOperation();
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

namespace {

class ResumeOperation : public Operation<FridaSession> {
 protected:
  void Begin() {
    frida_session_resume(handle_, cancellable_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    frida_session_resume_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    return Nan::Undefined();
  }
};

}

NAN_METHOD(Session::Resume) {
  auto isolate = info.GetIsolate();
  auto wrapper = ObjectWrap::Unwrap<Session>(info.Holder());

  auto operation = new ResumeOperation();
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

namespace {

class EnableChildGatingOperation : public Operation<FridaSession> {
 protected:
  void Begin() {
    frida_session_enable_child_gating(handle_, cancellable_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    frida_session_enable_child_gating_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    return Nan::Undefined();
  }
};

}

NAN_METHOD(Session::EnableChildGating) {
  auto isolate = info.GetIsolate();
  auto wrapper = ObjectWrap::Unwrap<Session>(info.Holder());

  auto operation = new EnableChildGatingOperation();
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

namespace {

class DisableChildGatingOperation : public Operation<FridaSession> {
 protected:
  void Begin() {
    frida_session_disable_child_gating(handle_, cancellable_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    frida_session_disable_child_gating_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    return Nan::Undefined();
  }
};

}

NAN_METHOD(Session::DisableChildGating) {
  auto isolate = info.GetIsolate();
  auto wrapper = ObjectWrap::Unwrap<Session>(info.Holder());

  auto operation = new DisableChildGatingOperation();
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

namespace {

class CreateScriptOperation : public Operation<FridaSession> {
 public:
  CreateScriptOperation(gchar* source, FridaScriptOptions* options)
    : source_(source),
      options_(options) {
  }

  ~CreateScriptOperation() {
    g_object_unref(options_);
    g_free(source_);
  }

 protected:
  void Begin() {
    frida_session_create_script(handle_, source_, options_, cancellable_,
        OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    script_ = frida_session_create_script_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    auto wrapper = Script::New(script_, runtime_);
    g_object_unref(script_);
    return wrapper;
  }

 private:
  gchar* source_;
  FridaScriptOptions* options_;
  FridaScript* script_;
};

}


NAN_METHOD(Session::CreateScript) {
  auto isolate = info.GetIsolate();
  auto wrapper = ObjectWrap::Unwrap<Session>(info.Holder());

  if (info.Length() < 4) {
    Nan::ThrowTypeError("Missing one or more arguments");
    return;
  }

  auto source_value = info[0];
  auto name_value = info[1];
  auto snapshot_value = info[2];
  auto runtime_value = info[3];

  bool valid = true;

  gchar* source;
  Nan::Utf8String val(source_value);
  source = g_strdup(*val);
  if (source == NULL) {
    Nan::ThrowTypeError("Bad argument, 'source' must be a string");
    valid = false;
  }

  FridaScriptOptions* options = NULL;
  if (valid) {
    options = ParseScriptOptions(name_value, snapshot_value, runtime_value);
    valid = options != NULL;
  }

  if (!valid) {
    g_free(source);
    g_clear_object(&options);
    return;
  }

  auto operation = new CreateScriptOperation(source, options);
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

namespace {

class CreateScriptFromBytesOperation : public Operation<FridaSession> {
 public:
  CreateScriptFromBytesOperation(GBytes* bytes, FridaScriptOptions* options)
    : bytes_(bytes),
      options_(options) {
  }

  ~CreateScriptFromBytesOperation() {
    g_object_unref(options_);
    g_bytes_unref(bytes_);
  }

 protected:
  void Begin() {
    frida_session_create_script_from_bytes(handle_, bytes_, options_,
        cancellable_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    script_ = frida_session_create_script_from_bytes_finish(handle_, result,
        error);
  }

  Local<Value> Result(Isolate* isolate) {
    auto wrapper = Script::New(script_, runtime_);
    g_object_unref(script_);
    return wrapper;
  }

 private:
  GBytes* bytes_;
  FridaScriptOptions* options_;
  FridaScript* script_;
};

}

NAN_METHOD(Session::CreateScriptFromBytes) {
  auto isolate = info.GetIsolate();
  auto wrapper = ObjectWrap::Unwrap<Session>(info.Holder());

  if (info.Length() < 4) {
    Nan::ThrowTypeError("Missing one or more arguments");
    return;
  }

  auto bytes_value = info[0];
  auto name_value = info[1];
  auto snapshot_value = info[2];
  auto runtime_value = info[3];

  bool valid = true;

  GBytes* bytes = NULL;
  if (node::Buffer::HasInstance(bytes_value)) {
    bytes = g_bytes_new(node::Buffer::Data(bytes_value),
        node::Buffer::Length(bytes_value));
  } else {
    Nan::ThrowTypeError("Bad argument, 'bytes' must be a Buffer");
    valid = false;
  }

  FridaScriptOptions* options = NULL;
  if (valid) {
    options = ParseScriptOptions(name_value, snapshot_value, runtime_value);
    valid = options != NULL;
  }

  if (!valid) {
    g_bytes_unref(bytes);
    g_clear_object(&options);
    return;
  }

  auto operation = new CreateScriptFromBytesOperation(bytes, options);
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

namespace {

class CompileScriptOperation : public Operation<FridaSession> {
 public:
  CompileScriptOperation(gchar* source, FridaScriptOptions* options)
    : source_(source),
      options_(options) {
  }

  ~CompileScriptOperation() {
    g_object_unref(options_);
    g_free(source_);
  }

 protected:
  void Begin() {
    frida_session_compile_script(handle_, source_, options_, cancellable_,
        OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    bytes_ = frida_session_compile_script_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    gsize size;
    auto data = g_bytes_get_data(bytes_, &size);
    return Nan::NewBuffer(static_cast<char*>(const_cast<void*>(data)), size,
        UnrefGBytes, bytes_).ToLocalChecked();
  }

 private:
  gchar* source_;
  FridaScriptOptions* options_;
  GBytes* bytes_;
};

}

NAN_METHOD(Session::CompileScript) {
  auto isolate = info.GetIsolate();
  auto wrapper = ObjectWrap::Unwrap<Session>(info.Holder());

  if (info.Length() < 3) {
    Nan::ThrowTypeError("Missing one or more arguments");
    return;
  }

  auto source_value = info[0];
  auto name_value = info[1];
  auto runtime_value = info[2];

  bool valid = true;

  gchar* source;
  Nan::Utf8String val(source_value);
  source = g_strdup(*val);
  if (source == NULL) {
    Nan::ThrowTypeError("Bad argument, 'source' must be a string");
    valid = false;
  }

  FridaScriptOptions* options = NULL;
  if (valid) {
    options = ParseScriptOptions(name_value, Nan::Null(), runtime_value);
    valid = options != NULL;
  }

  if (!valid) {
    g_free(source);
    g_clear_object(&options);
    return;
  }

  auto operation = new CompileScriptOperation(source, options);
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

static FridaScriptOptions* ParseScriptOptions(Local<Value> name_value,
    Local<Value> snapshot_value, Local<Value> runtime_value) {
  auto options = frida_script_options_new();
  bool valid = true;

  if (!name_value->IsNull()) {
    Nan::Utf8String val(name_value);
    const gchar* name = *val;
    if (name != NULL) {
      frida_script_options_set_name(options, name);
    } else {
      Nan::ThrowTypeError("Bad argument, 'name' must be a string");
      valid = false;
    }
  }

  if (valid && !snapshot_value->IsNull()) {
    if (node::Buffer::HasInstance(snapshot_value)) {
      auto snapshot = g_bytes_new(node::Buffer::Data(snapshot_value),
          node::Buffer::Length(snapshot_value));
      frida_script_options_set_snapshot(options, snapshot);
      g_bytes_unref(snapshot);
    } else {
      Nan::ThrowTypeError("Bad argument, 'snapshot' must be a Buffer");
      valid = false;
    }
  }

  if (valid && !runtime_value->IsNull()) {
    FridaScriptRuntime runtime;
    valid = Runtime::ValueToEnum(runtime_value, FRIDA_TYPE_SCRIPT_RUNTIME,
        &runtime);
    if (valid) {
      frida_script_options_set_runtime(options, runtime);
    }
  }

  if (!valid) {
    g_object_unref(options);
    return NULL;
  }

  return options;
}

namespace {

class SnapshotScriptOperation : public Operation<FridaSession> {
 public:
  SnapshotScriptOperation(gchar* embed_script, FridaSnapshotOptions* options)
    : embed_script_(embed_script),
      options_(options) {
  }

  ~SnapshotScriptOperation() {
    g_object_unref(options_);
    g_free(embed_script_);
  }

 protected:
  void Begin() {
    frida_session_snapshot_script(handle_, embed_script_, options_,
        cancellable_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    bytes_ = frida_session_snapshot_script_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    gsize size;
    auto data = g_bytes_get_data(bytes_, &size);
    return Nan::NewBuffer(static_cast<char*>(const_cast<void*>(data)), size,
        UnrefGBytes, bytes_).ToLocalChecked();
  }

 private:
  gchar* embed_script_;
  FridaSnapshotOptions* options_;
  GBytes* bytes_;
};

}

NAN_METHOD(Session::SnapshotScript) {
  auto isolate = info.GetIsolate();
  auto wrapper = ObjectWrap::Unwrap<Session>(info.Holder());

  if (info.Length() < 3) {
    Nan::ThrowTypeError("Missing one or more arguments");
    return;
  }

  auto embed_script_value = info[0];
  auto warmup_script_value = info[1];
  auto runtime_value = info[2];

  bool valid = true;

  gchar* embed_script;
  Nan::Utf8String val(embed_script_value);
  embed_script = g_strdup(*val);
  if (embed_script == NULL) {
    Nan::ThrowTypeError("Bad argument, 'embedScript' must be a string");
    valid = false;
  }

  FridaSnapshotOptions* options = NULL;
  if (valid) {
    options = ParseSnapshotOptions(warmup_script_value, runtime_value);
    valid = options != NULL;
  }

  if (!valid) {
    g_free(embed_script);
    g_clear_object(&options);
    return;
  }

  auto operation = new SnapshotScriptOperation(embed_script, options);
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

static FridaSnapshotOptions* ParseSnapshotOptions(
    Local<Value> warmup_script_value, Local<Value> runtime_value) {
  auto options = frida_snapshot_options_new();
  bool valid = true;

  if (!warmup_script_value->IsNull()) {
    Nan::Utf8String val(warmup_script_value);
    const gchar* warmup_script = *val;
    if (warmup_script != NULL) {
      frida_snapshot_options_set_warmup_script(options, warmup_script);
    } else {
      Nan::ThrowTypeError("Bad argument, 'warmupScript' must be a string");
      valid = false;
    }
  }

  if (valid && !runtime_value->IsNull()) {
    FridaScriptRuntime runtime;
    valid = Runtime::ValueToEnum(runtime_value, FRIDA_TYPE_SCRIPT_RUNTIME,
        &runtime);
    if (valid) {
      frida_snapshot_options_set_runtime(options, runtime);
    }
  }

  if (!valid) {
    g_object_unref(options);
    return NULL;
  }

  return options;
}

namespace {

class SetupPeerConnectionOperation : public Operation<FridaSession> {
 public:
  SetupPeerConnectionOperation(FridaPeerOptions* options) : options_(options) {
  }

  ~SetupPeerConnectionOperation() {
    g_object_unref(options_);
  }

 protected:
  void Begin() {
    frida_session_setup_peer_connection(handle_, options_, cancellable_,
        OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    frida_session_setup_peer_connection_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    return Nan::Undefined();
  }

 private:
  FridaPeerOptions* options_;
};

}

NAN_METHOD(Session::SetupPeerConnection) {
  auto isolate = info.GetIsolate();
  auto wrapper = ObjectWrap::Unwrap<Session>(info.Holder());

  if (info.Length() < 2) {
    Nan::ThrowTypeError("Missing one or more arguments");
    return;
  }

  auto stun_server_value = info[0];
  auto relays_value = info[1];

  auto options = frida_peer_options_new();
  bool valid = true;

  if (!stun_server_value->IsNull()) {
    if (stun_server_value->IsString()) {
      Nan::Utf8String stun_server(stun_server_value);
      frida_peer_options_set_stun_server(options, *stun_server);
    } else {
      Nan::ThrowTypeError("Bad argument, 'stunServer' must be a string");
      valid = false;
    }
  }

  if (valid) {
    if (relays_value->IsArray()) {
      auto array = Local<Array>::Cast(relays_value);

      uint32_t n = array->Length();

      for (uint32_t i = 0; i != n; i++) {
        auto element_value = Nan::Get(array, i).ToLocalChecked();
        FridaRelay* relay = Relay::TryParse(element_value, wrapper->runtime_);
        if (relay == NULL) {
          Nan::ThrowTypeError("Bad argument, 'relays' element type mismatch");
          valid = false;
          break;
        }
        frida_peer_options_add_relay(options, relay);
      }
    } else {
      Nan::ThrowTypeError("Bad argument, 'relays' must be an array");
      valid = false;
    }
  }

  if (!valid) {
    g_object_unref(options);
    return;
  }

  auto operation = new SetupPeerConnectionOperation(options);
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

namespace {

class JoinPortalOperation : public Operation<FridaSession> {
 public:
  JoinPortalOperation(gchar* address, FridaPortalOptions* options)
    : address_(address),
      options_(options) {
  }

  ~JoinPortalOperation() {
    g_object_unref(options_);
    g_free(address_);
  }

 protected:
  void Begin() {
    frida_session_join_portal(handle_, address_, options_, cancellable_,
        OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    membership_ = frida_session_join_portal_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    auto wrapper = PortalMembership::New(membership_, runtime_);
    g_object_unref(membership_);
    return wrapper;
  }

 private:
  gchar* address_;
  FridaPortalOptions* options_;
  FridaPortalMembership* membership_;
};

}

NAN_METHOD(Session::JoinPortal) {
  auto isolate = info.GetIsolate();
  auto wrapper = ObjectWrap::Unwrap<Session>(info.Holder());

  if (info.Length() < 4) {
    Nan::ThrowTypeError("Missing one or more arguments");
    return;
  }

  auto address_value = info[0];
  auto certificate_value = info[1];
  auto token_value = info[2];
  auto acl_value = info[3];

  if (!address_value->IsString()) {
    Nan::ThrowTypeError("Bad argument, 'address' must be a string");
    return;
  }
  Nan::Utf8String address(address_value);

  auto options = frida_portal_options_new();
  bool valid = true;

  if (!certificate_value->IsNull()) {
    GTlsCertificate* certificate;
    valid = Runtime::ValueToCertificate(certificate_value, &certificate);
    if (valid) {
      frida_portal_options_set_certificate(options, certificate);
      g_object_unref(certificate);
    }
  }

  if (valid && !token_value->IsNull()) {
    if (token_value->IsString()) {
      Nan::Utf8String token(token_value);
      frida_portal_options_set_token(options, *token);
    } else {
      Nan::ThrowTypeError("Bad argument, 'token' must be a string");
      valid = false;
    }
  }

  if (valid && !acl_value->IsNull()) {
    gchar** acl;
    gint acl_length;
    valid = Runtime::ValueToEnvp(acl_value, &acl, &acl_length);
    if (valid) {
      frida_portal_options_set_acl(options, acl, acl_length);
      g_strfreev(acl);
    }
  }

  if (!valid) {
    g_object_unref(options);
    return;
  }

  auto operation = new JoinPortalOperation(g_strdup(*address), options);
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

Local<Value> Session::TransformSignal(const gchar* name, guint index,
    const GValue* value, gpointer user_data) {
  auto runtime = static_cast<Runtime*>(user_data);

  if (index == 1 && strcmp(name, "detached") == 0) {
    auto crash = g_value_get_object(value);
    if (crash == NULL)
      return Nan::Null();
    return Crash::New(crash, runtime);
  }

  return Local<Value>();
}

static void UnrefGBytes(char* data, void* hint) {
  g_bytes_unref(static_cast<GBytes*>(hint));
}

}
