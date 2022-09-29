#include "portal_service.h"

#include "application.h"
#include "device.h"
#include "endpoint_parameters.h"
#include "operation.h"
#include "signals.h"

#include <cstring>

using std::strcmp;
using v8::DEFAULT;
using v8::Function;
using v8::FunctionTemplate;
using v8::Isolate;
using v8::Local;
using v8::Object;
using v8::Persistent;
using v8::ReadOnly;
using v8::Value;

namespace frida {

PortalService::PortalService(FridaPortalService* handle,
    Runtime* runtime)
    : GLibObject(handle, runtime) {
  g_object_ref(handle_);
}

PortalService::~PortalService() {
  frida_unref(handle_);
}

void PortalService::Init(Local<Object> exports, Runtime* runtime) {
  auto name = Nan::New("PortalService").ToLocalChecked();
  auto tpl = CreateTemplate(name, PortalService::New, runtime);

  auto instance_tpl = tpl->InstanceTemplate();
  auto data = Local<Value>();
  Nan::SetAccessor(instance_tpl, Nan::New("device").ToLocalChecked(), GetDevice,
      0, data, DEFAULT, ReadOnly);

  Nan::SetPrototypeMethod(tpl, "start", Start);
  Nan::SetPrototypeMethod(tpl, "stop", Stop);
  Nan::SetPrototypeMethod(tpl, "post", Post);
  Nan::SetPrototypeMethod(tpl, "narrowcast", Narrowcast);
  Nan::SetPrototypeMethod(tpl, "broadcast", Broadcast);
  Nan::SetPrototypeMethod(tpl, "enumerateTags", EnumerateTags);
  Nan::SetPrototypeMethod(tpl, "tag", Tag);
  Nan::SetPrototypeMethod(tpl, "untag", Untag);

  auto ctor = Nan::GetFunction(tpl).ToLocalChecked();
  Nan::Set(exports, name, ctor);
}

NAN_METHOD(PortalService::New) {
  if (!info.IsConstructCall()) {
    Nan::ThrowError("Use the `new` keyword to create a new instance");
    return;
  }

  if (info.Length() < 2) {
    Nan::ThrowTypeError("Missing one or more arguments");
    return;
  }

  auto runtime = GetRuntimeFromConstructorArgs(info);

  auto cluster_params_value = info[0];
  auto control_params_value = info[1];

  FridaEndpointParameters* cluster_params = NULL;
  FridaEndpointParameters* control_params = NULL;
  bool valid = true;

  if (!cluster_params_value->IsNull()) {
    cluster_params =
        EndpointParameters::TryParse(cluster_params_value, runtime);
    if (cluster_params != NULL) {
      g_object_ref(cluster_params);
    } else {
      Nan::ThrowTypeError("Bad argument, 'clusterParams' type mismatch");
      valid = false;
    }
  } else {
    cluster_params =
        frida_endpoint_parameters_new(NULL, 0, NULL, NULL, NULL, NULL);
  }

  if (valid && !control_params_value->IsNull()) {
    control_params =
        EndpointParameters::TryParse(control_params_value, runtime);
    if (control_params != NULL) {
      g_object_ref(control_params);
    } else {
      Nan::ThrowTypeError("Bad argument, 'controlParams' type mismatch");
      valid = false;
    }
  }

  if (valid) {
    auto handle = frida_portal_service_new(cluster_params, control_params);
    auto wrapper = new PortalService(handle, runtime);
    g_object_unref(handle);
    auto obj = info.This();
    wrapper->Wrap(obj);
    Nan::Set(obj, Nan::New("signals").ToLocalChecked(),
        Signals::New(handle, runtime, TransformSignal, runtime));

    info.GetReturnValue().Set(obj);
  }

  g_clear_object(&control_params);
  g_clear_object(&cluster_params);
}

NAN_PROPERTY_GETTER(PortalService::GetDevice) {
  auto wrapper = ObjectWrap::Unwrap<PortalService>(info.Holder());
  auto handle = wrapper->GetHandle<FridaPortalService>();

  info.GetReturnValue().Set(
      Device::New(frida_portal_service_get_device(handle), wrapper->runtime_));
}

namespace {

class StartOperation : public Operation<FridaPortalService> {
 protected:
  void Begin() {
    frida_portal_service_start(handle_, cancellable_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    frida_portal_service_start_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    runtime_->GetUVContext()->IncreaseUsage();
    return Nan::Undefined();
  }
};

}

NAN_METHOD(PortalService::Start) {
  auto isolate = info.GetIsolate();
  auto wrapper = ObjectWrap::Unwrap<PortalService>(info.Holder());

  auto operation = new StartOperation();
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

namespace {

class StopOperation : public Operation<FridaPortalService> {
 protected:
  void Begin() {
    frida_portal_service_stop(handle_, cancellable_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    frida_portal_service_stop_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    runtime_->GetUVContext()->DecreaseUsage();
    return Nan::Undefined();
  }
};

}

NAN_METHOD(PortalService::Stop) {
  auto isolate = info.GetIsolate();
  auto wrapper = ObjectWrap::Unwrap<PortalService>(info.Holder());

  auto operation = new StopOperation();
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

NAN_METHOD(PortalService::Post) {
  auto wrapper = ObjectWrap::Unwrap<PortalService>(info.Holder());

  auto num_args = info.Length();
  if (num_args < 3) {
    Nan::ThrowTypeError("Missing one or more arguments");
    return;
  }

  guint connection_id;
  if (!ValueToConnectionId(info[0], &connection_id))
    return;

  Nan::Utf8String message(wrapper->runtime_->ValueToJson(info[1]));

  GBytes* data = NULL;
  auto buffer = info[2];
  if (!buffer->IsNull()) {
    if (!node::Buffer::HasInstance(buffer)) {
      Nan::ThrowTypeError("Expected a buffer");
      return;
    }
    data = g_bytes_new(node::Buffer::Data(buffer),
        node::Buffer::Length(buffer));
  }

  frida_portal_service_post(wrapper->GetHandle<FridaPortalService>(),
      connection_id, *message, data);

  g_bytes_unref(data);
}

NAN_METHOD(PortalService::Narrowcast) {
  auto wrapper = ObjectWrap::Unwrap<PortalService>(info.Holder());

  auto num_args = info.Length();
  if (num_args < 3) {
    Nan::ThrowTypeError("Missing one or more arguments");
    return;
  }

  Nan::Utf8String tag(info[0]);

  Nan::Utf8String message(wrapper->runtime_->ValueToJson(info[1]));

  GBytes* data = NULL;
  auto buffer = info[2];
  if (!buffer->IsNull()) {
    if (!node::Buffer::HasInstance(buffer)) {
      Nan::ThrowTypeError("Expected a buffer");
      return;
    }
    data = g_bytes_new(node::Buffer::Data(buffer),
        node::Buffer::Length(buffer));
  }

  frida_portal_service_narrowcast(wrapper->GetHandle<FridaPortalService>(),
      *tag, *message, data);

  g_bytes_unref(data);
}

NAN_METHOD(PortalService::Broadcast) {
  auto wrapper = ObjectWrap::Unwrap<PortalService>(info.Holder());

  auto num_args = info.Length();
  if (num_args < 2) {
    Nan::ThrowTypeError("Missing one or more arguments");
    return;
  }

  Nan::Utf8String message(wrapper->runtime_->ValueToJson(info[0]));

  GBytes* data = NULL;
  auto buffer = info[1];
  if (!buffer->IsNull()) {
    if (!node::Buffer::HasInstance(buffer)) {
      Nan::ThrowTypeError("Expected a buffer");
      return;
    }
    data = g_bytes_new(node::Buffer::Data(buffer),
        node::Buffer::Length(buffer));
  }

  frida_portal_service_broadcast(wrapper->GetHandle<FridaPortalService>(),
      *message, data);

  g_bytes_unref(data);
}

namespace {

class EnumerateTagsOperation : public Operation<FridaPortalService> {
 public:
  EnumerateTagsOperation(guint connection_id)
    : connection_id_(connection_id),
      tags_(NULL),
      n_(0) {
  }

  ~EnumerateTagsOperation() {
    g_strfreev(tags_);
  }

 protected:
  void Begin() {
    tags_ = frida_portal_service_enumerate_tags(handle_, connection_id_, &n_);
    OnReady(G_OBJECT(handle_), NULL, this);
  }

  void End(GAsyncResult* result, GError** error) {
  }

  Local<Value> Result(Isolate* isolate) {
    return Runtime::ValueFromStrv(tags_, n_);
  }

 private:
  guint connection_id_;
  gchar** tags_;
  gint n_;
};

}

NAN_METHOD(PortalService::EnumerateTags) {
  auto isolate = info.GetIsolate();
  auto wrapper = ObjectWrap::Unwrap<PortalService>(info.Holder());

  if (info.Length() < 1) {
    Nan::ThrowTypeError("Bad argument, expected a connection ID");
    return;
  }

  guint connection_id;
  if (!ValueToConnectionId(info[0], &connection_id))
    return;

  auto operation = new EnumerateTagsOperation(connection_id);
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

NAN_METHOD(PortalService::Tag) {
  auto wrapper = ObjectWrap::Unwrap<PortalService>(info.Holder());

  auto num_args = info.Length();
  if (num_args < 2) {
    Nan::ThrowTypeError("Missing one or more arguments");
    return;
  }

  guint connection_id;
  if (!ValueToConnectionId(info[0], &connection_id))
    return;

  Nan::Utf8String tag(info[1]);

  frida_portal_service_tag(wrapper->GetHandle<FridaPortalService>(),
      connection_id, *tag);
}

NAN_METHOD(PortalService::Untag) {
  auto wrapper = ObjectWrap::Unwrap<PortalService>(info.Holder());

  auto num_args = info.Length();
  if (num_args < 2) {
    Nan::ThrowTypeError("Missing one or more arguments");
    return;
  }

  guint connection_id;
  if (!ValueToConnectionId(info[0], &connection_id))
    return;

  Nan::Utf8String tag(info[1]);

  frida_portal_service_untag(wrapper->GetHandle<FridaPortalService>(),
      connection_id, *tag);
}

bool PortalService::ValueToConnectionId(Local<Value> value,
    guint* connection_id) {
  if (!value->IsNumber()) {
    Nan::ThrowTypeError("Expected a connection ID");
    return false;
  }

  auto id = Nan::To<uint32_t>(value).FromMaybe(0);
  if (id == 0) {
    Nan::ThrowTypeError("Expected a connection ID");
    return false;
  }

  *connection_id = id;
  return true;
}

Local<Value> PortalService::TransformSignal(const gchar* name, guint index,
    const GValue* value, gpointer user_data) {
  auto runtime = static_cast<Runtime*>(user_data);

  if (index == 1 && (strcmp(name, "node-joined") == 0 ||
        strcmp(name, "node-left") == 0))
    return Application::New(g_value_get_object(value), runtime);

  if (index == 1 && (strcmp(name, "authenticated") == 0 ||
        strcmp(name, "message") == 0)) {
    auto json = Nan::New(g_value_get_string(value)).ToLocalChecked();
    return runtime->ValueFromJson(json);
  }

  return Local<Value>();
}

}
