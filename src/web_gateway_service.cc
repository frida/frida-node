#include "web_gateway_service.h"

#include "endpoint_parameters.h"
#include "operation.h"

using v8::Function;
using v8::FunctionTemplate;
using v8::Isolate;
using v8::Local;
using v8::Object;
using v8::Persistent;
using v8::Value;

namespace frida {

WebGatewayService::WebGatewayService(FridaWebGatewayService* handle,
    Runtime* runtime)
    : GLibObject(handle, runtime) {
  g_object_ref(handle_);
}

WebGatewayService::~WebGatewayService() {
  g_object_unref(handle_);
}

void WebGatewayService::Init(Local<Object> exports, Runtime* runtime) {
  auto name = Nan::New("WebGatewayService").ToLocalChecked();
  auto tpl = CreateTemplate(name, WebGatewayService::New, runtime);

  Nan::SetPrototypeMethod(tpl, "start", Start);
  Nan::SetPrototypeMethod(tpl, "stop", Stop);

  auto ctor = Nan::GetFunction(tpl).ToLocalChecked();
  Nan::Set(exports, name, ctor);
}

NAN_METHOD(WebGatewayService::New) {
  if (!info.IsConstructCall()) {
    Nan::ThrowError("Use the `new` keyword to create a new instance");
    return;
  }

  if (info.Length() < 4) {
    Nan::ThrowTypeError("Missing one or more arguments");
    return;
  }

  auto runtime = GetRuntimeFromConstructorArgs(info);

  auto gateway_params_value = info[0];
  auto target_params_value = info[1];
  auto root_value = info[2];
  auto origin_value = info[3];

  FridaEndpointParameters* gateway_params = NULL;
  FridaEndpointParameters* target_params = NULL;
  GFile* root = NULL;
  gchar* origin = NULL;
  bool valid = true;

  if (!gateway_params_value->IsNull()) {
    gateway_params =
        EndpointParameters::TryParse(gateway_params_value, runtime);
    if (gateway_params != NULL) {
      g_object_ref(gateway_params);
    } else {
      Nan::ThrowTypeError("Bad argument, 'gatewayParams' type mismatch");
      valid = false;
    }
  } else {
    gateway_params = frida_endpoint_parameters_new(NULL, 0, NULL, NULL);
  }

  if (valid && !target_params_value->IsNull()) {
    target_params = EndpointParameters::TryParse(target_params_value, runtime);
    if (target_params != NULL) {
      g_object_ref(target_params);
    } else {
      Nan::ThrowTypeError("Bad argument, 'targetParams' type mismatch");
      valid = false;
    }
  } else if (valid) {
    target_params = frida_endpoint_parameters_new(NULL, 0, NULL, NULL);
  }

  if (valid && !root_value->IsNull()) {
    if (root_value->IsString()) {
      Nan::Utf8String str(root_value);
      root = g_file_new_for_path(*str);
    } else {
      Nan::ThrowTypeError("Bad argument, 'root' must be a string");
      valid = false;
    }
  }

  if (valid && !origin_value->IsNull()) {
    if (origin_value->IsString()) {
      Nan::Utf8String str(origin_value);
      origin = g_strdup(*str);
    } else {
      Nan::ThrowTypeError("Bad argument, 'origin' must be a string");
      valid = false;
    }
  }

  if (valid) {
    auto handle = frida_web_gateway_service_new(gateway_params, target_params,
        root, origin);
    auto wrapper = new WebGatewayService(handle, runtime);
    g_object_unref(handle);
    auto obj = info.This();
    wrapper->Wrap(obj);

    info.GetReturnValue().Set(obj);
  }

  g_free(origin);
  g_clear_object(&root);
  g_clear_object(&target_params);
  g_clear_object(&gateway_params);
}

namespace {

class StartOperation : public Operation<FridaWebGatewayService> {
 protected:
  void Begin() {
    frida_web_gateway_service_start(handle_, cancellable_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    frida_web_gateway_service_start_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    runtime_->GetUVContext()->IncreaseUsage();
    return Nan::Undefined();
  }
};

}

NAN_METHOD(WebGatewayService::Start) {
  auto isolate = info.GetIsolate();
  auto wrapper = ObjectWrap::Unwrap<WebGatewayService>(info.Holder());

  auto operation = new StartOperation();
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

namespace {

class StopOperation : public Operation<FridaWebGatewayService> {
 protected:
  void Begin() {
    frida_web_gateway_service_stop(handle_, cancellable_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    frida_web_gateway_service_stop_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    runtime_->GetUVContext()->DecreaseUsage();
    return Nan::Undefined();
  }
};

}

NAN_METHOD(WebGatewayService::Stop) {
  auto isolate = info.GetIsolate();
  auto wrapper = ObjectWrap::Unwrap<WebGatewayService>(info.Holder());

  auto operation = new StopOperation();
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

}
