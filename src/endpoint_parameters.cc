#include "endpoint_parameters.h"

#include "authentication.h"

#define ENDPOINT_PARAMETERS_DATA_TEMPLATE "endpoint_parameters:tpl"

using v8::Function;
using v8::FunctionTemplate;
using v8::Isolate;
using v8::Local;
using v8::Object;
using v8::Persistent;
using v8::Value;

namespace frida {

EndpointParameters::EndpointParameters(FridaEndpointParameters* handle,
    Runtime* runtime)
    : GLibObject(handle, runtime) {
  g_object_ref(handle_);
}

EndpointParameters::~EndpointParameters() {
  g_object_unref(handle_);
}

void EndpointParameters::Init(Local<Object> exports, Runtime* runtime) {
  auto isolate = Isolate::GetCurrent();

  auto name = Nan::New("EndpointParameters").ToLocalChecked();
  auto tpl = CreateTemplate(name, EndpointParameters::New, runtime);

  auto ctor = Nan::GetFunction(tpl).ToLocalChecked();
  Nan::Set(exports, name, ctor);
  runtime->SetDataPointer(ENDPOINT_PARAMETERS_DATA_TEMPLATE,
      new Persistent<FunctionTemplate>(isolate, tpl));
}

FridaEndpointParameters* EndpointParameters::TryParse(Local<Value> value,
    Runtime* runtime) {
  if (!value->IsObject())
    return NULL;

  auto impl = Nan::Get(value.As<Object>(), Nan::New("impl").ToLocalChecked())
      .ToLocalChecked();
  if (!HasInstance(impl, runtime))
    return NULL;

  return ObjectWrap::Unwrap<EndpointParameters>(
      impl.As<Object>())->GetHandle<FridaEndpointParameters>();
}

bool EndpointParameters::HasInstance(Local<Value> value, Runtime* runtime) {
  auto tpl = Nan::New<FunctionTemplate>(
      *static_cast<Persistent<FunctionTemplate>*>(
      runtime->GetDataPointer(ENDPOINT_PARAMETERS_DATA_TEMPLATE)));
  return tpl->HasInstance(value);
}

NAN_METHOD(EndpointParameters::New) {
  if (!info.IsConstructCall()) {
    Nan::ThrowError("Use the `new` keyword to create a new instance");
    return;
  }

  if (info.Length() < 7) {
    Nan::ThrowTypeError("Missing one or more arguments");
    return;
  }

  auto runtime = GetRuntimeFromConstructorArgs(info);

  auto address_value = info[0];
  auto port_value = info[1];
  auto certificate_value = info[2];
  auto origin_value = info[3];
  auto auth_token_value = info[4];
  auto auth_callback_value = info[5];
  auto asset_root_value = info[6];

  gchar* address = NULL;
  guint16 port = 0;
  GTlsCertificate* certificate = NULL;
  gchar* origin = NULL;
  FridaAuthenticationService* auth_service = NULL;
  GFile* asset_root = NULL;
  bool valid = true;

  if (!address_value->IsNull()) {
    if (address_value->IsString()) {
      Nan::Utf8String str(address_value);
      address = g_strdup(*str);
    } else {
      Nan::ThrowTypeError("Bad argument, 'address' must be a string");
      valid = false;
    }
  }

  if (valid && !port_value->IsNull()) {
    auto val = Nan::To<int32_t>(port_value).FromMaybe(-1);
    if (val >= 0 && val <= 65535) {
      port = val;
    } else {
      Nan::ThrowTypeError("Bad argument, 'port' must be a valid port number");
      valid = false;
    }
  }

  if (valid && !certificate_value->IsNull()) {
    valid = Runtime::ValueToCertificate(certificate_value, &certificate);
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

  if (valid && !auth_token_value->IsNull()) {
    if (auth_token_value->IsString()) {
      Nan::Utf8String auth_token(auth_token_value);
      auth_service = FRIDA_AUTHENTICATION_SERVICE(
          frida_static_authentication_service_new(*auth_token));
    } else {
      Nan::ThrowTypeError("Bad argument, 'authToken' must be a string");
      valid = false;
    }
  } else if (valid && !auth_callback_value->IsNull()) {
    if (auth_callback_value->IsFunction()) {
      auto auth_callback = Local<Function>::Cast(auth_callback_value);
      auth_service =
          frida_node_authentication_service_new(auth_callback, runtime);
    } else {
      Nan::ThrowTypeError("Bad argument, 'authCallback' must be a function");
      valid = false;
    }
  }

  if (valid && !asset_root_value->IsNull()) {
    if (asset_root_value->IsString()) {
      Nan::Utf8String str(asset_root_value);
      asset_root = g_file_new_for_path(*str);
    } else {
      Nan::ThrowTypeError("Bad argument, 'assetRoot' must be a string");
      valid = false;
    }
  }

  if (valid) {
    auto handle = frida_endpoint_parameters_new(address, port, certificate,
        origin, auth_service, asset_root);
    auto wrapper = new EndpointParameters(handle, runtime);
    g_object_unref(handle);
    auto obj = info.This();
    wrapper->Wrap(obj);

    info.GetReturnValue().Set(obj);
  }

  g_clear_object(&asset_root);
  g_clear_object(&auth_service);
  g_free(origin);
  g_clear_object(&certificate);
  g_free(address);
}

}
