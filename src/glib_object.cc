#include "glib_object.h"

#include <nan.h>

using v8::External;
using v8::FunctionTemplate;
using v8::Local;
using v8::String;
using v8::Value;

namespace frida {

Local<FunctionTemplate> GLibObject::CreateTemplate(Local<String> name,
    Nan::FunctionCallback callback, Runtime* runtime) {
  v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(
    callback, Nan::New<v8::External>(runtime));
  tpl->SetClassName(name);
  tpl->InstanceTemplate()->SetInternalFieldCount(1);
  return tpl;
}

Runtime* GLibObject::GetRuntimeFromConstructorArgs(
    const Nan::FunctionCallbackInfo<Value>& args) {
  return static_cast<Runtime*>(args.Data().As<External>()->Value ());
}

}
