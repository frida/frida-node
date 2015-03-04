#include "glib_object.h"

using v8::External;
using v8::FunctionCallback;
using v8::FunctionCallbackInfo;
using v8::FunctionTemplate;
using v8::Handle;
using v8::Isolate;
using v8::Local;
using v8::String;
using v8::Value;

namespace frida {

Local<FunctionTemplate> GLibObject::CreateTemplate(Isolate* isolate,
    Handle<String> name, FunctionCallback callback, Runtime* runtime) {
  auto tpl = FunctionTemplate::New(isolate, callback,
      External::New(isolate, runtime));
  tpl->SetClassName(name);
  tpl->InstanceTemplate()->SetInternalFieldCount(1);
  return tpl;
}

Runtime* GLibObject::GetRuntimeFromConstructorArgs(
    const FunctionCallbackInfo<Value>& args) {
  return static_cast<Runtime*>(args.Data().As<External>()->Value ());
}

}
