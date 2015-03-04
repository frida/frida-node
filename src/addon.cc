#include "device.h"
#include "device_manager.h"
#include "events.h"
#include "glib_context.h"
#include "process.h"
#include "runtime.h"
#include "script.h"
#include "session.h"
#include "uv_context.h"

#include <node.h>

using v8::Context;
using v8::Handle;
using v8::Object;
using v8::Value;

namespace frida {

static void InitAll(Handle<Object> exports,
    Handle<Value> module,
    Handle<Context> context) {
  frida_init();

  auto uv_context = new UVContext(uv_default_loop());
  auto glib_context = new GLibContext(frida_get_main_context());
  auto runtime = new Runtime(uv_context, glib_context);

  Events::Init(exports, runtime);

  DeviceManager::Init(exports, runtime);
  Device::Init(exports, runtime);
  Process::Init(exports, runtime);
  Session::Init(exports, runtime);
  Script::Init(exports, runtime);
}

}

NODE_MODULE(frida, frida::InitAll)
