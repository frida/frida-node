#include "application.h"
#include "bus.h"
#include "cancellable.h"
#include "child.h"
#include "crash.h"
#include "device.h"
#include "device_manager.h"
#include "endpoint_parameters.h"
#include "glib_context.h"
#include "iostream.h"
#include "portal_membership.h"
#include "portal_service.h"
#include "process.h"
#include "relay.h"
#include "runtime.h"
#include "script.h"
#include "service.h"
#include "session.h"
#include "signals.h"
#include "spawn.h"
#include "uv_context.h"

using v8::Context;
using v8::Local;
using v8::Object;
using v8::Value;

namespace frida {

static void DisposeAll(void* data);

static void InitAll(Local<Object> exports,
    Local<Value> module,
    Local<Context> context) {
  frida_init();

  auto uv_context = new UVContext(uv_default_loop());
  auto glib_context = new GLibContext(frida_get_main_context());
  auto runtime = new Runtime(uv_context, glib_context);

  Signals::Init(exports, runtime);

  DeviceManager::Init(exports, runtime);
  Device::Init(exports, runtime);
  Application::Init(exports, runtime);
  Process::Init(exports, runtime);
  Spawn::Init(exports, runtime);
  Child::Init(exports, runtime);
  Crash::Init(exports, runtime);
  Bus::Init(exports, runtime);
  Service::Init(exports, runtime);
  Session::Init(exports, runtime);
  Script::Init(exports, runtime);
  Relay::Init(exports, runtime);
  PortalMembership::Init(exports, runtime);
  PortalService::Init(exports, runtime);
  EndpointParameters::Init(exports, runtime);
  IOStream::Init(exports, runtime);
  Cancellable::Init(exports, runtime);

#if NODE_VERSION_AT_LEAST(11, 0, 0)
  node::AddEnvironmentCleanupHook(context->GetIsolate(), DisposeAll, runtime);
#else
  node::AtExit(DisposeAll, runtime);
#endif
}

static void DisposeAll(void* data) {
  auto runtime = static_cast<Runtime*>(data);

  DeviceManager::Dispose(runtime);

  delete runtime;
}

}

NODE_MODULE_CONTEXT_AWARE(frida_binding, frida::InitAll)
