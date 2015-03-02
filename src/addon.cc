#include "device_manager.h"
#include "events.h"
#include "glib_context.h"
#include "runtime.h"
#include "uv_context.h"

#include <node.h>

using namespace v8;

namespace frida {

static void InitAll(Handle<Object> exports) {
  frida_init();

  auto uv_context = new UVContext(uv_default_loop());
  auto glib_context = new GLibContext(frida_get_main_context());
  Runtime::Init(uv_context, glib_context);

  Events::Init(exports);
  DeviceManager::Init(exports);
}

}

NODE_MODULE(frida, frida::InitAll)
