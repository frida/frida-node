#include "device_manager.h"
#include "events.h"
#include "main_context.h"
#include "runtime.h"

#include <node.h>

using namespace v8;

namespace frida {

static void InitAll(Handle<Object> exports) {
  frida_init();

  Runtime::Init(new MainContext(frida_get_main_context()));
  Events::Init(exports);
  DeviceManager::Init(exports);
}

}

NODE_MODULE(frida, frida::InitAll)
