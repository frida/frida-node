#include "device_manager.h"
#include "events.h"
#include "main_context.h"

#include <node.h>

using namespace v8;

namespace frida {

static void InitAll(Handle<Object> exports) {
  frida_init();

  auto main_context = new MainContext(frida_get_main_context());
  Events::Init(exports, main_context);
  DeviceManager::Init(exports);
}

}

NODE_MODULE(frida, frida::InitAll)
