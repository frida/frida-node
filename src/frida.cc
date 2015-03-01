#include "device_manager.h"

using namespace v8;

namespace frida {

static void InitAll(Handle<Object> exports) {
  frida_init();

  DeviceManager::Init(exports);
}

}

NODE_MODULE(frida, frida::InitAll)
