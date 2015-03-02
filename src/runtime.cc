#include "runtime.h"

namespace frida {

UVContext* Runtime::uv_context_ = NULL;
GLibContext* Runtime::glib_context_ = NULL;

}
