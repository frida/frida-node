#ifndef FRIDANODE_AUTHENTICATION_H
#define FRIDANODE_AUTHENTICATION_H

#include "runtime.h"

#include <frida-core.h>
#include <node.h>

G_BEGIN_DECLS

#define FRIDA_TYPE_NODE_AUTHENTICATION_SERVICE (frida_node_authentication_service_get_type())
G_DECLARE_FINAL_TYPE(
    FridaNodeAuthenticationService,
    frida_node_authentication_service,
    FRIDA,
    NODE_AUTHENTICATION_SERVICE,
    GObject)

FridaAuthenticationService* frida_node_authentication_service_new(
    v8::Local<v8::Function> callback, frida::Runtime* runtime);

G_END_DECLS

#endif
