#include "authentication.h"

using frida::Runtime;
using v8::External;
using v8::Function;
using v8::Isolate;
using v8::Local;
using v8::Object;
using v8::Persistent;
using v8::String;
using v8::Value;

struct _FridaNodeAuthenticationService {
  GObject parent;
  Persistent<Function>* callback;
  Runtime* runtime;
};

static void frida_node_authentication_service_iface_init(gpointer g_iface,
    gpointer iface_data);
static void frida_node_authentication_service_dispose(GObject* object);
static void frida_node_authentication_service_authenticate(
    FridaAuthenticationService* service, const gchar* token,
    GCancellable* cancellable, GAsyncReadyCallback callback,
    gpointer user_data);
static gchar* frida_node_authentication_service_authenticate_finish(
    FridaAuthenticationService* service, GAsyncResult* result, GError** error);

G_DEFINE_TYPE_EXTENDED(
    FridaNodeAuthenticationService,
    frida_node_authentication_service,
    G_TYPE_OBJECT,
    0,
    G_IMPLEMENT_INTERFACE(FRIDA_TYPE_AUTHENTICATION_SERVICE,
      frida_node_authentication_service_iface_init))

FridaAuthenticationService* frida_node_authentication_service_new(
    Local<Function> callback, Runtime* runtime) {
  auto service = static_cast<FridaNodeAuthenticationService*>(
      g_object_new(FRIDA_TYPE_NODE_AUTHENTICATION_SERVICE, NULL));
  service->callback = new Persistent<Function>(Isolate::GetCurrent(), callback);
  service->runtime = runtime;
  return FRIDA_AUTHENTICATION_SERVICE(service);
}

static void frida_node_authentication_service_class_init(
    FridaNodeAuthenticationServiceClass* klass)
{
  GObjectClass* object_class = G_OBJECT_CLASS(klass);

  object_class->dispose = frida_node_authentication_service_dispose;
}

static void frida_node_authentication_service_iface_init(gpointer g_iface,
    gpointer iface_data) {
  auto iface = static_cast<FridaAuthenticationServiceIface*>(g_iface);

  iface->authenticate =
      frida_node_authentication_service_authenticate;
  iface->authenticate_finish =
      frida_node_authentication_service_authenticate_finish;
}

static void frida_node_authentication_service_init(
    FridaNodeAuthenticationService* self) {
}

static void frida_node_authentication_service_dispose(GObject* object) {
  auto self = FRIDA_NODE_AUTHENTICATION_SERVICE(object);

  Persistent<Function>* callback = self->callback;
  if (callback != NULL) {
    self->callback = NULL;
    self->runtime->GetUVContext()->Schedule([=]() {
      delete callback;
    });
  }

  G_OBJECT_CLASS(frida_node_authentication_service_parent_class)->dispose(
      object);
}

static NAN_METHOD(OnAuthenticationSuccess) {
  auto task = static_cast<GTask*>(info.Data().As<External>()->Value ());
  auto self = static_cast<FridaNodeAuthenticationService*>(
      g_task_get_source_object(task));

  gchar* session_info = NULL;
  if (info.Length() >= 1) {
    auto val = info[0];
    if (val->IsObject() && !val->IsNull()) {
      Local<String> json = self->runtime->ValueToJson(val);
      Nan::Utf8String str(json);
      session_info = g_strdup(*str);
    }
  }

  if (session_info != NULL) {
    g_task_return_pointer(task, session_info, g_free);
  } else {
    g_task_return_new_error(task, FRIDA_ERROR, FRIDA_ERROR_INVALID_ARGUMENT,
        "Internal error");
  }

  g_object_unref(task);
}

static NAN_METHOD(OnAuthenticationFailure) {
  auto task = static_cast<GTask*>(info.Data().As<External>()->Value ());

  Local<Value> fallback_message = Nan::New("Internal error").ToLocalChecked();
  Local<Value> message = fallback_message;
  if (info.Length() >= 1) {
    auto error_value = info[0];
    if (error_value->IsObject()) {
      message = Nan::Get(error_value.As<Object>(),
          Nan::New("message").ToLocalChecked()).FromMaybe(fallback_message);
    }
  }

  Nan::Utf8String str(message);
  g_task_return_new_error(task, FRIDA_ERROR, FRIDA_ERROR_INVALID_ARGUMENT,
      "%s", *str);

  g_object_unref(task);
}

static void frida_node_authentication_service_authenticate(
    FridaAuthenticationService* service, const gchar* token,
    GCancellable* cancellable, GAsyncReadyCallback callback,
    gpointer user_data) {
  auto self = FRIDA_NODE_AUTHENTICATION_SERVICE(service);

  auto task = g_task_new(self, cancellable, callback, user_data);
  g_task_set_task_data(task, g_strdup(token), g_free);

  self->runtime->GetUVContext()->Schedule([=]() {
    auto context = Isolate::GetCurrent()->GetCurrentContext();

    bool scheduled = false;
    Local<Value> no_result = Nan::Undefined();

    auto callback = Nan::New<Function>(*self->callback);
    Local<Value> token_value = Nan::New(static_cast<gchar*>(
          g_task_get_task_data(task))).ToLocalChecked();

    Local<Value> promise_value = callback->Call(context, Nan::Undefined(), 1,
        &token_value).FromMaybe(no_result);
    if (promise_value->IsObject()) {
      auto promise = promise_value.As<Object>();
      auto then = Nan::Get(promise, Nan::New("then").ToLocalChecked())
          .FromMaybe(no_result);
      if (then->IsFunction()) {
        Local<Value> argv[] = {
          Nan::New<Function>(OnAuthenticationSuccess, Nan::New<External>(task)),
          Nan::New<Function>(OnAuthenticationFailure, Nan::New<External>(task)),
        };
        scheduled = !then.As<Function>()->Call(context, promise_value,
            G_N_ELEMENTS(argv), argv).IsEmpty();
      }
    }

    if (!scheduled) {
      g_task_return_new_error(task, FRIDA_ERROR, FRIDA_ERROR_INVALID_ARGUMENT,
          "Internal error");
      g_object_unref(task);
    }
  });
}

static gchar* frida_node_authentication_service_authenticate_finish(
    FridaAuthenticationService* service, GAsyncResult* result, GError** error) {
  return static_cast<gchar*>(g_task_propagate_pointer(G_TASK(result), error));
}
