#include "events.h"

#include <node.h>

#include <cstring>

#include <nan.h>

#define EVENTS_DATA_CONSTRUCTOR "events:ctor"

using v8::Boolean;
using v8::Exception;
using v8::External;
using v8::Function;
using v8::FunctionCallbackInfo;
using v8::Handle;
using v8::Integer;
using v8::Isolate;
using v8::Local;
using v8::Number;
using v8::Object;
using v8::Persistent;
using v8::String;
using v8::Value;

namespace frida {

typedef struct _EventsClosure EventsClosure;

struct _EventsClosure {
  GClosure closure;
  gboolean alive;
  guint signal_id;
  guint handler_id;
  Persistent<Function>* callback;
  Persistent<Object>* parent;
  Events::TransformCallback transform;
  gpointer transform_data;
  Runtime* runtime;
};

static EventsClosure* events_closure_new(guint signal_id,
    Handle<Function> callback, Handle<Object> parent,
    Events::TransformCallback transform, gpointer transform_data,
    Runtime* runtime);
static void events_closure_finalize(gpointer data, GClosure* closure);
static void events_closure_marshal(GClosure* closure, GValue* return_gvalue,
    guint n_param_values, const GValue* param_values, gpointer invocation_hint,
    gpointer marshal_data);
static Local<Value> events_closure_gvalue_to_jsvalue(Isolate* isolate,
    const GValue* gvalue);

Events::Events(gpointer handle, TransformCallback transform,
    gpointer transform_data, Runtime* runtime)
    : GLibObject(handle, runtime),
      transform_(transform),
      transform_data_(transform_data),
      listen_(NULL),
      listen_data_(NULL),
      unlisten_(NULL),
      unlisten_data_(NULL),
      closures_(NULL) {
  g_object_ref(handle_);
}

Events::~Events() {
  g_assert(closures_ == NULL); // They keep us alive
  frida_unref(handle_);
}

void Events::Init(Handle<Object> exports, Runtime* runtime) {
  auto isolate = Isolate::GetCurrent();

  auto name = NanNew("Events");
  auto tpl = CreateTemplate(isolate, name, New, runtime);

  NODE_SET_PROTOTYPE_METHOD(tpl, "listen", Listen);
  NODE_SET_PROTOTYPE_METHOD(tpl, "unlisten", Unlisten);

  auto ctor = tpl->GetFunction();
  exports->Set(name, ctor);
  runtime->SetDataPointer(EVENTS_DATA_CONSTRUCTOR,
      new Persistent<Function>(isolate, ctor));
}

Local<Object> Events::New(gpointer handle, Runtime* runtime,
    TransformCallback transform, gpointer transform_data) {
  auto isolate = Isolate::GetCurrent();

  auto ctor = Local<Function>::New(isolate,
      *static_cast<Persistent<Function>*>(
      runtime->GetDataPointer(EVENTS_DATA_CONSTRUCTOR)));
  const int argc = 3;
  Local<Value> argv[argc] = {
    External::New(isolate, handle),
    External::New(isolate, reinterpret_cast<void*>(transform)),
    External::New(isolate, transform_data)
  };
  return ctor->NewInstance(argc, argv);
}

void Events::SetListenCallback(ListenCallback callback,
    gpointer user_data) {
  listen_ = callback;
  listen_data_ = user_data;
}

void Events::SetUnlistenCallback(UnlistenCallback callback,
    gpointer user_data) {
  unlisten_ = callback;
  unlisten_data_ = user_data;
}

void Events::New(const FunctionCallbackInfo<Value>& args) {

  NanScope();

  auto isolate = args.GetIsolate();

  if (args.IsConstructCall()) {
    if (args.Length() != 3 ||
        !args[0]->IsExternal() ||
        !args[1]->IsExternal() ||
        !args[2]->IsExternal()) {
      isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate,
          "Bad argument, expected raw handles")));
      return;
    }
    auto handle = Local<External>::Cast(args[0])->Value();
    auto transform = reinterpret_cast<TransformCallback>(
        Local<External>::Cast(args[1])->Value());
    auto transform_data = Local<External>::Cast(args[2])->Value();
    auto wrapper = new Events(handle, transform, transform_data,
        GetRuntimeFromConstructorArgs(args));
    auto obj = args.This();
    wrapper->Wrap(obj);
    args.GetReturnValue().Set(obj);
  } else {
    args.GetReturnValue().Set(args.Callee()->NewInstance(0, NULL));
  }
}

void Events::Listen(const FunctionCallbackInfo<Value>& args) {

  NanScope();

  auto obj = args.Holder();
  auto wrapper = ObjectWrap::Unwrap<Events>(obj);
  auto runtime = wrapper->runtime_;

  guint signal_id;
  Local<Function> callback;
  if (!wrapper->GetSignalArguments(args, signal_id, callback))
    return;

  auto events_closure = events_closure_new(signal_id, callback, obj,
      wrapper->transform_, wrapper->transform_data_, runtime);
  auto closure = reinterpret_cast<GClosure*>(events_closure);
  g_closure_ref(closure);
  g_closure_sink(closure);
  wrapper->closures_ = g_slist_append(wrapper->closures_, events_closure);

  runtime->GetGLibContext()->Schedule([=]() {
    events_closure->handler_id = g_signal_connect_closure_by_id(
        wrapper->handle_, signal_id, 0, closure, TRUE);
    g_assert(events_closure->handler_id != 0);
  });

  if (wrapper->listen_ != NULL) {
    wrapper->listen_(g_signal_name(signal_id), wrapper->listen_data_);
  }
}

void Events::Unlisten(const FunctionCallbackInfo<Value>& args) {

  NanScope();

  auto isolate = args.GetIsolate();
  auto wrapper = ObjectWrap::Unwrap<Events>(args.Holder());

  guint signal_id;
  Local<Function> callback;
  if (!wrapper->GetSignalArguments(args, signal_id, callback))
    return;

  for (GSList* cur = wrapper->closures_; cur != NULL; cur = cur->next) {
    auto events_closure = static_cast<EventsClosure*>(cur->data);
    auto closure = reinterpret_cast<GClosure*>(events_closure);
    auto closure_callback = Local<Function>::New(isolate,
        *events_closure->callback);
    if (events_closure->signal_id == signal_id &&
        closure_callback->SameValue(callback)) {
      if (wrapper->unlisten_ != NULL) {
        wrapper->unlisten_(g_signal_name(signal_id), wrapper->unlisten_data_);
      }

      wrapper->closures_ = g_slist_delete_link(wrapper->closures_, cur);

      events_closure->alive = FALSE;

      auto runtime = wrapper->runtime_;
      runtime->GetGLibContext()->Schedule([=]() {
        g_assert(events_closure->handler_id != 0);
        g_signal_handler_disconnect(wrapper->handle_,
            events_closure->handler_id);
        runtime->GetUVContext()->Schedule([=]() {
          g_closure_unref(closure);
        });
      });

      break;
    }
  }
}

bool Events::GetSignalArguments(const FunctionCallbackInfo<Value>& args,
    guint& signal_id, Local<Function>& callback) {
  if (args.Length() < 2 || !args[0]->IsString() || !args[1]->IsFunction()) {
    Isolate* isolate = args.GetIsolate();
    isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate,
        "Bad arguments, expected string and function")));
    return false;
  }
  String::Utf8Value signal_name(Local<String>::Cast(args[0]));
  signal_id = g_signal_lookup(*signal_name, G_OBJECT_TYPE(handle_));
  if (signal_id == 0) {
    Isolate* isolate = args.GetIsolate();
    isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate,
        "Bad event name")));
    return false;
  }
  callback = Local<Function>::Cast(args[1]);
  return true;
}

static EventsClosure* events_closure_new(guint signal_id,
    Handle<Function> callback, Handle<Object> parent,
    Events::TransformCallback transform, gpointer transform_data,
    Runtime* runtime) {
  auto isolate = Isolate::GetCurrent();

  GClosure* closure = g_closure_new_simple(sizeof(EventsClosure), NULL);
  g_closure_add_finalize_notifier(closure, NULL, events_closure_finalize);
  g_closure_set_marshal(closure, events_closure_marshal);

  EventsClosure* self = reinterpret_cast<EventsClosure*>(closure);
  self->alive = TRUE;
  self->signal_id = signal_id;
  self->handler_id = 0;
  self->callback = new Persistent<Function>(isolate, callback);
  self->parent = new Persistent<Object>(isolate, parent);
  self->transform = transform;
  self->transform_data = transform_data;
  self->runtime = runtime;

  return self;
}

static void events_closure_finalize(gpointer data, GClosure* closure) {
  EventsClosure* self = reinterpret_cast<EventsClosure*>(closure);

  self->callback->Reset();
  self->parent->Reset();
  delete self->callback;
  delete self->parent;
}

static void events_closure_marshal(GClosure* closure, GValue* return_gvalue,
    guint n_param_values, const GValue* param_values, gpointer invocation_hint,
    gpointer marshal_data) {
  EventsClosure* self = reinterpret_cast<EventsClosure*>(closure);

  g_closure_ref(closure);

  GArray* args = g_array_sized_new(FALSE, FALSE, sizeof (GValue), n_param_values);
  g_assert(n_param_values >= 1);
  for (guint i = 1; i != n_param_values; i++) {
    GValue val;
    memset(&val, 0, sizeof(val));
    if (param_values[i].g_type == G_TYPE_POINTER) {
      g_assert(n_param_values - i >= 2);
      g_assert(G_VALUE_TYPE(&param_values[i + 1]) == G_TYPE_INT);
      auto bytes = g_bytes_new(g_value_get_pointer(&param_values[i]),
          g_value_get_int(&param_values[i + 1]));
      g_value_init(&val, G_TYPE_VARIANT);
      g_value_set_variant(&val,
          g_variant_new_from_bytes(G_VARIANT_TYPE("ay"), bytes, TRUE));
      g_bytes_unref(bytes);
      i++;
    } else {
      g_value_init(&val, param_values[i].g_type);
      g_value_copy(&param_values[i], &val);
    }
    g_array_append_val(args, val);
  }

  self->runtime->GetUVContext()->Schedule([=]() {
    if (self->alive) {
      auto isolate = Isolate::GetCurrent();

      auto transform = self->transform;
      auto transform_data = self->transform_data;
      auto signal_name = g_signal_name(self->signal_id);

      const int argc = args->len;
      Local<Value>* argv = new Local<Value>[argc];
      for (guint i = 0; i != args->len; i++) {
        auto value = &g_array_index(args, GValue, i);
        argv[i] = transform != NULL
            ? transform(isolate, signal_name, i, value, transform_data)
            : Local<Value>();
        if (argv[i].IsEmpty())
          argv[i] = events_closure_gvalue_to_jsvalue(isolate, value);
      }

      auto recv = Local<Object>::New(isolate, *self->parent);
      auto callback = Local<Function>::New(isolate, *self->callback);
      callback->Call(recv, argc, argv);

      delete[] argv;
    }

    for (guint i = 0; i != args->len; i++)
      g_value_reset(&g_array_index(args, GValue, i));
    g_array_free(args, TRUE);

    g_closure_unref(closure);
  });
}

static Local<Value> events_closure_gvalue_to_jsvalue(Isolate* isolate,
    const GValue* gvalue) {
  switch (G_VALUE_TYPE(gvalue)) {
    case G_TYPE_BOOLEAN:
      return Boolean::New(isolate, g_value_get_boolean(gvalue));
    case G_TYPE_INT:
      return Integer::New(isolate, g_value_get_int(gvalue));
    case G_TYPE_UINT:
      return Integer::NewFromUnsigned(isolate, g_value_get_uint(gvalue));
    case G_TYPE_FLOAT:
      return Number::New(isolate, g_value_get_float(gvalue));
    case G_TYPE_DOUBLE:
      return Number::New(isolate, g_value_get_double(gvalue));
    case G_TYPE_STRING:
      return NanNew(g_value_get_string(gvalue));
    case G_TYPE_VARIANT: {
      auto variant = g_value_get_variant (gvalue);
      g_assert(variant != NULL);
      g_assert(g_variant_is_of_type(variant, G_VARIANT_TYPE("ay")));
      return node::Encode(isolate,
          g_variant_get_data(variant),
          g_variant_get_size(variant),
          node::BUFFER);
    }
    default:
      g_assert_not_reached();
  }
}

}
