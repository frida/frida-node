#include "events.h"

#include <cstring>
#include <nan.h>
#include <node.h>

#define EVENTS_DATA_CONSTRUCTOR "events:ctor"

using v8::Boolean;
using v8::Exception;
using v8::External;
using v8::Function;
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
  v8::Persistent<Function>* callback;
  v8::Persistent<Object>* parent;
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
static Local<Value> events_closure_gvalue_to_jsvalue(const GValue* gvalue);

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

  auto name = Nan::New("Events").ToLocalChecked();
  auto tpl = CreateTemplate(name, Events::New, runtime);

  Nan::SetPrototypeMethod(tpl, "listen", Listen);
  Nan::SetPrototypeMethod(tpl, "unlisten", Unlisten);

  auto ctor = Nan::GetFunction(tpl).ToLocalChecked();
  Nan::Set(exports, name, ctor);
  runtime->SetDataPointer(EVENTS_DATA_CONSTRUCTOR,
      new v8::Persistent<Function>(isolate, ctor));
}

Local<Object> Events::New(gpointer handle, Runtime* runtime,
    TransformCallback transform, gpointer transform_data) {

  auto ctor = Nan::New<v8::Function>(
      *static_cast<v8::Persistent<Function>*>(
      runtime->GetDataPointer(EVENTS_DATA_CONSTRUCTOR)));
  const int argc = 3;
  Local<Value> argv[argc] = {
    Nan::New<v8::External>(handle),
    Nan::New<v8::External>(reinterpret_cast<void*>(transform)),
    Nan::New<v8::External>(transform_data)
  };
  return Nan::NewInstance(ctor, argc, argv).ToLocalChecked();
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

NAN_METHOD(Events::New) {
  if (info.IsConstructCall()) {
    if (info.Length() != 3 ||
        !info[0]->IsExternal() ||
        !info[1]->IsExternal() ||
        !info[2]->IsExternal()) {
      Nan::ThrowTypeError("Bad argument, expected raw handles");
      return;
    }
    auto handle = Local<External>::Cast(info[0])->Value();
    auto transform = reinterpret_cast<TransformCallback>(
        Local<External>::Cast(info[1])->Value());
    auto transform_data = Local<External>::Cast(info[2])->Value();
    auto wrapper = new Events(handle, transform, transform_data,
        GetRuntimeFromConstructorArgs(info));
    auto obj = info.This();
    wrapper->Wrap(obj);
    info.GetReturnValue().Set(obj);
  } else {
    info.GetReturnValue().Set(info.Callee()->NewInstance(0, NULL));
  }
}

NAN_METHOD(Events::Listen) {
  auto obj = info.Holder();
  auto wrapper = ObjectWrap::Unwrap<Events>(obj);
  auto runtime = wrapper->runtime_;

  guint signal_id;
  Local<Function> callback;
  if (!wrapper->GetSignalArguments(info, signal_id, callback))
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

NAN_METHOD(Events::Unlisten) {
  auto wrapper = ObjectWrap::Unwrap<Events>(info.Holder());

  guint signal_id;
  Local<Function> callback;
  if (!wrapper->GetSignalArguments(info, signal_id, callback))
    return;

  for (GSList* cur = wrapper->closures_; cur != NULL; cur = cur->next) {
    auto events_closure = static_cast<EventsClosure*>(cur->data);
    auto closure = reinterpret_cast<GClosure*>(events_closure);
    auto closure_callback = Nan::New<v8::Function>(*events_closure->callback);
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

bool Events::GetSignalArguments(const Nan::FunctionCallbackInfo<Value>& info,
    guint& signal_id, Local<Function>& callback) {
  if (info.Length() < 2 || !info[0]->IsString() || !info[1]->IsFunction()) {
    Nan::ThrowTypeError("Bad arguments, expected string and function");
    return false;
  }
  String::Utf8Value signal_name(Local<String>::Cast(info[0]));
  signal_id = g_signal_lookup(*signal_name, G_OBJECT_TYPE(handle_));
  if (signal_id == 0) {
    Nan::ThrowTypeError("Bad event name");
    return false;
  }
  callback = Local<Function>::Cast(info[1]);
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
  self->callback = new v8::Persistent<Function>(isolate, callback);
  self->parent = new v8::Persistent<Object>(isolate, parent);
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
      auto transform = self->transform;
      auto transform_data = self->transform_data;
      auto signal_name = g_signal_name(self->signal_id);

      const int argc = args->len;
      Local<Value>* argv = new Local<Value>[argc];
      for (guint i = 0; i != args->len; i++) {
        auto value = &g_array_index(args, GValue, i);
        argv[i] = transform != NULL
            ? transform(signal_name, i, value, transform_data)
            : Local<Value>();
        if (argv[i].IsEmpty())
          argv[i] = events_closure_gvalue_to_jsvalue(value);
      }

      auto recv = Nan::New<v8::Object>(*self->parent);
      auto callback = Nan::New<v8::Function>(*self->callback);
      callback->Call(recv, argc, argv);

      delete[] argv;
    }

    for (guint i = 0; i != args->len; i++)
      g_value_reset(&g_array_index(args, GValue, i));
    g_array_free(args, TRUE);

    g_closure_unref(closure);
  });
}

static void events_buffer_free(char* data, void* hint) {
  g_variant_unref(static_cast<GVariant*>(hint));
}

static Local<Value> events_closure_gvalue_to_jsvalue(const GValue* gvalue) {
  switch (G_VALUE_TYPE(gvalue)) {
    case G_TYPE_BOOLEAN:
      return Nan::New<v8::Boolean>(g_value_get_boolean(gvalue));
    case G_TYPE_INT:
      return Nan::New<v8::Integer>(g_value_get_int(gvalue));
    case G_TYPE_UINT:
      return Nan::New<v8::Uint32>(g_value_get_uint(gvalue));
    case G_TYPE_FLOAT:
      return Nan::New<v8::Number>(g_value_get_float(gvalue));
    case G_TYPE_DOUBLE:
      return Nan::New<v8::Number>(g_value_get_float(gvalue));
    case G_TYPE_STRING:
      return Nan::New<v8::String>(g_value_get_string(gvalue)).ToLocalChecked();
    case G_TYPE_VARIANT: {
      auto variant = g_value_dup_variant (gvalue);
      g_assert(variant != NULL);
      g_assert(g_variant_is_of_type(variant, G_VARIANT_TYPE("ay")));
      return Nan::NewBuffer(
          static_cast<char*>(const_cast<void*>(g_variant_get_data(
          variant))), g_variant_get_size(variant), events_buffer_free,
          variant).ToLocalChecked();
    }
    default:
      g_assert_not_reached();
  }
}

}
