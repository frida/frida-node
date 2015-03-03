#include "events.h"

#include "runtime.h"

#include <frida-core.h>
#include <node.h>

#include <cstring>

using v8::Boolean;
using v8::Exception;
using v8::External;
using v8::Function;
using v8::FunctionCallbackInfo;
using v8::FunctionTemplate;
using v8::Handle;
using v8::HandleScope;
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
  guint handler_id;
  Persistent<Object>* parent;
  Persistent<Function>* callback;
};

static EventsClosure* events_closure_new(Handle<Object> parent,
    Handle<Function> callback);
static void events_closure_finalize(gpointer data, GClosure* closure);
static void events_closure_marshal(GClosure* closure, GValue* return_gvalue,
    guint n_param_values, const GValue* param_values, gpointer invocation_hint,
    gpointer marshal_data);
static Local<Value> events_closure_gvalue_to_jsvalue(Isolate* isolate,
    const GValue* gvalue);

Persistent<Function> Events::constructor_;

Events::Events(gpointer handle)
    : handle_(handle),
      closures_(NULL) {
}

Events::~Events() {
  g_assert(closures_ == NULL); // They keep us alive
  frida_unref(handle_);
}

void Events::Init(Handle<Object> exports) {
  auto isolate = Isolate::GetCurrent();

  auto tpl = FunctionTemplate::New(isolate, New);
  tpl->SetClassName(String::NewFromUtf8(isolate, "Events"));
  tpl->InstanceTemplate()->SetInternalFieldCount(1);
  NODE_SET_PROTOTYPE_METHOD(tpl, "listen", Listen);
  NODE_SET_PROTOTYPE_METHOD(tpl, "unlisten", Unlisten);
  exports->Set(String::NewFromUtf8(isolate, "Events"), tpl->GetFunction());

  constructor_.Reset(isolate, tpl->GetFunction());
}

Local<Object> Events::Create(gpointer handle) {
  auto isolate = Isolate::GetCurrent();

  auto constructor = Local<Function>::New(isolate, constructor_);
  const int argc = 1;
  Local<Value> argv[argc] = { External::New(isolate, handle) };
  return constructor->NewInstance(argc, argv);
}

void Events::New(const FunctionCallbackInfo<Value>& args) {
  auto isolate = args.GetIsolate();
  HandleScope scope(isolate);

  if (args.IsConstructCall()) {
    if (args.Length() != 1 || !args[0]->IsExternal()) {
      isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate,
          "Bad argument, expected raw handle")));
      return;
    }
    auto wrapper = new Events(Local<External>::Cast(args[0])->Value());
    auto obj = args.This();
    wrapper->Wrap(obj);
    args.GetReturnValue().Set(obj);
  } else {
    auto constructor = Local<Function>::New(isolate, constructor_);
    args.GetReturnValue().Set(constructor->NewInstance(0, NULL));
  }
}

void Events::Listen(const FunctionCallbackInfo<Value>& args) {
  auto isolate = args.GetIsolate();
  HandleScope scope(isolate);
  auto obj = args.Holder();
  auto wrapper = ObjectWrap::Unwrap<Events>(obj);

  guint signal_id;
  Local<Function> callback;
  if (!wrapper->GetSignalArguments(args, signal_id, callback))
    return;

  auto events_closure = events_closure_new(obj, callback);
  auto closure = reinterpret_cast<GClosure*>(events_closure);
  g_closure_ref(closure);
  g_closure_sink(closure);
  wrapper->closures_ = g_slist_append(wrapper->closures_, events_closure);

  Runtime::GetUVContext()->IncreaseUsage();
  Runtime::GetGLibContext()->Schedule([=]() {
    events_closure->handler_id = g_signal_connect_closure_by_id(
        wrapper->handle_, signal_id, 0, closure, TRUE);
    g_assert(events_closure->handler_id != 0);
  });
}

void Events::Unlisten(const FunctionCallbackInfo<Value>& args) {
  auto isolate = args.GetIsolate();
  HandleScope scope(isolate);
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
    // TODO: also check signal name
    if (closure_callback->SameValue(callback)) {
      wrapper->closures_ = g_slist_delete_link(wrapper->closures_, cur);

      auto handler_id = events_closure->handler_id;
      events_closure->handler_id = 0;

      Runtime::GetUVContext()->DecreaseUsage();
      Runtime::GetGLibContext()->Schedule([=]() {
        g_signal_handler_disconnect(wrapper->handle_, handler_id);
        Runtime::GetUVContext()->Schedule([=]() {
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

static EventsClosure* events_closure_new(Handle<Object> parent,
    Handle<Function> callback) {
  auto isolate = Isolate::GetCurrent();

  GClosure* closure = g_closure_new_simple(sizeof(EventsClosure), NULL);
  g_closure_add_finalize_notifier(closure, NULL, events_closure_finalize);
  g_closure_set_marshal(closure, events_closure_marshal);

  EventsClosure* self = reinterpret_cast<EventsClosure*>(closure);
  self->handler_id = 0;
  self->parent = new Persistent<Object>(isolate, parent);
  self->callback = new Persistent<Function>(isolate, callback);

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
  g_assert_cmpuint(n_param_values, >=, 1);
  for (guint i = 1; i != n_param_values; i++) {
    GValue val;
    memset(&val, 0, sizeof(val));
    g_value_init(&val, param_values[i].g_type);
    g_value_copy(&param_values[i], &val);
    g_array_append_val(args, val);
  }

  Runtime::GetUVContext()->Schedule([=]() {
    const bool still_connected = self->handler_id != 0;
    if (still_connected) {
      auto isolate = Isolate::GetCurrent();

      const int argc = args->len;
      Local<Value>* argv = new Local<Value>[argc];
      for (int i = 0; i != argc; i++) {
        argv[i] = events_closure_gvalue_to_jsvalue(isolate,
            &g_array_index(args, GValue, i));
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
  // TODO: parse JSON
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
      return String::NewFromUtf8(isolate, g_value_get_string(gvalue));
    case G_TYPE_VARIANT: {
      GVariant* variant = g_value_get_variant(gvalue);
      if (variant == NULL) {
        return Null(isolate);
      } else if (g_variant_is_of_type(variant, G_VARIANT_TYPE("ay"))) {
        return node::Encode(isolate, g_variant_get_data(variant),
            g_variant_get_size(variant));
      } else {
        // XXX: extend as necessary
        g_assert_not_reached();
      }
      break;
    }
    default:
      // XXX: extend as necessary
      g_assert_not_reached();
  }
}

}
