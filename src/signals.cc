#include "signals.h"

#include <cstring>

#define SIGNALS_DATA_CONSTRUCTOR "signals:ctor"

using std::memset;
using v8::Boolean;
using v8::Exception;
using v8::External;
using v8::Function;
using v8::Integer;
using v8::Isolate;
using v8::Local;
using v8::Number;
using v8::Object;
using v8::Persistent;
using v8::String;
using v8::Uint32;
using v8::Value;

namespace frida {

struct SignalsClosure {
  GClosure closure;
  gboolean alive;
  guint signal_id;
  guint handler_id;
  Persistent<Function>* callback;
  Persistent<Object>* parent;
  Signals::TransformCallback transform;
  gpointer transform_data;
  Runtime* runtime;
};

static SignalsClosure* signals_closure_new(guint signal_id,
    Local<Function> callback, Local<Object> parent,
    Signals::TransformCallback transform, gpointer transform_data,
    Runtime* runtime);
static void signals_closure_finalize(gpointer data, GClosure* closure);
static void signals_closure_marshal(GClosure* closure, GValue* return_gvalue,
    guint n_param_values, const GValue* param_values, gpointer invocation_hint,
    gpointer marshal_data);
static Local<Value> signals_closure_gvalue_to_jsvalue(const GValue* gvalue);

Signals::Signals(gpointer handle, TransformCallback transform,
    gpointer transform_data, Runtime* runtime)
    : GLibObject(handle, runtime),
      transform_(transform),
      transform_data_(transform_data),
      connect_(NULL),
      connect_data_(NULL),
      disconnect_(NULL),
      disconnect_data_(NULL),
      closures_(NULL) {
  g_object_ref(handle_);
}

Signals::~Signals() {
  g_assert(closures_ == NULL); // They keep us alive
  frida_unref(handle_);
}

void Signals::Init(Local<Object> exports, Runtime* runtime) {
  auto isolate = Isolate::GetCurrent();

  auto name = Nan::New("Signals").ToLocalChecked();
  auto tpl = CreateTemplate(name, Signals::New, runtime);

  Nan::SetPrototypeMethod(tpl, "connect", Connect);
  Nan::SetPrototypeMethod(tpl, "disconnect", Disconnect);

  auto ctor = Nan::GetFunction(tpl).ToLocalChecked();
  Nan::Set(exports, name, ctor);
  runtime->SetDataPointer(SIGNALS_DATA_CONSTRUCTOR,
      new Persistent<Function>(isolate, ctor));
}

Local<Object> Signals::New(gpointer handle, Runtime* runtime,
    TransformCallback transform, gpointer transform_data) {

  auto ctor = Nan::New<Function>(
      *static_cast<Persistent<Function>*>(
      runtime->GetDataPointer(SIGNALS_DATA_CONSTRUCTOR)));
  const int argc = 3;
  Local<Value> argv[argc] = {
    Nan::New<External>(handle),
    Nan::New<External>(reinterpret_cast<void*>(transform)),
    Nan::New<External>(transform_data)
  };
  return Nan::NewInstance(ctor, argc, argv).ToLocalChecked();
}

void Signals::SetConnectCallback(ConnectCallback callback,
    gpointer user_data) {
  connect_ = callback;
  connect_data_ = user_data;
}

void Signals::SetDisconnectCallback(DisconnectCallback callback,
    gpointer user_data) {
  disconnect_ = callback;
  disconnect_data_ = user_data;
}

NAN_METHOD(Signals::New) {
  if (!info.IsConstructCall()) {
    Nan::ThrowError("Use the `new` keyword to create a new instance");
    return;
  }

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
  auto wrapper = new Signals(handle, transform, transform_data,
      GetRuntimeFromConstructorArgs(info));
  auto obj = info.This();
  wrapper->Wrap(obj);
  info.GetReturnValue().Set(obj);
}

NAN_METHOD(Signals::Connect) {
  auto obj = info.Holder();
  auto wrapper = ObjectWrap::Unwrap<Signals>(obj);
  auto runtime = wrapper->runtime_;

  guint signal_id;
  Local<Function> callback;
  if (!wrapper->GetSignalArguments(info, signal_id, callback))
    return;

  auto signals_closure = signals_closure_new(signal_id, callback, obj,
      wrapper->transform_, wrapper->transform_data_, runtime);
  auto closure = reinterpret_cast<GClosure*>(signals_closure);
  g_closure_ref(closure);
  g_closure_sink(closure);
  wrapper->closures_ = g_slist_append(wrapper->closures_, signals_closure);

  signals_closure->handler_id = g_signal_connect_closure_by_id(wrapper->handle_,
      signal_id, 0, closure, TRUE);
  g_assert(signals_closure->handler_id != 0);

  if (wrapper->connect_ != NULL) {
    wrapper->connect_(g_signal_name(signal_id), wrapper->connect_data_);
  }
}

NAN_METHOD(Signals::Disconnect) {
  auto wrapper = ObjectWrap::Unwrap<Signals>(info.Holder());

  guint signal_id;
  Local<Function> callback;
  if (!wrapper->GetSignalArguments(info, signal_id, callback))
    return;

  for (GSList* cur = wrapper->closures_; cur != NULL; cur = cur->next) {
    auto signals_closure = static_cast<SignalsClosure*>(cur->data);
    auto closure = reinterpret_cast<GClosure*>(signals_closure);
    auto closure_callback = Nan::New<Function>(*signals_closure->callback);
    if (signals_closure->signal_id == signal_id &&
        closure_callback->SameValue(callback)) {
      if (wrapper->disconnect_ != NULL) {
        wrapper->disconnect_(g_signal_name(signal_id),
            wrapper->disconnect_data_);
      }

      wrapper->closures_ = g_slist_delete_link(wrapper->closures_, cur);

      signals_closure->alive = FALSE;

      g_assert(signals_closure->handler_id != 0);
      g_signal_handler_disconnect(wrapper->handle_,
          signals_closure->handler_id);

      g_closure_unref(closure);

      break;
    }
  }
}

bool Signals::GetSignalArguments(const Nan::FunctionCallbackInfo<Value>& info,
    guint& signal_id, Local<Function>& callback) {
  if (info.Length() < 2 || !info[0]->IsString() || !info[1]->IsFunction()) {
    Nan::ThrowTypeError("Bad arguments, expected string and function");
    return false;
  }
  Nan::Utf8String signal_name(info[0]);
  signal_id = g_signal_lookup(*signal_name, G_OBJECT_TYPE(handle_));
  if (signal_id == 0) {
    Nan::ThrowTypeError("Bad signal name");
    return false;
  }
  callback = Local<Function>::Cast(info[1]);
  return true;
}

static SignalsClosure* signals_closure_new(guint signal_id,
    Local<Function> callback, Local<Object> parent,
    Signals::TransformCallback transform, gpointer transform_data,
    Runtime* runtime) {
  auto isolate = Isolate::GetCurrent();

  GClosure* closure = g_closure_new_simple(sizeof(SignalsClosure), NULL);
  g_closure_add_finalize_notifier(closure, NULL, signals_closure_finalize);
  g_closure_set_marshal(closure, signals_closure_marshal);

  SignalsClosure* self = reinterpret_cast<SignalsClosure*>(closure);
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

static void signals_closure_finalize(gpointer data, GClosure* closure) {
  SignalsClosure* self = reinterpret_cast<SignalsClosure*>(closure);

  self->callback->Reset();
  self->parent->Reset();
  delete self->callback;
  delete self->parent;
}

static void signals_closure_marshal(GClosure* closure, GValue* return_gvalue,
    guint n_param_values, const GValue* param_values, gpointer invocation_hint,
    gpointer marshal_data) {
  SignalsClosure* self = reinterpret_cast<SignalsClosure*>(closure);

  g_closure_ref(closure);

  GArray* args = g_array_sized_new(FALSE, FALSE, sizeof(GValue),
      n_param_values);
  g_assert(n_param_values >= 1);
  for (guint i = 1; i != n_param_values; i++) {
    GValue val;
    memset(&val, 0, sizeof(val));
    g_value_init(&val, param_values[i].g_type);
    g_value_copy(&param_values[i], &val);
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
          argv[i] = signals_closure_gvalue_to_jsvalue(value);
      }

      auto context = Isolate::GetCurrent()->GetCurrentContext();
      auto callback = Nan::New<Function>(*self->callback);
      auto recv = Nan::Undefined();
      Local<Value> no_result;
      callback->Call(context, recv, argc, argv).FromMaybe(no_result);

      delete[] argv;
    }

    for (guint i = 0; i != args->len; i++)
      g_value_reset(&g_array_index(args, GValue, i));
    g_array_free(args, TRUE);

    g_closure_unref(closure);
  });
}

static Local<Value> signals_closure_gvalue_to_jsvalue(const GValue* gvalue) {
  auto gtype = G_VALUE_TYPE(gvalue);
  switch (gtype) {
    case G_TYPE_BOOLEAN:
      return Nan::New<Boolean>(g_value_get_boolean(gvalue));
    case G_TYPE_INT:
      return Nan::New<Integer>(g_value_get_int(gvalue));
    case G_TYPE_UINT:
      return Nan::New<Uint32>(g_value_get_uint(gvalue));
    case G_TYPE_FLOAT:
      return Nan::New<Number>(g_value_get_float(gvalue));
    case G_TYPE_DOUBLE:
      return Nan::New<Number>(g_value_get_double(gvalue));
    case G_TYPE_STRING: {
      auto str = g_value_get_string(gvalue);
      if (str == NULL)
        return Nan::Null();
      return Nan::New<String>(str).ToLocalChecked();
    }
    default: {
      if (G_TYPE_IS_ENUM(gtype))
        return Runtime::ValueFromEnum(g_value_get_enum(gvalue), gtype);

      if (g_type_is_a(gtype, G_TYPE_SOCKET_ADDRESS)) {
        return Runtime::ValueFromSocketAddress(
            G_SOCKET_ADDRESS(g_value_get_object(gvalue)));
      }

      g_assert(gtype == G_TYPE_BYTES);
      auto bytes = static_cast<GBytes*>(g_value_get_boxed(gvalue));
      if (bytes != NULL) {
        gsize size;
        gconstpointer data = g_bytes_get_data(bytes, &size);

        return Nan::CopyBuffer(static_cast<const char*>(data), size)
            .ToLocalChecked();
      } else {
        return Nan::Null();
      }
    }
  }
}

}
