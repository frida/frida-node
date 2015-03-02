#include "events.h"

#include "runtime.h"

#include <frida-core.h>
#include <node.h>

#include <cstring>

using namespace v8;

namespace frida {

typedef struct _EventsClosure EventsClosure;
typedef struct _EventsClosureInvocation EventsClosureInvocation;

struct _EventsClosure {
  GClosure closure;
  guint handler_id;
  Persistent<Function>* callback;
};

struct _EventsClosureInvocation
{
  EventsClosure* closure;
  GArray* args;
};

static EventsClosure* events_closure_new(Handle<Object> parent,
    Handle<Function> callback);
static void events_closure_finalize(gpointer data, GClosure* closure);
static void events_closure_marshal(GClosure* closure, GValue* return_gvalue,
    guint n_param_values, const GValue* param_values, gpointer invocation_hint,
    gpointer marshal_data);

Persistent<Function> Events::constructor_;

Events::Events(gpointer handle)
    : handle_(handle),
      closures_(NULL),
      pending_(NULL) {
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
    if (args.Length() < 1 || !args[0]->IsExternal()) {
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
  auto closure = events_closure_new(obj, callback);
  wrapper->closures_ = g_slist_append(wrapper->closures_, closure);
  Runtime::GetMainContext()->schedule([=] () {
    closure->handler_id = g_signal_connect_closure_by_id(wrapper->handle_,
        signal_id, 0, reinterpret_cast<GClosure*>(closure), TRUE);
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
    auto closure = static_cast<EventsClosure*>(cur->data);
    auto closure_callback = Local<Function>::New(isolate, *closure->callback);
    if (closure_callback->SameValue(callback)) {
      wrapper->closures_ = g_slist_delete_link(wrapper->closures_, cur);
      Runtime::GetMainContext()->schedule([=] () {
        g_signal_handler_disconnect(wrapper->handle_, closure->handler_id);
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
  EventsClosure* self = reinterpret_cast<EventsClosure*>(closure);
  self->handler_id = 0;
  self->callback = new Persistent<Function>(isolate, callback);

  g_closure_set_marshal(closure, events_closure_marshal);

  return self;
}

static void events_closure_finalize(gpointer data, GClosure* closure) {
  EventsClosure* self = reinterpret_cast<EventsClosure*>(closure);

  self->callback->Reset();
  delete self->callback;
}

static void events_closure_marshal(GClosure* closure, GValue* return_gvalue,
    guint n_param_values, const GValue* param_values, gpointer invocation_hint,
    gpointer marshal_data) {
  EventsClosure* self = reinterpret_cast<EventsClosure*>(closure);

  auto invocation = g_slice_new(EventsClosureInvocation);
  invocation->closure = self;
  invocation->args = g_array_sized_new(FALSE, FALSE, sizeof (GValue), n_param_values);
  for (guint i = 0; i != n_param_values; i++) {
    GValue val;
    memset(&val, 0, sizeof(val));
    g_value_init(&val, param_values[i].g_type);
    g_value_copy(&param_values[i], &val);
    g_array_append_val(invocation->args, val);
  }
}

}
