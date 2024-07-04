#include "iostream.h"

#include "operation.h"
#include "signals.h"

#define IOSTREAM_DATA_CONSTRUCTOR "iostream:ctor"

using v8::DEFAULT;
using v8::External;
using v8::Function;
using v8::Isolate;
using v8::Local;
using v8::Number;
using v8::Object;
using v8::Persistent;
using v8::ReadOnly;
using v8::Value;

namespace frida {

static void UnrefGBytes(char* data, void* hint);

IOStream::IOStream(GIOStream* handle, Runtime* runtime)
    : GLibObject(handle, runtime) {
  g_object_ref(handle_);
}

IOStream::~IOStream() {
  g_object_unref(handle_);
}

void IOStream::Init(Local<Object> exports, Runtime* runtime) {
  auto isolate = Isolate::GetCurrent();

  auto name = Nan::New("IOStream").ToLocalChecked();
  auto tpl = CreateTemplate(name, New, runtime);

  auto instance_tpl = tpl->InstanceTemplate();
  auto data = Local<Value>();
  Nan::SetAccessor(instance_tpl, Nan::New("isClosed").ToLocalChecked(),
      IsClosed, 0, data, DEFAULT, ReadOnly);

  Nan::SetPrototypeMethod(tpl, "close", Close);
  Nan::SetPrototypeMethod(tpl, "read", Read);
  Nan::SetPrototypeMethod(tpl, "write", Write);

  auto ctor = Nan::GetFunction(tpl).ToLocalChecked();
  Nan::Set(exports, name, ctor);
  runtime->SetDataPointer(IOSTREAM_DATA_CONSTRUCTOR,
      new Persistent<Function>(isolate, ctor));
}

Local<Object> IOStream::New(gpointer handle, Runtime* runtime) {
  auto ctor = Nan::New<Function>(
      *static_cast<Persistent<Function>*>(
      runtime->GetDataPointer(IOSTREAM_DATA_CONSTRUCTOR)));
  const int argc = 1;
  Local<Value> argv[argc] = { Nan::New<External>(handle) };
  return Nan::NewInstance(ctor, argc, argv).ToLocalChecked();
}

NAN_METHOD(IOStream::New) {
  if (!info.IsConstructCall()) {
    Nan::ThrowError("Use the `new` keyword to create a new instance");
    return;
  }

  if (info.Length() != 1 || !info[0]->IsExternal()) {
    Nan::ThrowTypeError("Bad argument, expected raw handle");
    return;
  }

  auto runtime = GetRuntimeFromConstructorArgs(info);

  auto handle = static_cast<GIOStream*>(
      Local<External>::Cast(info[0])->Value());
  auto wrapper = new IOStream(handle, runtime);
  auto obj = info.This();
  wrapper->Wrap(obj);
  Nan::Set(obj, Nan::New("signals").ToLocalChecked(),
      Signals::New(handle, runtime));

  info.GetReturnValue().Set(obj);
}

NAN_PROPERTY_GETTER(IOStream::IsClosed) {
  auto handle = ObjectWrap::Unwrap<IOStream>(
      info.Holder())->GetHandle<GIOStream>();

  info.GetReturnValue().Set(
      static_cast<bool>(g_io_stream_is_closed(handle)));
}

namespace {

class CloseOperation : public Operation<GIOStream> {
 protected:
  void Begin() {
    g_io_stream_close_async(handle_, G_PRIORITY_DEFAULT, cancellable_,
        OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    g_io_stream_close_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    return Nan::Undefined();
  }
};

}

NAN_METHOD(IOStream::Close) {
  auto isolate = info.GetIsolate();
  auto wrapper = ObjectWrap::Unwrap<IOStream>(info.Holder());

  auto operation = new CloseOperation();
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

namespace {

class ReadOperation : public Operation<GIOStream> {
 public:
  ReadOperation(gsize count)
    : stream_(NULL),
      count_(count),
      bytes_(NULL) {
  }

 protected:
  void Begin() {
    stream_ = g_io_stream_get_input_stream(handle_);

    g_input_stream_read_bytes_async(stream_, count_, G_PRIORITY_DEFAULT,
        cancellable_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    bytes_ = g_input_stream_read_bytes_finish(stream_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    gsize size;
    auto data = g_bytes_get_data(bytes_, &size);
    return Nan::NewBuffer(static_cast<char*>(const_cast<void*>(data)), size,
        UnrefGBytes, bytes_).ToLocalChecked();
  }

 private:
  GInputStream* stream_;
  gsize count_;
  GBytes* bytes_;
};

}

NAN_METHOD(IOStream::Read) {
  auto isolate = info.GetIsolate();
  auto wrapper = ObjectWrap::Unwrap<IOStream>(info.Holder());

  if (info.Length() < 1 || !info[0]->IsNumber()) {
    Nan::ThrowTypeError("Bad argument, expected amount to read");
    return;
  }
  auto count = Nan::To<int32_t>(info[0]).FromMaybe(-1);
  if (count <= 0) {
    Nan::ThrowTypeError("Bad argument, expected amount to read");
    return;
  }

  auto operation = new ReadOperation(count);
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

namespace {

class WriteOperation : public Operation<GIOStream> {
 public:
  WriteOperation(Isolate* isolate, Local<Value> buffer)
    : stream_(NULL),
      data_(node::Buffer::Data(buffer)),
      count_(node::Buffer::Length(buffer)) {
    buffer_.Reset(buffer);
  }

 protected:
  void Begin() {
    stream_ = g_io_stream_get_output_stream(handle_);

    g_output_stream_write_all_async(stream_, data_, count_, G_PRIORITY_DEFAULT,
        cancellable_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    g_output_stream_write_all_finish(stream_, result, NULL, error);
  }

  Local<Value> Result(Isolate* isolate) {
    return Nan::Undefined();
  }

 private:
  GOutputStream* stream_;
  Nan::Persistent<Value, Nan::CopyablePersistentTraits<Value>> buffer_;
  const void* data_;
  gsize count_;
};

}

NAN_METHOD(IOStream::Write) {
  auto isolate = info.GetIsolate();
  auto wrapper = ObjectWrap::Unwrap<IOStream>(info.Holder());

  auto num_args = info.Length();
  if (num_args < 1) {
    Nan::ThrowTypeError("Expected a buffer");
    return;
  }

  auto buffer = info[0];
  if (!node::Buffer::HasInstance(buffer)) {
    Nan::ThrowTypeError("Expected a buffer");
    return;
  }

  auto operation = new WriteOperation(isolate, buffer);
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

static void UnrefGBytes(char* data, void* hint) {
  g_bytes_unref(static_cast<GBytes*>(hint));
}

}
