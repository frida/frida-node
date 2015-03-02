#include "uv_context.h"

#define UV_CONTEXT_LOCK()   g_mutex_lock(&mutex_)
#define UV_CONTEXT_UNLOCK() g_mutex_unlock(&mutex_)
#define UV_CONTEXT_WAIT()   g_cond_wait(&cond_, &mutex_)
#define UV_CONTEXT_SIGNAL() g_cond_signal(&cond_)

namespace frida {

UVContext::UVContext(uv_loop_t* loop) : pending_(NULL) {
  uv_async_init(loop, &async_, ProcessPendingWrapper);
  async_.data = this;
  g_mutex_init(&mutex_);
  g_cond_init(&cond_);
}

UVContext::~UVContext() {
  g_cond_clear(&cond_);
  g_mutex_clear(&mutex_);
  uv_close(reinterpret_cast<uv_handle_t*>(&async_), NULL);
}

void UVContext::schedule(std::function<void ()> f) {
  auto work = new std::function<void ()>(f);
  UV_CONTEXT_LOCK();
  pending_ = g_slist_append(pending_, work);
  UV_CONTEXT_UNLOCK();
  uv_async_send(&async_);
}

void UVContext::perform(std::function<void ()> f) {
  volatile bool finished = false;

  schedule([this, f, &finished]() {
    f();

    UV_CONTEXT_LOCK();
    finished = true;
    UV_CONTEXT_SIGNAL();
    UV_CONTEXT_UNLOCK();
  });

  UV_CONTEXT_LOCK();
  while (!finished)
    UV_CONTEXT_WAIT();
  UV_CONTEXT_UNLOCK();
}

void UVContext::ProcessPending() {
  UV_CONTEXT_LOCK();
  while (pending_ != NULL) {
    auto work = static_cast<std::function<void ()>*>(pending_->data);
    pending_ = g_slist_delete_link(pending_, pending_);
    UV_CONTEXT_UNLOCK();
    (*work)();
    delete work;
    UV_CONTEXT_LOCK();
  }
  UV_CONTEXT_UNLOCK();
}

void UVContext::ProcessPendingWrapper(uv_async_t* handle) {
  static_cast<UVContext*>(handle->data)->ProcessPending();
}

}
