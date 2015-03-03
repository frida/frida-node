#include "glib_context.h"

#define GLIB_CONTEXT_LOCK()   g_mutex_lock(&mutex_)
#define GLIB_CONTEXT_UNLOCK() g_mutex_unlock(&mutex_)
#define GLIB_CONTEXT_WAIT()   g_cond_wait(&cond_, &mutex_)
#define GLIB_CONTEXT_SIGNAL() g_cond_signal(&cond_)

namespace frida {

GLibContext::GLibContext(GMainContext* main_context) : main_context_(main_context) {
  g_mutex_init(&mutex_);
  g_cond_init(&cond_);
}

GLibContext::~GLibContext() {
  g_cond_clear(&cond_);
  g_mutex_clear(&mutex_);
}

void GLibContext::Schedule(std::function<void ()> f) {
  auto source = g_idle_source_new();
  g_source_set_callback(source, InvokeCallback, new std::function<void ()>(f),
      DestroyCallback);
  g_source_attach(source, main_context_);
  g_source_unref(source);
}

void GLibContext::Perform(std::function<void ()> f) {
  volatile bool finished = false;

  auto work = new std::function<void ()>([this, f, &finished]() {
    f();

    GLIB_CONTEXT_LOCK();
    finished = true;
    GLIB_CONTEXT_SIGNAL();
    GLIB_CONTEXT_UNLOCK();
  });

  auto source = g_idle_source_new();
  g_source_set_callback(source, InvokeCallback, work, DestroyCallback);
  g_source_attach(source, main_context_);
  g_source_unref(source);

  GLIB_CONTEXT_LOCK();
  while (!finished)
    GLIB_CONTEXT_WAIT();
  GLIB_CONTEXT_UNLOCK();
}

gboolean GLibContext::InvokeCallback(gpointer data) {
  auto f = static_cast<std::function<void ()>*>(data);
  (*f)();
  return FALSE;
}

void GLibContext::DestroyCallback(gpointer data) {
  auto f = static_cast<std::function<void ()>*>(data);
  delete f;
}

}
