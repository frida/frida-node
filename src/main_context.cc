#include "main_context.h"

namespace frida {

MainContext::MainContext(GMainContext* main_context) : handle_(main_context) {
  g_mutex_init(&mutex_);
  g_cond_init(&cond_);
}

MainContext::~MainContext() {
  g_cond_clear(&cond_);
  g_mutex_clear(&mutex_);
}

void MainContext::schedule(std::function<void ()> f) {
  auto source = g_idle_source_new();
  g_source_set_callback(source, InvokeCallback, new std::function<void ()>(f),
      DestroyCallback);
  g_source_attach(source, handle_);
  g_source_unref(source);
}

void MainContext::perform(std::function<void ()> f) {
  volatile bool finished = false;

  auto work = new std::function<void ()>([this, f, &finished]() {
    f();

    g_mutex_lock(&mutex_);
    finished = true;
    g_cond_signal(&cond_);
    g_mutex_unlock(&mutex_);
  });

  auto source = g_idle_source_new();
  g_source_set_callback(source, InvokeCallback, work, DestroyCallback);
  g_source_attach(source, handle_);
  g_source_unref(source);

  g_mutex_lock(&mutex_);
  while (!finished)
    g_cond_wait(&cond_, &mutex_);
  g_mutex_unlock(&mutex_);
}

gboolean MainContext::InvokeCallback(gpointer data) {
  auto f = static_cast<std::function<void ()>*>(data);
  (*f)();
  return FALSE;
}

void MainContext::DestroyCallback(gpointer data) {
  auto f = static_cast<std::function<void ()>*>(data);
  delete f;
}

}
