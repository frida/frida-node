#include <frida-core.h>
#include <node_api.h>


typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaDeviceManager * handle;
  GError * error;
  GCancellable * cancellable;
} DeviceManagerCloseOperation;

static gboolean device_manager_close_begin (gpointer user_data);
static void device_manager_close_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void device_manager_close_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void device_manager_close_operation_free (DeviceManagerCloseOperation * operation);

static napi_value
device_manager_close (napi_env env,
                      napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaDeviceManager * handle;
  napi_deferred deferred;
  napi_value promise;
  DeviceManagerCloseOperation * operation;
  GSource * source;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  status = napi_create_promise (env, &deferred, &promise);
  if (status != napi_ok)
    return NULL;

  operation = g_slice_new0 (DeviceManagerCloseOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0)
  {
    status = napi_get_value_object (env, args[0], &operation->cancellable);
    if (status != napi_ok)
    {
      napi_throw_error (env, NULL, "failed to get argument value");
      goto invalid_argument;
    }
  else
  {
    operation->cancellable = NULL;
  }

  source = g_idle_source_new ();
  g_source_set_callback (source, device_manager_close_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, device_manager_close_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    device_manager_close_operation_free (operation);
    return NULL;
  }
}

static gboolean
device_manager_close_begin (gpointer user_data)
{
  DeviceManagerCloseOperation * operation = user_data;

  frida_device_manager_close (operation->handle,
      operation->cancellable,
      device_manager_close_end, operation);

  return G_SOURCE_REMOVE;
}

static void
device_manager_close_end (GObject * source_object,
                          GAsyncResult * res,
                          gpointer user_data)
{
  DeviceManagerCloseOperation * operation = user_data;

  frida_device_manager_close_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (device_manager_close_tsfn, operation, napi_tsfn_blocking);
}

static void
device_manager_close_deliver (napi_env env,
                              napi_value js_cb,
                              void * context,
                              void * data)
{
  DeviceManagerCloseOperation * operation = data;

  if (operation->error != NULL)
  {
    napi_value message;
    napi_create_string_utf8 (env, operation->error->message, NAPI_AUTO_LENGTH,
        &message);
    napi_value error_obj;
    napi_create_error (env, NULL, message, &error_obj);
    napi_reject_deferred (env, operation->deferred, error_obj);
    g_error_free (operation->error);
  }
  else
  {
    napi_value result;
    napi_get_undefined (env, &result);
    napi_resolve_deferred (env, operation->deferred, result);
  }

  device_manager_close_operation_free (operation);

  napi_unref_threadsafe_function (env, device_manager_close_tsfn);
}


static void
device_manager_close_operation_free (DeviceManagerCloseOperation * operation)
{
  
  
  g_slice_free (DeviceManagerCloseOperation, operation);
}


typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaDeviceManager * handle;
  GError * error;
  const gchar * id;
  gint timeout;
  GCancellable * cancellable;
  FridaDevice * return_value;
} DeviceManagerGetDeviceByIdOperation;

static gboolean device_manager_get_device_by_id_begin (gpointer user_data);
static void device_manager_get_device_by_id_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void device_manager_get_device_by_id_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void device_manager_get_device_by_id_operation_free (DeviceManagerGetDeviceByIdOperation * operation);

static napi_value
device_manager_get_device_by_id (napi_env env,
                                 napi_callback_info info)
{
  size_t argc = 3;
  napi_value args[3];
  napi_status status;
  napi_value jsthis;
  FridaDeviceManager * handle;
  napi_deferred deferred;
  napi_value promise;
  DeviceManagerGetDeviceByIdOperation * operation;
  GSource * source;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  status = napi_create_promise (env, &deferred, &promise);
  if (status != napi_ok)
    return NULL;

  operation = g_slice_new0 (DeviceManagerGetDeviceByIdOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  size_t id_length;
  status = napi_get_value_string_utf8 (env, args[0], NULL, 0, &id_length);
  if (status != napi_ok)
  {
    napi_throw_error (env, NULL, "failed to get string length");
    goto invalid_argument;
  }
  operation->id = g_malloc (id_length + 1);
  status = napi_get_value_string_utf8 (env, args[0], operation->id, id_length + 1, &id_length);
  if (status != napi_ok)
  {
    napi_throw_error (env, NULL, "failed to get string value");
    goto invalid_argument;
  }

  if (argc <= 1)
  {
    napi_throw_type_error (env, NULL, "missing argument: timeout");
    goto invalid_argument;
  }
  status = napi_get_value_int32 (env, args[1], &operation->timeout);
  if (status != napi_ok)
  {
    napi_throw_error (env, NULL, "failed to get argument value");
    goto invalid_argument;
  }

  if (argc > 2)
  {
    status = napi_get_value_object (env, args[2], &operation->cancellable);
    if (status != napi_ok)
    {
      napi_throw_error (env, NULL, "failed to get argument value");
      goto invalid_argument;
    }
  else
  {
    operation->cancellable = NULL;
  }

  source = g_idle_source_new ();
  g_source_set_callback (source, device_manager_get_device_by_id_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, device_manager_get_device_by_id_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    device_manager_get_device_by_id_operation_free (operation);
    return NULL;
  }
}

static gboolean
device_manager_get_device_by_id_begin (gpointer user_data)
{
  DeviceManagerGetDeviceByIdOperation * operation = user_data;

  frida_device_manager_get_device_by_id (operation->handle,
      operation->id, operation->timeout, operation->cancellable,
      device_manager_get_device_by_id_end, operation);

  return G_SOURCE_REMOVE;
}

static void
device_manager_get_device_by_id_end (GObject * source_object,
                                     GAsyncResult * res,
                                     gpointer user_data)
{
  DeviceManagerGetDeviceByIdOperation * operation = user_data;

  operation->return_value = frida_device_manager_get_device_by_id_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (device_manager_get_device_by_id_tsfn, operation, napi_tsfn_blocking);
}

static void
device_manager_get_device_by_id_deliver (napi_env env,
                                         napi_value js_cb,
                                         void * context,
                                         void * data)
{
  DeviceManagerGetDeviceByIdOperation * operation = data;

  if (operation->error != NULL)
  {
    napi_value message;
    napi_create_string_utf8 (env, operation->error->message, NAPI_AUTO_LENGTH,
        &message);
    napi_value error_obj;
    napi_create_error (env, NULL, message, &error_obj);
    napi_reject_deferred (env, operation->deferred, error_obj);
    g_error_free (operation->error);
  }
  else
  {
    napi_value result;
    result = Runtime_ValueFromFrida.device (env, operation->return_value);
    napi_resolve_deferred (env, operation->deferred, result);
  }

  device_manager_get_device_by_id_operation_free (operation);

  napi_unref_threadsafe_function (env, device_manager_get_device_by_id_tsfn);
}


static void
device_manager_get_device_by_id_operation_free (DeviceManagerGetDeviceByIdOperation * operation)
{
  g_free (operation->id);
  
  g_slice_free (DeviceManagerGetDeviceByIdOperation, operation);
}


typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaDeviceManager * handle;
  GError * error;
  FridaDeviceType type;
  gint timeout;
  GCancellable * cancellable;
  FridaDevice * return_value;
} DeviceManagerGetDeviceByTypeOperation;

static gboolean device_manager_get_device_by_type_begin (gpointer user_data);
static void device_manager_get_device_by_type_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void device_manager_get_device_by_type_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void device_manager_get_device_by_type_operation_free (DeviceManagerGetDeviceByTypeOperation * operation);

static napi_value
device_manager_get_device_by_type (napi_env env,
                                   napi_callback_info info)
{
  size_t argc = 3;
  napi_value args[3];
  napi_status status;
  napi_value jsthis;
  FridaDeviceManager * handle;
  napi_deferred deferred;
  napi_value promise;
  DeviceManagerGetDeviceByTypeOperation * operation;
  GSource * source;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  status = napi_create_promise (env, &deferred, &promise);
  if (status != napi_ok)
    return NULL;

  operation = g_slice_new0 (DeviceManagerGetDeviceByTypeOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc <= 0)
  {
    napi_throw_type_error (env, NULL, "missing argument: type");
    goto invalid_argument;
  }
  status = napi_get_value_unknown (env, args[0], &operation->type);
  if (status != napi_ok)
  {
    napi_throw_error (env, NULL, "failed to get argument value");
    goto invalid_argument;
  }

  if (argc <= 1)
  {
    napi_throw_type_error (env, NULL, "missing argument: timeout");
    goto invalid_argument;
  }
  status = napi_get_value_int32 (env, args[1], &operation->timeout);
  if (status != napi_ok)
  {
    napi_throw_error (env, NULL, "failed to get argument value");
    goto invalid_argument;
  }

  if (argc > 2)
  {
    status = napi_get_value_object (env, args[2], &operation->cancellable);
    if (status != napi_ok)
    {
      napi_throw_error (env, NULL, "failed to get argument value");
      goto invalid_argument;
    }
  else
  {
    operation->cancellable = NULL;
  }

  source = g_idle_source_new ();
  g_source_set_callback (source, device_manager_get_device_by_type_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, device_manager_get_device_by_type_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    device_manager_get_device_by_type_operation_free (operation);
    return NULL;
  }
}

static gboolean
device_manager_get_device_by_type_begin (gpointer user_data)
{
  DeviceManagerGetDeviceByTypeOperation * operation = user_data;

  frida_device_manager_get_device_by_type (operation->handle,
      operation->type, operation->timeout, operation->cancellable,
      device_manager_get_device_by_type_end, operation);

  return G_SOURCE_REMOVE;
}

static void
device_manager_get_device_by_type_end (GObject * source_object,
                                       GAsyncResult * res,
                                       gpointer user_data)
{
  DeviceManagerGetDeviceByTypeOperation * operation = user_data;

  operation->return_value = frida_device_manager_get_device_by_type_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (device_manager_get_device_by_type_tsfn, operation, napi_tsfn_blocking);
}

static void
device_manager_get_device_by_type_deliver (napi_env env,
                                           napi_value js_cb,
                                           void * context,
                                           void * data)
{
  DeviceManagerGetDeviceByTypeOperation * operation = data;

  if (operation->error != NULL)
  {
    napi_value message;
    napi_create_string_utf8 (env, operation->error->message, NAPI_AUTO_LENGTH,
        &message);
    napi_value error_obj;
    napi_create_error (env, NULL, message, &error_obj);
    napi_reject_deferred (env, operation->deferred, error_obj);
    g_error_free (operation->error);
  }
  else
  {
    napi_value result;
    result = Runtime_ValueFromFrida.device (env, operation->return_value);
    napi_resolve_deferred (env, operation->deferred, result);
  }

  device_manager_get_device_by_type_operation_free (operation);

  napi_unref_threadsafe_function (env, device_manager_get_device_by_type_tsfn);
}


static void
device_manager_get_device_by_type_operation_free (DeviceManagerGetDeviceByTypeOperation * operation)
{
  
  
  g_slice_free (DeviceManagerGetDeviceByTypeOperation, operation);
}


typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaDeviceManager * handle;
  GError * error;
  const gchar * id;
  gint timeout;
  GCancellable * cancellable;
  FridaDevice * return_value;
} DeviceManagerFindDeviceByIdOperation;

static gboolean device_manager_find_device_by_id_begin (gpointer user_data);
static void device_manager_find_device_by_id_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void device_manager_find_device_by_id_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void device_manager_find_device_by_id_operation_free (DeviceManagerFindDeviceByIdOperation * operation);

static napi_value
device_manager_find_device_by_id (napi_env env,
                                  napi_callback_info info)
{
  size_t argc = 3;
  napi_value args[3];
  napi_status status;
  napi_value jsthis;
  FridaDeviceManager * handle;
  napi_deferred deferred;
  napi_value promise;
  DeviceManagerFindDeviceByIdOperation * operation;
  GSource * source;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  status = napi_create_promise (env, &deferred, &promise);
  if (status != napi_ok)
    return NULL;

  operation = g_slice_new0 (DeviceManagerFindDeviceByIdOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  size_t id_length;
  status = napi_get_value_string_utf8 (env, args[0], NULL, 0, &id_length);
  if (status != napi_ok)
  {
    napi_throw_error (env, NULL, "failed to get string length");
    goto invalid_argument;
  }
  operation->id = g_malloc (id_length + 1);
  status = napi_get_value_string_utf8 (env, args[0], operation->id, id_length + 1, &id_length);
  if (status != napi_ok)
  {
    napi_throw_error (env, NULL, "failed to get string value");
    goto invalid_argument;
  }

  if (argc <= 1)
  {
    napi_throw_type_error (env, NULL, "missing argument: timeout");
    goto invalid_argument;
  }
  status = napi_get_value_int32 (env, args[1], &operation->timeout);
  if (status != napi_ok)
  {
    napi_throw_error (env, NULL, "failed to get argument value");
    goto invalid_argument;
  }

  if (argc > 2)
  {
    status = napi_get_value_object (env, args[2], &operation->cancellable);
    if (status != napi_ok)
    {
      napi_throw_error (env, NULL, "failed to get argument value");
      goto invalid_argument;
    }
  else
  {
    operation->cancellable = NULL;
  }

  source = g_idle_source_new ();
  g_source_set_callback (source, device_manager_find_device_by_id_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, device_manager_find_device_by_id_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    device_manager_find_device_by_id_operation_free (operation);
    return NULL;
  }
}

static gboolean
device_manager_find_device_by_id_begin (gpointer user_data)
{
  DeviceManagerFindDeviceByIdOperation * operation = user_data;

  frida_device_manager_find_device_by_id (operation->handle,
      operation->id, operation->timeout, operation->cancellable,
      device_manager_find_device_by_id_end, operation);

  return G_SOURCE_REMOVE;
}

static void
device_manager_find_device_by_id_end (GObject * source_object,
                                      GAsyncResult * res,
                                      gpointer user_data)
{
  DeviceManagerFindDeviceByIdOperation * operation = user_data;

  operation->return_value = frida_device_manager_find_device_by_id_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (device_manager_find_device_by_id_tsfn, operation, napi_tsfn_blocking);
}

static void
device_manager_find_device_by_id_deliver (napi_env env,
                                          napi_value js_cb,
                                          void * context,
                                          void * data)
{
  DeviceManagerFindDeviceByIdOperation * operation = data;

  if (operation->error != NULL)
  {
    napi_value message;
    napi_create_string_utf8 (env, operation->error->message, NAPI_AUTO_LENGTH,
        &message);
    napi_value error_obj;
    napi_create_error (env, NULL, message, &error_obj);
    napi_reject_deferred (env, operation->deferred, error_obj);
    g_error_free (operation->error);
  }
  else
  {
    napi_value result;
    result = Runtime_ValueFromFrida.device (env, operation->return_value);
    napi_resolve_deferred (env, operation->deferred, result);
  }

  device_manager_find_device_by_id_operation_free (operation);

  napi_unref_threadsafe_function (env, device_manager_find_device_by_id_tsfn);
}


static void
device_manager_find_device_by_id_operation_free (DeviceManagerFindDeviceByIdOperation * operation)
{
  g_free (operation->id);
  
  g_slice_free (DeviceManagerFindDeviceByIdOperation, operation);
}


typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaDeviceManager * handle;
  GError * error;
  FridaDeviceType type;
  gint timeout;
  GCancellable * cancellable;
  FridaDevice * return_value;
} DeviceManagerFindDeviceByTypeOperation;

static gboolean device_manager_find_device_by_type_begin (gpointer user_data);
static void device_manager_find_device_by_type_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void device_manager_find_device_by_type_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void device_manager_find_device_by_type_operation_free (DeviceManagerFindDeviceByTypeOperation * operation);

static napi_value
device_manager_find_device_by_type (napi_env env,
                                    napi_callback_info info)
{
  size_t argc = 3;
  napi_value args[3];
  napi_status status;
  napi_value jsthis;
  FridaDeviceManager * handle;
  napi_deferred deferred;
  napi_value promise;
  DeviceManagerFindDeviceByTypeOperation * operation;
  GSource * source;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  status = napi_create_promise (env, &deferred, &promise);
  if (status != napi_ok)
    return NULL;

  operation = g_slice_new0 (DeviceManagerFindDeviceByTypeOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc <= 0)
  {
    napi_throw_type_error (env, NULL, "missing argument: type");
    goto invalid_argument;
  }
  status = napi_get_value_unknown (env, args[0], &operation->type);
  if (status != napi_ok)
  {
    napi_throw_error (env, NULL, "failed to get argument value");
    goto invalid_argument;
  }

  if (argc <= 1)
  {
    napi_throw_type_error (env, NULL, "missing argument: timeout");
    goto invalid_argument;
  }
  status = napi_get_value_int32 (env, args[1], &operation->timeout);
  if (status != napi_ok)
  {
    napi_throw_error (env, NULL, "failed to get argument value");
    goto invalid_argument;
  }

  if (argc > 2)
  {
    status = napi_get_value_object (env, args[2], &operation->cancellable);
    if (status != napi_ok)
    {
      napi_throw_error (env, NULL, "failed to get argument value");
      goto invalid_argument;
    }
  else
  {
    operation->cancellable = NULL;
  }

  source = g_idle_source_new ();
  g_source_set_callback (source, device_manager_find_device_by_type_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, device_manager_find_device_by_type_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    device_manager_find_device_by_type_operation_free (operation);
    return NULL;
  }
}

static gboolean
device_manager_find_device_by_type_begin (gpointer user_data)
{
  DeviceManagerFindDeviceByTypeOperation * operation = user_data;

  frida_device_manager_find_device_by_type (operation->handle,
      operation->type, operation->timeout, operation->cancellable,
      device_manager_find_device_by_type_end, operation);

  return G_SOURCE_REMOVE;
}

static void
device_manager_find_device_by_type_end (GObject * source_object,
                                        GAsyncResult * res,
                                        gpointer user_data)
{
  DeviceManagerFindDeviceByTypeOperation * operation = user_data;

  operation->return_value = frida_device_manager_find_device_by_type_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (device_manager_find_device_by_type_tsfn, operation, napi_tsfn_blocking);
}

static void
device_manager_find_device_by_type_deliver (napi_env env,
                                            napi_value js_cb,
                                            void * context,
                                            void * data)
{
  DeviceManagerFindDeviceByTypeOperation * operation = data;

  if (operation->error != NULL)
  {
    napi_value message;
    napi_create_string_utf8 (env, operation->error->message, NAPI_AUTO_LENGTH,
        &message);
    napi_value error_obj;
    napi_create_error (env, NULL, message, &error_obj);
    napi_reject_deferred (env, operation->deferred, error_obj);
    g_error_free (operation->error);
  }
  else
  {
    napi_value result;
    result = Runtime_ValueFromFrida.device (env, operation->return_value);
    napi_resolve_deferred (env, operation->deferred, result);
  }

  device_manager_find_device_by_type_operation_free (operation);

  napi_unref_threadsafe_function (env, device_manager_find_device_by_type_tsfn);
}


static void
device_manager_find_device_by_type_operation_free (DeviceManagerFindDeviceByTypeOperation * operation)
{
  
  
  g_slice_free (DeviceManagerFindDeviceByTypeOperation, operation);
}


typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaDeviceManager * handle;
  GError * error;
  GCancellable * cancellable;
  FridaDeviceList * return_value;
} DeviceManagerEnumerateDevicesOperation;

static gboolean device_manager_enumerate_devices_begin (gpointer user_data);
static void device_manager_enumerate_devices_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void device_manager_enumerate_devices_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void device_manager_enumerate_devices_operation_free (DeviceManagerEnumerateDevicesOperation * operation);

static napi_value
device_manager_enumerate_devices (napi_env env,
                                  napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaDeviceManager * handle;
  napi_deferred deferred;
  napi_value promise;
  DeviceManagerEnumerateDevicesOperation * operation;
  GSource * source;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  status = napi_create_promise (env, &deferred, &promise);
  if (status != napi_ok)
    return NULL;

  operation = g_slice_new0 (DeviceManagerEnumerateDevicesOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0)
  {
    status = napi_get_value_object (env, args[0], &operation->cancellable);
    if (status != napi_ok)
    {
      napi_throw_error (env, NULL, "failed to get argument value");
      goto invalid_argument;
    }
  else
  {
    operation->cancellable = NULL;
  }

  source = g_idle_source_new ();
  g_source_set_callback (source, device_manager_enumerate_devices_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, device_manager_enumerate_devices_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    device_manager_enumerate_devices_operation_free (operation);
    return NULL;
  }
}

static gboolean
device_manager_enumerate_devices_begin (gpointer user_data)
{
  DeviceManagerEnumerateDevicesOperation * operation = user_data;

  frida_device_manager_enumerate_devices (operation->handle,
      operation->cancellable,
      device_manager_enumerate_devices_end, operation);

  return G_SOURCE_REMOVE;
}

static void
device_manager_enumerate_devices_end (GObject * source_object,
                                      GAsyncResult * res,
                                      gpointer user_data)
{
  DeviceManagerEnumerateDevicesOperation * operation = user_data;

  operation->return_value = frida_device_manager_enumerate_devices_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (device_manager_enumerate_devices_tsfn, operation, napi_tsfn_blocking);
}

static void
device_manager_enumerate_devices_deliver (napi_env env,
                                          napi_value js_cb,
                                          void * context,
                                          void * data)
{
  DeviceManagerEnumerateDevicesOperation * operation = data;

  if (operation->error != NULL)
  {
    napi_value message;
    napi_create_string_utf8 (env, operation->error->message, NAPI_AUTO_LENGTH,
        &message);
    napi_value error_obj;
    napi_create_error (env, NULL, message, &error_obj);
    napi_reject_deferred (env, operation->deferred, error_obj);
    g_error_free (operation->error);
  }
  else
  {
    napi_value result;
    result = Runtime_ValueFromFrida.devicelist (env, operation->return_value);
    napi_resolve_deferred (env, operation->deferred, result);
  }

  device_manager_enumerate_devices_operation_free (operation);

  napi_unref_threadsafe_function (env, device_manager_enumerate_devices_tsfn);
}


static void
device_manager_enumerate_devices_operation_free (DeviceManagerEnumerateDevicesOperation * operation)
{
  
  
  g_slice_free (DeviceManagerEnumerateDevicesOperation, operation);
}


typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaDeviceManager * handle;
  GError * error;
  const gchar * address;
  FridaRemoteDeviceOptions * options;
  GCancellable * cancellable;
  FridaDevice * return_value;
} DeviceManagerAddRemoteDeviceOperation;

static gboolean device_manager_add_remote_device_begin (gpointer user_data);
static void device_manager_add_remote_device_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void device_manager_add_remote_device_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void device_manager_add_remote_device_operation_free (DeviceManagerAddRemoteDeviceOperation * operation);

static napi_value
device_manager_add_remote_device (napi_env env,
                                  napi_callback_info info)
{
  size_t argc = 3;
  napi_value args[3];
  napi_status status;
  napi_value jsthis;
  FridaDeviceManager * handle;
  napi_deferred deferred;
  napi_value promise;
  DeviceManagerAddRemoteDeviceOperation * operation;
  GSource * source;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  status = napi_create_promise (env, &deferred, &promise);
  if (status != napi_ok)
    return NULL;

  operation = g_slice_new0 (DeviceManagerAddRemoteDeviceOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  size_t address_length;
  status = napi_get_value_string_utf8 (env, args[0], NULL, 0, &address_length);
  if (status != napi_ok)
  {
    napi_throw_error (env, NULL, "failed to get string length");
    goto invalid_argument;
  }
  operation->address = g_malloc (address_length + 1);
  status = napi_get_value_string_utf8 (env, args[0], operation->address, address_length + 1, &address_length);
  if (status != napi_ok)
  {
    napi_throw_error (env, NULL, "failed to get string value");
    goto invalid_argument;
  }

  if (argc <= 1)
  {
    napi_throw_type_error (env, NULL, "missing argument: options");
    goto invalid_argument;
  }
  status = napi_get_value_unknown (env, args[1], &operation->options);
  if (status != napi_ok)
  {
    napi_throw_error (env, NULL, "failed to get argument value");
    goto invalid_argument;
  }

  if (argc > 2)
  {
    status = napi_get_value_object (env, args[2], &operation->cancellable);
    if (status != napi_ok)
    {
      napi_throw_error (env, NULL, "failed to get argument value");
      goto invalid_argument;
    }
  else
  {
    operation->cancellable = NULL;
  }

  source = g_idle_source_new ();
  g_source_set_callback (source, device_manager_add_remote_device_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, device_manager_add_remote_device_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    device_manager_add_remote_device_operation_free (operation);
    return NULL;
  }
}

static gboolean
device_manager_add_remote_device_begin (gpointer user_data)
{
  DeviceManagerAddRemoteDeviceOperation * operation = user_data;

  frida_device_manager_add_remote_device (operation->handle,
      operation->address, operation->options, operation->cancellable,
      device_manager_add_remote_device_end, operation);

  return G_SOURCE_REMOVE;
}

static void
device_manager_add_remote_device_end (GObject * source_object,
                                      GAsyncResult * res,
                                      gpointer user_data)
{
  DeviceManagerAddRemoteDeviceOperation * operation = user_data;

  operation->return_value = frida_device_manager_add_remote_device_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (device_manager_add_remote_device_tsfn, operation, napi_tsfn_blocking);
}

static void
device_manager_add_remote_device_deliver (napi_env env,
                                          napi_value js_cb,
                                          void * context,
                                          void * data)
{
  DeviceManagerAddRemoteDeviceOperation * operation = data;

  if (operation->error != NULL)
  {
    napi_value message;
    napi_create_string_utf8 (env, operation->error->message, NAPI_AUTO_LENGTH,
        &message);
    napi_value error_obj;
    napi_create_error (env, NULL, message, &error_obj);
    napi_reject_deferred (env, operation->deferred, error_obj);
    g_error_free (operation->error);
  }
  else
  {
    napi_value result;
    result = Runtime_ValueFromFrida.device (env, operation->return_value);
    napi_resolve_deferred (env, operation->deferred, result);
  }

  device_manager_add_remote_device_operation_free (operation);

  napi_unref_threadsafe_function (env, device_manager_add_remote_device_tsfn);
}


static void
device_manager_add_remote_device_operation_free (DeviceManagerAddRemoteDeviceOperation * operation)
{
  g_free (operation->address);
  
  g_slice_free (DeviceManagerAddRemoteDeviceOperation, operation);
}


typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaDeviceManager * handle;
  GError * error;
  const gchar * address;
  GCancellable * cancellable;
} DeviceManagerRemoveRemoteDeviceOperation;

static gboolean device_manager_remove_remote_device_begin (gpointer user_data);
static void device_manager_remove_remote_device_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void device_manager_remove_remote_device_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void device_manager_remove_remote_device_operation_free (DeviceManagerRemoveRemoteDeviceOperation * operation);

static napi_value
device_manager_remove_remote_device (napi_env env,
                                     napi_callback_info info)
{
  size_t argc = 2;
  napi_value args[2];
  napi_status status;
  napi_value jsthis;
  FridaDeviceManager * handle;
  napi_deferred deferred;
  napi_value promise;
  DeviceManagerRemoveRemoteDeviceOperation * operation;
  GSource * source;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  status = napi_create_promise (env, &deferred, &promise);
  if (status != napi_ok)
    return NULL;

  operation = g_slice_new0 (DeviceManagerRemoveRemoteDeviceOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  size_t address_length;
  status = napi_get_value_string_utf8 (env, args[0], NULL, 0, &address_length);
  if (status != napi_ok)
  {
    napi_throw_error (env, NULL, "failed to get string length");
    goto invalid_argument;
  }
  operation->address = g_malloc (address_length + 1);
  status = napi_get_value_string_utf8 (env, args[0], operation->address, address_length + 1, &address_length);
  if (status != napi_ok)
  {
    napi_throw_error (env, NULL, "failed to get string value");
    goto invalid_argument;
  }

  if (argc > 1)
  {
    status = napi_get_value_object (env, args[1], &operation->cancellable);
    if (status != napi_ok)
    {
      napi_throw_error (env, NULL, "failed to get argument value");
      goto invalid_argument;
    }
  else
  {
    operation->cancellable = NULL;
  }

  source = g_idle_source_new ();
  g_source_set_callback (source, device_manager_remove_remote_device_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, device_manager_remove_remote_device_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    device_manager_remove_remote_device_operation_free (operation);
    return NULL;
  }
}

static gboolean
device_manager_remove_remote_device_begin (gpointer user_data)
{
  DeviceManagerRemoveRemoteDeviceOperation * operation = user_data;

  frida_device_manager_remove_remote_device (operation->handle,
      operation->address, operation->cancellable,
      device_manager_remove_remote_device_end, operation);

  return G_SOURCE_REMOVE;
}

static void
device_manager_remove_remote_device_end (GObject * source_object,
                                         GAsyncResult * res,
                                         gpointer user_data)
{
  DeviceManagerRemoveRemoteDeviceOperation * operation = user_data;

  frida_device_manager_remove_remote_device_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (device_manager_remove_remote_device_tsfn, operation, napi_tsfn_blocking);
}

static void
device_manager_remove_remote_device_deliver (napi_env env,
                                             napi_value js_cb,
                                             void * context,
                                             void * data)
{
  DeviceManagerRemoveRemoteDeviceOperation * operation = data;

  if (operation->error != NULL)
  {
    napi_value message;
    napi_create_string_utf8 (env, operation->error->message, NAPI_AUTO_LENGTH,
        &message);
    napi_value error_obj;
    napi_create_error (env, NULL, message, &error_obj);
    napi_reject_deferred (env, operation->deferred, error_obj);
    g_error_free (operation->error);
  }
  else
  {
    napi_value result;
    napi_get_undefined (env, &result);
    napi_resolve_deferred (env, operation->deferred, result);
  }

  device_manager_remove_remote_device_operation_free (operation);

  napi_unref_threadsafe_function (env, device_manager_remove_remote_device_tsfn);
}


static void
device_manager_remove_remote_device_operation_free (DeviceManagerRemoveRemoteDeviceOperation * operation)
{
  g_free (operation->address);
  
  g_slice_free (DeviceManagerRemoveRemoteDeviceOperation, operation);
}


static napi_threadsafe_function device_manager_close_tsfn;
static napi_threadsafe_function device_manager_get_device_by_id_tsfn;
static napi_threadsafe_function device_manager_get_device_by_type_tsfn;
static napi_threadsafe_function device_manager_find_device_by_id_tsfn;
static napi_threadsafe_function device_manager_find_device_by_type_tsfn;
static napi_threadsafe_function device_manager_enumerate_devices_tsfn;
static napi_threadsafe_function device_manager_add_remote_device_tsfn;
static napi_threadsafe_function device_manager_remove_remote_device_tsfn;

static napi_value
Init (napi_env env,
      napi_value exports)
{
  napi_status status;
  napi_property_descriptor properties[] =
  {
    { "close", 0, device_manager_close, 0, 0, 0, napi_default, 0 },
    { "getDeviceById", 0, device_manager_get_device_by_id, 0, 0, 0, napi_default, 0 },
    { "getDeviceByType", 0, device_manager_get_device_by_type, 0, 0, 0, napi_default, 0 },
    { "findDeviceById", 0, device_manager_find_device_by_id, 0, 0, 0, napi_default, 0 },
    { "findDeviceByType", 0, device_manager_find_device_by_type, 0, 0, 0, napi_default, 0 },
    { "enumerateDevices", 0, device_manager_enumerate_devices, 0, 0, 0, napi_default, 0 },
    { "addRemoteDevice", 0, device_manager_add_remote_device, 0, 0, 0, napi_default, 0 },
    { "removeRemoteDevice", 0, device_manager_remove_remote_device, 0, 0, 0, napi_default, 0 },
  };

  napi_value constructor;
  napi_define_class (env, "DeviceManager", NAPI_AUTO_LENGTH, device_manager_constructor, NULL, G_N_ELEMENTS (properties), properties, &constructor);

  napi_set_named_property (env, exports, "DeviceManager", constructor);

  {
    napi_value resource_name;
    napi_create_string_utf8 (env, "close", NAPI_AUTO_LENGTH, &resource_name);
    napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, device_manager_close_deliver, &device_manager_close_tsfn);
  }
  {
    napi_value resource_name;
    napi_create_string_utf8 (env, "getDeviceById", NAPI_AUTO_LENGTH, &resource_name);
    napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, device_manager_get_device_by_id_deliver, &device_manager_get_device_by_id_tsfn);
  }
  {
    napi_value resource_name;
    napi_create_string_utf8 (env, "getDeviceByType", NAPI_AUTO_LENGTH, &resource_name);
    napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, device_manager_get_device_by_type_deliver, &device_manager_get_device_by_type_tsfn);
  }
  {
    napi_value resource_name;
    napi_create_string_utf8 (env, "findDeviceById", NAPI_AUTO_LENGTH, &resource_name);
    napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, device_manager_find_device_by_id_deliver, &device_manager_find_device_by_id_tsfn);
  }
  {
    napi_value resource_name;
    napi_create_string_utf8 (env, "findDeviceByType", NAPI_AUTO_LENGTH, &resource_name);
    napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, device_manager_find_device_by_type_deliver, &device_manager_find_device_by_type_tsfn);
  }
  {
    napi_value resource_name;
    napi_create_string_utf8 (env, "enumerateDevices", NAPI_AUTO_LENGTH, &resource_name);
    napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, device_manager_enumerate_devices_deliver, &device_manager_enumerate_devices_tsfn);
  }
  {
    napi_value resource_name;
    napi_create_string_utf8 (env, "addRemoteDevice", NAPI_AUTO_LENGTH, &resource_name);
    napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, device_manager_add_remote_device_deliver, &device_manager_add_remote_device_tsfn);
  }
  {
    napi_value resource_name;
    napi_create_string_utf8 (env, "removeRemoteDevice", NAPI_AUTO_LENGTH, &resource_name);
    napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, device_manager_remove_remote_device_deliver, &device_manager_remove_remote_device_tsfn);
  }

  return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)

