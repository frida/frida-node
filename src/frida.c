#include <frida-core.h>
#include <node_api.h>

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaDeviceManager * handle;
  GError * error;
  GCancellable * cancellable;
} FdnDeviceManagerCloseOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaDeviceManager * handle;
  GError * error;
  gchar * id;
  gint timeout;
  GCancellable * cancellable;
  FridaDevice * return_value;
} FdnDeviceManagerGetDeviceByIdOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaDeviceManager * handle;
  GError * error;
  FridaDeviceType type;
  gint timeout;
  GCancellable * cancellable;
  FridaDevice * return_value;
} FdnDeviceManagerGetDeviceByTypeOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaDeviceManager * handle;
  GError * error;
  gchar * id;
  gint timeout;
  GCancellable * cancellable;
  FridaDevice * return_value;
} FdnDeviceManagerFindDeviceByIdOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaDeviceManager * handle;
  GError * error;
  FridaDeviceType type;
  gint timeout;
  GCancellable * cancellable;
  FridaDevice * return_value;
} FdnDeviceManagerFindDeviceByTypeOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaDeviceManager * handle;
  GError * error;
  GCancellable * cancellable;
  FridaDeviceList * return_value;
} FdnDeviceManagerEnumerateDevicesOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaDeviceManager * handle;
  GError * error;
  gchar * address;
  FridaRemoteDeviceOptions * options;
  GCancellable * cancellable;
  FridaDevice * return_value;
} FdnDeviceManagerAddRemoteDeviceOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaDeviceManager * handle;
  GError * error;
  gchar * address;
  GCancellable * cancellable;
} FdnDeviceManagerRemoveRemoteDeviceOperation;


static void fdn_device_manager_register (napi_env env, napi_value exports);
static gboolean fdn_device_manager_from_value (napi_env env, napi_value value, FridaDeviceManager ** result);
static napi_value fdn_device_manager_to_value (napi_env env, FridaDeviceManager * handle);
static napi_value fdn_device_manager_construct (napi_env env, napi_callback_info info);

static napi_value fdn_device_manager_close (napi_env env, napi_callback_info info);
static gboolean fdn_device_manager_close_begin (gpointer user_data);
static void fdn_device_manager_close_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void fdn_device_manager_close_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void fdn_device_manager_close_operation_free (FdnDeviceManagerCloseOperation * operation);

static napi_value fdn_device_manager_get_device_by_id (napi_env env, napi_callback_info info);
static gboolean fdn_device_manager_get_device_by_id_begin (gpointer user_data);
static void fdn_device_manager_get_device_by_id_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void fdn_device_manager_get_device_by_id_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void fdn_device_manager_get_device_by_id_operation_free (FdnDeviceManagerGetDeviceByIdOperation * operation);

static napi_value fdn_device_manager_get_device_by_type (napi_env env, napi_callback_info info);
static gboolean fdn_device_manager_get_device_by_type_begin (gpointer user_data);
static void fdn_device_manager_get_device_by_type_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void fdn_device_manager_get_device_by_type_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void fdn_device_manager_get_device_by_type_operation_free (FdnDeviceManagerGetDeviceByTypeOperation * operation);

static napi_value fdn_device_manager_find_device_by_id (napi_env env, napi_callback_info info);
static gboolean fdn_device_manager_find_device_by_id_begin (gpointer user_data);
static void fdn_device_manager_find_device_by_id_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void fdn_device_manager_find_device_by_id_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void fdn_device_manager_find_device_by_id_operation_free (FdnDeviceManagerFindDeviceByIdOperation * operation);

static napi_value fdn_device_manager_find_device_by_type (napi_env env, napi_callback_info info);
static gboolean fdn_device_manager_find_device_by_type_begin (gpointer user_data);
static void fdn_device_manager_find_device_by_type_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void fdn_device_manager_find_device_by_type_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void fdn_device_manager_find_device_by_type_operation_free (FdnDeviceManagerFindDeviceByTypeOperation * operation);

static napi_value fdn_device_manager_enumerate_devices (napi_env env, napi_callback_info info);
static gboolean fdn_device_manager_enumerate_devices_begin (gpointer user_data);
static void fdn_device_manager_enumerate_devices_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void fdn_device_manager_enumerate_devices_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void fdn_device_manager_enumerate_devices_operation_free (FdnDeviceManagerEnumerateDevicesOperation * operation);

static napi_value fdn_device_manager_add_remote_device (napi_env env, napi_callback_info info);
static gboolean fdn_device_manager_add_remote_device_begin (gpointer user_data);
static void fdn_device_manager_add_remote_device_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void fdn_device_manager_add_remote_device_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void fdn_device_manager_add_remote_device_operation_free (FdnDeviceManagerAddRemoteDeviceOperation * operation);

static napi_value fdn_device_manager_remove_remote_device (napi_env env, napi_callback_info info);
static gboolean fdn_device_manager_remove_remote_device_begin (gpointer user_data);
static void fdn_device_manager_remove_remote_device_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void fdn_device_manager_remove_remote_device_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void fdn_device_manager_remove_remote_device_operation_free (FdnDeviceManagerRemoveRemoteDeviceOperation * operation);

static void fdn_cancellable_register (napi_env env, napi_value exports);
static gboolean fdn_cancellable_from_value (napi_env env, napi_value value, GCancellable ** result);
static napi_value fdn_cancellable_to_value (napi_env env, GCancellable * handle);
static napi_value fdn_cancellable_construct (napi_env env, napi_callback_info info);

static napi_value fdn_cancellable_cancel (napi_env env, napi_callback_info info);

static napi_value fdn_cancellable_disconnect (napi_env env, napi_callback_info info);

static napi_value fdn_cancellable_get_fd (napi_env env, napi_callback_info info);

static napi_value fdn_cancellable_is_cancelled (napi_env env, napi_callback_info info);

static napi_value fdn_cancellable_make_pollfd (napi_env env, napi_callback_info info);

static napi_value fdn_cancellable_pop_current (napi_env env, napi_callback_info info);

static napi_value fdn_cancellable_push_current (napi_env env, napi_callback_info info);

static napi_value fdn_cancellable_release_fd (napi_env env, napi_callback_info info);

static napi_value fdn_cancellable_reset (napi_env env, napi_callback_info info);

static napi_value fdn_cancellable_set_error_if_cancelled (napi_env env, napi_callback_info info);

static napi_value fdn_cancellable_source_new (napi_env env, napi_callback_info info);

static napi_value fdn_boolean_to_value (napi_env env, gboolean value);
static gboolean fdn_ulong_from_value (napi_env env, napi_value value, gulong * result);
static gboolean fdn_utf8_from_value (napi_env env, napi_value value, gchar ** str);

static napi_type_tag fdn_device_manager_type_tag = { 0x2397c5c305a24ad4, 0xacf81155b7c0ead4 };
static napi_type_tag fdn_cancellable_type_tag = { 0xce35d3adaa714ad8, 0xa76dad34a39266c7 };

static napi_ref fdn_device_manager_constructor;
static napi_ref fdn_cancellable_constructor;

static napi_threadsafe_function fdn_device_manager_close_tsfn;
static napi_threadsafe_function fdn_device_manager_get_device_by_id_tsfn;
static napi_threadsafe_function fdn_device_manager_get_device_by_type_tsfn;
static napi_threadsafe_function fdn_device_manager_find_device_by_id_tsfn;
static napi_threadsafe_function fdn_device_manager_find_device_by_type_tsfn;
static napi_threadsafe_function fdn_device_manager_enumerate_devices_tsfn;
static napi_threadsafe_function fdn_device_manager_add_remote_device_tsfn;
static napi_threadsafe_function fdn_device_manager_remove_remote_device_tsfn;

static napi_value
Init (napi_env env,
      napi_value exports)
{
  fdn_device_manager_register (env, exports);
  fdn_cancellable_register (env, exports);
  return exports;
}

NAPI_MODULE (NODE_GYP_MODULE_NAME, Init)

static void
fdn_device_manager_register (napi_env env,
                             napi_value exports)
{
  napi_property_descriptor properties[] =
  {
    { "close", 0, fdn_device_manager_close, 0, 0, 0, napi_default, 0 },
    { "getDeviceById", 0, fdn_device_manager_get_device_by_id, 0, 0, 0, napi_default, 0 },
    { "getDeviceByType", 0, fdn_device_manager_get_device_by_type, 0, 0, 0, napi_default, 0 },
    { "findDeviceById", 0, fdn_device_manager_find_device_by_id, 0, 0, 0, napi_default, 0 },
    { "findDeviceByType", 0, fdn_device_manager_find_device_by_type, 0, 0, 0, napi_default, 0 },
    { "enumerateDevices", 0, fdn_device_manager_enumerate_devices, 0, 0, 0, napi_default, 0 },
    { "addRemoteDevice", 0, fdn_device_manager_add_remote_device, 0, 0, 0, napi_default, 0 },
    { "removeRemoteDevice", 0, fdn_device_manager_remove_remote_device, 0, 0, 0, napi_default, 0 },
  };

  napi_value constructor;
  napi_define_class (env, "DeviceManager", NAPI_AUTO_LENGTH, fdn_device_manager_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_device_manager_constructor);

  napi_set_named_property (env, exports, "DeviceManager", constructor);

  napi_value resource_name;

  napi_create_string_utf8 (env, "close", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_device_manager_close_deliver, &fdn_device_manager_close_tsfn);

  napi_create_string_utf8 (env, "getDeviceById", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_device_manager_get_device_by_id_deliver, &fdn_device_manager_get_device_by_id_tsfn);

  napi_create_string_utf8 (env, "getDeviceByType", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_device_manager_get_device_by_type_deliver, &fdn_device_manager_get_device_by_type_tsfn);

  napi_create_string_utf8 (env, "findDeviceById", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_device_manager_find_device_by_id_deliver, &fdn_device_manager_find_device_by_id_tsfn);

  napi_create_string_utf8 (env, "findDeviceByType", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_device_manager_find_device_by_type_deliver, &fdn_device_manager_find_device_by_type_tsfn);

  napi_create_string_utf8 (env, "enumerateDevices", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_device_manager_enumerate_devices_deliver, &fdn_device_manager_enumerate_devices_tsfn);

  napi_create_string_utf8 (env, "addRemoteDevice", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_device_manager_add_remote_device_deliver, &fdn_device_manager_add_remote_device_tsfn);

  napi_create_string_utf8 (env, "removeRemoteDevice", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_device_manager_remove_remote_device_deliver, &fdn_device_manager_remove_remote_device_tsfn);
}

static gboolean
fdn_device_manager_from_value (napi_env env,
                               napi_value value,
                               FridaDeviceManager ** result)
{
  napi_status status;
  bool is_instance;
  FridaDeviceManager * handle;

  status = napi_check_object_type_tag (env, value, &fdn_device_manager_type_tag, &is_instance);
  if (status != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of DeviceManager");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) &handle);

  g_object_ref (handle);
  *result = handle;

  return TRUE;
}

static napi_value
fdn_device_manager_to_value (napi_env env,
                             FridaDeviceManager * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_device_manager_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_device_manager_construct (napi_env env,
                              napi_callback_info info)
{
  size_t argc = 0;
  napi_value jsthis;
  napi_status status;
  FridaDeviceManager * handle;

  status = napi_get_cb_info (env, info, &argc, NULL, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  handle = frida_device_manager_new ();

  status = napi_type_tag_object (env, jsthis, &fdn_device_manager_type_tag);
  if (status != napi_ok)
    return NULL;

  status = napi_wrap (env, jsthis, handle, NULL, NULL, NULL);
  if (status != napi_ok)
    return NULL;

  return jsthis;
}

static napi_value
fdn_device_manager_close (napi_env env,
                          napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaDeviceManager * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnDeviceManagerCloseOperation * operation;
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

  operation = g_slice_new0 (FdnDeviceManagerCloseOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0)
  {
    if (!fdn_cancellable_from_value (env, args[0], &operation->cancellable))
      goto invalid_argument;
  }
  else
  {
    operation->cancellable = NULL;
  }

  source = g_idle_source_new ();
  g_source_set_callback (source, fdn_device_manager_close_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, fdn_device_manager_close_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    fdn_device_manager_close_operation_free (operation);
    return NULL;
  }
}

static gboolean
fdn_device_manager_close_begin (gpointer user_data)
{
  FdnDeviceManagerCloseOperation * operation = user_data;

  frida_device_manager_close (operation->handle,
      operation->cancellable,
      fdn_device_manager_close_end, operation);

  return G_SOURCE_REMOVE;
}

static void
fdn_device_manager_close_end (GObject * source_object,
                              GAsyncResult * res,
                              gpointer user_data)
{
  FdnDeviceManagerCloseOperation * operation = user_data;

  frida_device_manager_close_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (fdn_device_manager_close_tsfn, operation, napi_tsfn_blocking);
}

static void
fdn_device_manager_close_deliver (napi_env env,
                                  napi_value js_cb,
                                  void * context,
                                  void * data)
{
  FdnDeviceManagerCloseOperation * operation = data;

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

  fdn_device_manager_close_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_device_manager_close_tsfn);
}

static void
fdn_device_manager_close_operation_free (FdnDeviceManagerCloseOperation * operation)
{
  g_slice_free (FdnDeviceManagerCloseOperation, operation);
}

static napi_value
fdn_device_manager_get_device_by_id (napi_env env,
                                     napi_callback_info info)
{
  size_t argc = 3;
  napi_value args[3];
  napi_status status;
  napi_value jsthis;
  FridaDeviceManager * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnDeviceManagerGetDeviceByIdOperation * operation;
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

  operation = g_slice_new0 (FdnDeviceManagerGetDeviceByIdOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0)
  {
    if (!fdn_utf8_from_value (env, args[0], &operation->id))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: id");
    goto invalid_argument;
  }

  if (argc > 1)
  {
    if (!fdn_int_from_value (env, args[1], &operation->timeout))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: timeout");
    goto invalid_argument;
  }

  if (argc > 2)
  {
    if (!fdn_cancellable_from_value (env, args[2], &operation->cancellable))
      goto invalid_argument;
  }
  else
  {
    operation->cancellable = NULL;
  }

  source = g_idle_source_new ();
  g_source_set_callback (source, fdn_device_manager_get_device_by_id_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, fdn_device_manager_get_device_by_id_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    fdn_device_manager_get_device_by_id_operation_free (operation);
    return NULL;
  }
}

static gboolean
fdn_device_manager_get_device_by_id_begin (gpointer user_data)
{
  FdnDeviceManagerGetDeviceByIdOperation * operation = user_data;

  frida_device_manager_get_device_by_id (operation->handle,
      operation->id, operation->timeout, operation->cancellable,
      fdn_device_manager_get_device_by_id_end, operation);

  return G_SOURCE_REMOVE;
}

static void
fdn_device_manager_get_device_by_id_end (GObject * source_object,
                                         GAsyncResult * res,
                                         gpointer user_data)
{
  FdnDeviceManagerGetDeviceByIdOperation * operation = user_data;

  

  operation->return_value = frida_device_manager_get_device_by_id_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (fdn_device_manager_get_device_by_id_tsfn, operation, napi_tsfn_blocking);
}

static void
fdn_device_manager_get_device_by_id_deliver (napi_env env,
                                             napi_value js_cb,
                                             void * context,
                                             void * data)
{
  FdnDeviceManagerGetDeviceByIdOperation * operation = data;

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
    result = fdn_device_to_value (env, operation->return_value);
    napi_resolve_deferred (env, operation->deferred, result);
  }

  fdn_device_manager_get_device_by_id_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_device_manager_get_device_by_id_tsfn);
}

static void
fdn_device_manager_get_device_by_id_operation_free (FdnDeviceManagerGetDeviceByIdOperation * operation)
{
  g_free (operation->id);
  g_slice_free (FdnDeviceManagerGetDeviceByIdOperation, operation);
}

static napi_value
fdn_device_manager_get_device_by_type (napi_env env,
                                       napi_callback_info info)
{
  size_t argc = 3;
  napi_value args[3];
  napi_status status;
  napi_value jsthis;
  FridaDeviceManager * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnDeviceManagerGetDeviceByTypeOperation * operation;
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

  operation = g_slice_new0 (FdnDeviceManagerGetDeviceByTypeOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0)
  {
    if (!fdn_device_type_from_value (env, args[0], &operation->type))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: type");
    goto invalid_argument;
  }

  if (argc > 1)
  {
    if (!fdn_int_from_value (env, args[1], &operation->timeout))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: timeout");
    goto invalid_argument;
  }

  if (argc > 2)
  {
    if (!fdn_cancellable_from_value (env, args[2], &operation->cancellable))
      goto invalid_argument;
  }
  else
  {
    operation->cancellable = NULL;
  }

  source = g_idle_source_new ();
  g_source_set_callback (source, fdn_device_manager_get_device_by_type_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, fdn_device_manager_get_device_by_type_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    fdn_device_manager_get_device_by_type_operation_free (operation);
    return NULL;
  }
}

static gboolean
fdn_device_manager_get_device_by_type_begin (gpointer user_data)
{
  FdnDeviceManagerGetDeviceByTypeOperation * operation = user_data;

  frida_device_manager_get_device_by_type (operation->handle,
      operation->type, operation->timeout, operation->cancellable,
      fdn_device_manager_get_device_by_type_end, operation);

  return G_SOURCE_REMOVE;
}

static void
fdn_device_manager_get_device_by_type_end (GObject * source_object,
                                           GAsyncResult * res,
                                           gpointer user_data)
{
  FdnDeviceManagerGetDeviceByTypeOperation * operation = user_data;

  

  operation->return_value = frida_device_manager_get_device_by_type_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (fdn_device_manager_get_device_by_type_tsfn, operation, napi_tsfn_blocking);
}

static void
fdn_device_manager_get_device_by_type_deliver (napi_env env,
                                               napi_value js_cb,
                                               void * context,
                                               void * data)
{
  FdnDeviceManagerGetDeviceByTypeOperation * operation = data;

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
    result = fdn_device_to_value (env, operation->return_value);
    napi_resolve_deferred (env, operation->deferred, result);
  }

  fdn_device_manager_get_device_by_type_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_device_manager_get_device_by_type_tsfn);
}

static void
fdn_device_manager_get_device_by_type_operation_free (FdnDeviceManagerGetDeviceByTypeOperation * operation)
{
  g_slice_free (FdnDeviceManagerGetDeviceByTypeOperation, operation);
}

static napi_value
fdn_device_manager_find_device_by_id (napi_env env,
                                      napi_callback_info info)
{
  size_t argc = 3;
  napi_value args[3];
  napi_status status;
  napi_value jsthis;
  FridaDeviceManager * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnDeviceManagerFindDeviceByIdOperation * operation;
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

  operation = g_slice_new0 (FdnDeviceManagerFindDeviceByIdOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0)
  {
    if (!fdn_utf8_from_value (env, args[0], &operation->id))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: id");
    goto invalid_argument;
  }

  if (argc > 1)
  {
    if (!fdn_int_from_value (env, args[1], &operation->timeout))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: timeout");
    goto invalid_argument;
  }

  if (argc > 2)
  {
    if (!fdn_cancellable_from_value (env, args[2], &operation->cancellable))
      goto invalid_argument;
  }
  else
  {
    operation->cancellable = NULL;
  }

  source = g_idle_source_new ();
  g_source_set_callback (source, fdn_device_manager_find_device_by_id_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, fdn_device_manager_find_device_by_id_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    fdn_device_manager_find_device_by_id_operation_free (operation);
    return NULL;
  }
}

static gboolean
fdn_device_manager_find_device_by_id_begin (gpointer user_data)
{
  FdnDeviceManagerFindDeviceByIdOperation * operation = user_data;

  frida_device_manager_find_device_by_id (operation->handle,
      operation->id, operation->timeout, operation->cancellable,
      fdn_device_manager_find_device_by_id_end, operation);

  return G_SOURCE_REMOVE;
}

static void
fdn_device_manager_find_device_by_id_end (GObject * source_object,
                                          GAsyncResult * res,
                                          gpointer user_data)
{
  FdnDeviceManagerFindDeviceByIdOperation * operation = user_data;

  

  operation->return_value = frida_device_manager_find_device_by_id_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (fdn_device_manager_find_device_by_id_tsfn, operation, napi_tsfn_blocking);
}

static void
fdn_device_manager_find_device_by_id_deliver (napi_env env,
                                              napi_value js_cb,
                                              void * context,
                                              void * data)
{
  FdnDeviceManagerFindDeviceByIdOperation * operation = data;

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
    result = fdn_device_to_value (env, operation->return_value);
    napi_resolve_deferred (env, operation->deferred, result);
  }

  fdn_device_manager_find_device_by_id_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_device_manager_find_device_by_id_tsfn);
}

static void
fdn_device_manager_find_device_by_id_operation_free (FdnDeviceManagerFindDeviceByIdOperation * operation)
{
  g_free (operation->id);
  g_slice_free (FdnDeviceManagerFindDeviceByIdOperation, operation);
}

static napi_value
fdn_device_manager_find_device_by_type (napi_env env,
                                        napi_callback_info info)
{
  size_t argc = 3;
  napi_value args[3];
  napi_status status;
  napi_value jsthis;
  FridaDeviceManager * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnDeviceManagerFindDeviceByTypeOperation * operation;
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

  operation = g_slice_new0 (FdnDeviceManagerFindDeviceByTypeOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0)
  {
    if (!fdn_device_type_from_value (env, args[0], &operation->type))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: type");
    goto invalid_argument;
  }

  if (argc > 1)
  {
    if (!fdn_int_from_value (env, args[1], &operation->timeout))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: timeout");
    goto invalid_argument;
  }

  if (argc > 2)
  {
    if (!fdn_cancellable_from_value (env, args[2], &operation->cancellable))
      goto invalid_argument;
  }
  else
  {
    operation->cancellable = NULL;
  }

  source = g_idle_source_new ();
  g_source_set_callback (source, fdn_device_manager_find_device_by_type_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, fdn_device_manager_find_device_by_type_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    fdn_device_manager_find_device_by_type_operation_free (operation);
    return NULL;
  }
}

static gboolean
fdn_device_manager_find_device_by_type_begin (gpointer user_data)
{
  FdnDeviceManagerFindDeviceByTypeOperation * operation = user_data;

  frida_device_manager_find_device_by_type (operation->handle,
      operation->type, operation->timeout, operation->cancellable,
      fdn_device_manager_find_device_by_type_end, operation);

  return G_SOURCE_REMOVE;
}

static void
fdn_device_manager_find_device_by_type_end (GObject * source_object,
                                            GAsyncResult * res,
                                            gpointer user_data)
{
  FdnDeviceManagerFindDeviceByTypeOperation * operation = user_data;

  

  operation->return_value = frida_device_manager_find_device_by_type_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (fdn_device_manager_find_device_by_type_tsfn, operation, napi_tsfn_blocking);
}

static void
fdn_device_manager_find_device_by_type_deliver (napi_env env,
                                                napi_value js_cb,
                                                void * context,
                                                void * data)
{
  FdnDeviceManagerFindDeviceByTypeOperation * operation = data;

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
    result = fdn_device_to_value (env, operation->return_value);
    napi_resolve_deferred (env, operation->deferred, result);
  }

  fdn_device_manager_find_device_by_type_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_device_manager_find_device_by_type_tsfn);
}

static void
fdn_device_manager_find_device_by_type_operation_free (FdnDeviceManagerFindDeviceByTypeOperation * operation)
{
  g_slice_free (FdnDeviceManagerFindDeviceByTypeOperation, operation);
}

static napi_value
fdn_device_manager_enumerate_devices (napi_env env,
                                      napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaDeviceManager * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnDeviceManagerEnumerateDevicesOperation * operation;
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

  operation = g_slice_new0 (FdnDeviceManagerEnumerateDevicesOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0)
  {
    if (!fdn_cancellable_from_value (env, args[0], &operation->cancellable))
      goto invalid_argument;
  }
  else
  {
    operation->cancellable = NULL;
  }

  source = g_idle_source_new ();
  g_source_set_callback (source, fdn_device_manager_enumerate_devices_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, fdn_device_manager_enumerate_devices_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    fdn_device_manager_enumerate_devices_operation_free (operation);
    return NULL;
  }
}

static gboolean
fdn_device_manager_enumerate_devices_begin (gpointer user_data)
{
  FdnDeviceManagerEnumerateDevicesOperation * operation = user_data;

  frida_device_manager_enumerate_devices (operation->handle,
      operation->cancellable,
      fdn_device_manager_enumerate_devices_end, operation);

  return G_SOURCE_REMOVE;
}

static void
fdn_device_manager_enumerate_devices_end (GObject * source_object,
                                          GAsyncResult * res,
                                          gpointer user_data)
{
  FdnDeviceManagerEnumerateDevicesOperation * operation = user_data;

  

  operation->return_value = frida_device_manager_enumerate_devices_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (fdn_device_manager_enumerate_devices_tsfn, operation, napi_tsfn_blocking);
}

static void
fdn_device_manager_enumerate_devices_deliver (napi_env env,
                                              napi_value js_cb,
                                              void * context,
                                              void * data)
{
  FdnDeviceManagerEnumerateDevicesOperation * operation = data;

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
    result = fdn_device_list_to_value (env, operation->return_value);
    napi_resolve_deferred (env, operation->deferred, result);
  }

  fdn_device_manager_enumerate_devices_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_device_manager_enumerate_devices_tsfn);
}

static void
fdn_device_manager_enumerate_devices_operation_free (FdnDeviceManagerEnumerateDevicesOperation * operation)
{
  g_slice_free (FdnDeviceManagerEnumerateDevicesOperation, operation);
}

static napi_value
fdn_device_manager_add_remote_device (napi_env env,
                                      napi_callback_info info)
{
  size_t argc = 3;
  napi_value args[3];
  napi_status status;
  napi_value jsthis;
  FridaDeviceManager * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnDeviceManagerAddRemoteDeviceOperation * operation;
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

  operation = g_slice_new0 (FdnDeviceManagerAddRemoteDeviceOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0)
  {
    if (!fdn_utf8_from_value (env, args[0], &operation->address))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: address");
    goto invalid_argument;
  }

  if (argc > 1)
  {
    if (!fdn_remote_device_options_from_value (env, args[1], &operation->options))
      goto invalid_argument;
  }
  else
  {
    operation->options = NULL;
  }

  if (argc > 2)
  {
    if (!fdn_cancellable_from_value (env, args[2], &operation->cancellable))
      goto invalid_argument;
  }
  else
  {
    operation->cancellable = NULL;
  }

  source = g_idle_source_new ();
  g_source_set_callback (source, fdn_device_manager_add_remote_device_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, fdn_device_manager_add_remote_device_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    fdn_device_manager_add_remote_device_operation_free (operation);
    return NULL;
  }
}

static gboolean
fdn_device_manager_add_remote_device_begin (gpointer user_data)
{
  FdnDeviceManagerAddRemoteDeviceOperation * operation = user_data;

  frida_device_manager_add_remote_device (operation->handle,
      operation->address, operation->options, operation->cancellable,
      fdn_device_manager_add_remote_device_end, operation);

  return G_SOURCE_REMOVE;
}

static void
fdn_device_manager_add_remote_device_end (GObject * source_object,
                                          GAsyncResult * res,
                                          gpointer user_data)
{
  FdnDeviceManagerAddRemoteDeviceOperation * operation = user_data;

  

  operation->return_value = frida_device_manager_add_remote_device_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (fdn_device_manager_add_remote_device_tsfn, operation, napi_tsfn_blocking);
}

static void
fdn_device_manager_add_remote_device_deliver (napi_env env,
                                              napi_value js_cb,
                                              void * context,
                                              void * data)
{
  FdnDeviceManagerAddRemoteDeviceOperation * operation = data;

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
    result = fdn_device_to_value (env, operation->return_value);
    napi_resolve_deferred (env, operation->deferred, result);
  }

  fdn_device_manager_add_remote_device_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_device_manager_add_remote_device_tsfn);
}

static void
fdn_device_manager_add_remote_device_operation_free (FdnDeviceManagerAddRemoteDeviceOperation * operation)
{
  g_free (operation->address);
  g_slice_free (FdnDeviceManagerAddRemoteDeviceOperation, operation);
}

static napi_value
fdn_device_manager_remove_remote_device (napi_env env,
                                         napi_callback_info info)
{
  size_t argc = 2;
  napi_value args[2];
  napi_status status;
  napi_value jsthis;
  FridaDeviceManager * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnDeviceManagerRemoveRemoteDeviceOperation * operation;
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

  operation = g_slice_new0 (FdnDeviceManagerRemoveRemoteDeviceOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0)
  {
    if (!fdn_utf8_from_value (env, args[0], &operation->address))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: address");
    goto invalid_argument;
  }

  if (argc > 1)
  {
    if (!fdn_cancellable_from_value (env, args[1], &operation->cancellable))
      goto invalid_argument;
  }
  else
  {
    operation->cancellable = NULL;
  }

  source = g_idle_source_new ();
  g_source_set_callback (source, fdn_device_manager_remove_remote_device_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, fdn_device_manager_remove_remote_device_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    fdn_device_manager_remove_remote_device_operation_free (operation);
    return NULL;
  }
}

static gboolean
fdn_device_manager_remove_remote_device_begin (gpointer user_data)
{
  FdnDeviceManagerRemoveRemoteDeviceOperation * operation = user_data;

  frida_device_manager_remove_remote_device (operation->handle,
      operation->address, operation->cancellable,
      fdn_device_manager_remove_remote_device_end, operation);

  return G_SOURCE_REMOVE;
}

static void
fdn_device_manager_remove_remote_device_end (GObject * source_object,
                                             GAsyncResult * res,
                                             gpointer user_data)
{
  FdnDeviceManagerRemoveRemoteDeviceOperation * operation = user_data;

  frida_device_manager_remove_remote_device_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (fdn_device_manager_remove_remote_device_tsfn, operation, napi_tsfn_blocking);
}

static void
fdn_device_manager_remove_remote_device_deliver (napi_env env,
                                                 napi_value js_cb,
                                                 void * context,
                                                 void * data)
{
  FdnDeviceManagerRemoveRemoteDeviceOperation * operation = data;

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

  fdn_device_manager_remove_remote_device_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_device_manager_remove_remote_device_tsfn);
}

static void
fdn_device_manager_remove_remote_device_operation_free (FdnDeviceManagerRemoveRemoteDeviceOperation * operation)
{
  g_free (operation->address);
  g_slice_free (FdnDeviceManagerRemoveRemoteDeviceOperation, operation);
}

static void
fdn_cancellable_register (napi_env env,
                          napi_value exports)
{
  napi_property_descriptor properties[] =
  {
    { "cancel", 0, fdn_cancellable_cancel, 0, 0, 0, napi_default, 0 },
    { "disconnect", 0, fdn_cancellable_disconnect, 0, 0, 0, napi_default, 0 },
    { "getFd", 0, fdn_cancellable_get_fd, 0, 0, 0, napi_default, 0 },
    { "isCancelled", 0, fdn_cancellable_is_cancelled, 0, 0, 0, napi_default, 0 },
    { "makePollfd", 0, fdn_cancellable_make_pollfd, 0, 0, 0, napi_default, 0 },
    { "popCurrent", 0, fdn_cancellable_pop_current, 0, 0, 0, napi_default, 0 },
    { "pushCurrent", 0, fdn_cancellable_push_current, 0, 0, 0, napi_default, 0 },
    { "releaseFd", 0, fdn_cancellable_release_fd, 0, 0, 0, napi_default, 0 },
    { "reset", 0, fdn_cancellable_reset, 0, 0, 0, napi_default, 0 },
    { "setErrorIfCancelled", 0, fdn_cancellable_set_error_if_cancelled, 0, 0, 0, napi_default, 0 },
    { "sourceNew", 0, fdn_cancellable_source_new, 0, 0, 0, napi_default, 0 },
  };

  napi_value constructor;
  napi_define_class (env, "Cancellable", NAPI_AUTO_LENGTH, fdn_cancellable_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_cancellable_constructor);

  napi_set_named_property (env, exports, "Cancellable", constructor);
}

static gboolean
fdn_cancellable_from_value (napi_env env,
                            napi_value value,
                            GCancellable ** result)
{
  napi_status status;
  bool is_instance;
  GCancellable * handle;

  status = napi_check_object_type_tag (env, value, &fdn_cancellable_type_tag, &is_instance);
  if (status != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of Cancellable");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) &handle);

  g_object_ref (handle);
  *result = handle;

  return TRUE;
}

static napi_value
fdn_cancellable_to_value (napi_env env,
                          GCancellable * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_cancellable_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_cancellable_construct (napi_env env,
                           napi_callback_info info)
{
  size_t argc = 0;
  napi_value jsthis;
  napi_status status;
  GCancellable * handle;

  status = napi_get_cb_info (env, info, &argc, NULL, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  handle = g_cancellable_new ();

  status = napi_type_tag_object (env, jsthis, &fdn_cancellable_type_tag);
  if (status != napi_ok)
    return NULL;

  status = napi_wrap (env, jsthis, handle, NULL, NULL, NULL);
  if (status != napi_ok)
    return NULL;

  return jsthis;
}

static napi_value
fdn_cancellable_cancel (napi_env env,
                        napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  GCancellable * handle;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  g_cancellable_cancel (handle);

  napi_get_undefined (env, &result);

  return result;
}

static napi_value
fdn_cancellable_disconnect (napi_env env,
                            napi_callback_info info)
{
  napi_value result;
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  GCancellable * handle;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  if (argc > 0)
  {
    if (!fdn_ulong_from_value (env, args[0], &handler_id))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: handler_id");
    goto invalid_argument;
  }

  g_cancellable_disconnect (handle, handler_id);

  napi_get_undefined (env, &result);

  return result;

invalid_argument:
  {
    return NULL;
  }
}

static napi_value
fdn_cancellable_get_fd (napi_env env,
                        napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  GCancellable * handle;
  int return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = g_cancellable_get_fd (handle);

  result = fdn_int_to_value (env, return_value);

  return result;
}

static napi_value
fdn_cancellable_is_cancelled (napi_env env,
                              napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  GCancellable * handle;
  gboolean return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = g_cancellable_is_cancelled (handle);

  result = fdn_boolean_to_value (env, return_value);

  return result;
}

static napi_value
fdn_cancellable_make_pollfd (napi_env env,
                             napi_callback_info info)
{
  napi_value result;
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  GCancellable * handle;
  gboolean return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  if (argc > 0)
  {
    if (!fdn_pollfd_from_value (env, args[0], &pollfd))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: pollfd");
    goto invalid_argument;
  }

  return_value = g_cancellable_make_pollfd (handle, pollfd);

  result = fdn_boolean_to_value (env, return_value);

  return result;

invalid_argument:
  {
    return NULL;
  }
}

static napi_value
fdn_cancellable_pop_current (napi_env env,
                             napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  GCancellable * handle;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  g_cancellable_pop_current (handle);

  napi_get_undefined (env, &result);

  return result;
}

static napi_value
fdn_cancellable_push_current (napi_env env,
                              napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  GCancellable * handle;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  g_cancellable_push_current (handle);

  napi_get_undefined (env, &result);

  return result;
}

static napi_value
fdn_cancellable_release_fd (napi_env env,
                            napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  GCancellable * handle;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  g_cancellable_release_fd (handle);

  napi_get_undefined (env, &result);

  return result;
}

static napi_value
fdn_cancellable_reset (napi_env env,
                       napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  GCancellable * handle;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  g_cancellable_reset (handle);

  napi_get_undefined (env, &result);

  return result;
}

static napi_value
fdn_cancellable_set_error_if_cancelled (napi_env env,
                                        napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  GCancellable * handle;
  gboolean return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = g_cancellable_set_error_if_cancelled (handle);

  result = fdn_boolean_to_value (env, return_value);

  return result;
}

static napi_value
fdn_cancellable_source_new (napi_env env,
                            napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  GCancellable * handle;
  GSource * return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = g_cancellable_source_new (handle);

  result = fdn_source_to_value (env, return_value);

  return result;
}

static napi_value
fdn_boolean_to_value (napi_env env,
                      gboolean value)
{
  napi_value result;
  napi_get_boolean (env, value, &result);
  return result;
}

static gboolean
fdn_ulong_from_value (napi_env env,
                      napi_value value,
                      gulong * result)
{
  double number;

  if (napi_get_value_double (env, value, &number) != napi_ok)
    goto invalid_argument;

  *result = number;
  return TRUE;

invalid_argument:
  {
    napi_throw_error (env, NULL, "expected a number");
    g_free (result);
    return FALSE;
  }
}

static gboolean
fdn_utf8_from_value (napi_env env,
                     napi_value value,
                     gchar ** str)
{
  gchar * result = NULL;
  size_t length;

  if (napi_get_value_string_utf8 (env, value, NULL, 0, &length) != napi_ok)
    goto invalid_argument;

  result = g_malloc (length + 1);
  if (napi_get_value_string_utf8 (env, value, result, length + 1, &length) != napi_ok)
    goto invalid_argument;

  *str = result;
  return TRUE;

invalid_argument:
  {
    napi_throw_error (env, NULL, "expected a string");
    g_free (result);
    return FALSE;
  }
}
