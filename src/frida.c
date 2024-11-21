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

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaDevice * handle;
  GError * error;
  GCancellable * cancellable;
  GHashTable * return_value;
} FdnDeviceQuerySystemParametersOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaDevice * handle;
  GError * error;
  FridaFrontmostQueryOptions * options;
  GCancellable * cancellable;
  FridaApplication * return_value;
} FdnDeviceGetFrontmostApplicationOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaDevice * handle;
  GError * error;
  FridaApplicationQueryOptions * options;
  GCancellable * cancellable;
  FridaApplicationList * return_value;
} FdnDeviceEnumerateApplicationsOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaDevice * handle;
  GError * error;
  guint pid;
  FridaProcessMatchOptions * options;
  GCancellable * cancellable;
  FridaProcess * return_value;
} FdnDeviceGetProcessByPidOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaDevice * handle;
  GError * error;
  gchar * name;
  FridaProcessMatchOptions * options;
  GCancellable * cancellable;
  FridaProcess * return_value;
} FdnDeviceGetProcessByNameOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaDevice * handle;
  GError * error;
  guint pid;
  FridaProcessMatchOptions * options;
  GCancellable * cancellable;
  FridaProcess * return_value;
} FdnDeviceFindProcessByPidOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaDevice * handle;
  GError * error;
  gchar * name;
  FridaProcessMatchOptions * options;
  GCancellable * cancellable;
  FridaProcess * return_value;
} FdnDeviceFindProcessByNameOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaDevice * handle;
  GError * error;
  FridaProcessQueryOptions * options;
  GCancellable * cancellable;
  FridaProcessList * return_value;
} FdnDeviceEnumerateProcessesOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaDevice * handle;
  GError * error;
  GCancellable * cancellable;
} FdnDeviceEnableSpawnGatingOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaDevice * handle;
  GError * error;
  GCancellable * cancellable;
} FdnDeviceDisableSpawnGatingOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaDevice * handle;
  GError * error;
  GCancellable * cancellable;
  FridaSpawnList * return_value;
} FdnDeviceEnumeratePendingSpawnOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaDevice * handle;
  GError * error;
  GCancellable * cancellable;
  FridaChildList * return_value;
} FdnDeviceEnumeratePendingChildrenOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaDevice * handle;
  GError * error;
  gchar * program;
  FridaSpawnOptions * options;
  GCancellable * cancellable;
  guint return_value;
} FdnDeviceSpawnOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaDevice * handle;
  GError * error;
  guint pid;
  GBytes * data;
  GCancellable * cancellable;
} FdnDeviceInputOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaDevice * handle;
  GError * error;
  guint pid;
  GCancellable * cancellable;
} FdnDeviceResumeOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaDevice * handle;
  GError * error;
  guint pid;
  GCancellable * cancellable;
} FdnDeviceKillOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaDevice * handle;
  GError * error;
  guint pid;
  FridaSessionOptions * options;
  GCancellable * cancellable;
  FridaSession * return_value;
} FdnDeviceAttachOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaDevice * handle;
  GError * error;
  guint pid;
  gchar * path;
  gchar * entrypoint;
  gchar * data;
  GCancellable * cancellable;
  guint return_value;
} FdnDeviceInjectLibraryFileOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaDevice * handle;
  GError * error;
  guint pid;
  GBytes * blob;
  gchar * entrypoint;
  gchar * data;
  GCancellable * cancellable;
  guint return_value;
} FdnDeviceInjectLibraryBlobOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaDevice * handle;
  GError * error;
  gchar * address;
  GCancellable * cancellable;
  GIOStream * return_value;
} FdnDeviceOpenChannelOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaDevice * handle;
  GError * error;
  gchar * address;
  GCancellable * cancellable;
  FridaService * return_value;
} FdnDeviceOpenServiceOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaDevice * handle;
  GError * error;
  GCancellable * cancellable;
} FdnDeviceUnpairOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaDevice * handle;
  GError * error;
  GCancellable * cancellable;
  FridaHostSession * return_value;
} FdnDeviceGetHostSessionOperation;


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

static void fdn_device_register (napi_env env, napi_value exports);
static gboolean fdn_device_from_value (napi_env env, napi_value value, FridaDevice ** result);
static napi_value fdn_device_to_value (napi_env env, FridaDevice * handle);
static napi_value fdn_device_construct (napi_env env, napi_callback_info info);

static napi_value fdn_device_is_lost (napi_env env, napi_callback_info info);

static napi_value fdn_device_query_system_parameters (napi_env env, napi_callback_info info);
static gboolean fdn_device_query_system_parameters_begin (gpointer user_data);
static void fdn_device_query_system_parameters_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void fdn_device_query_system_parameters_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void fdn_device_query_system_parameters_operation_free (FdnDeviceQuerySystemParametersOperation * operation);

static napi_value fdn_device_get_frontmost_application (napi_env env, napi_callback_info info);
static gboolean fdn_device_get_frontmost_application_begin (gpointer user_data);
static void fdn_device_get_frontmost_application_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void fdn_device_get_frontmost_application_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void fdn_device_get_frontmost_application_operation_free (FdnDeviceGetFrontmostApplicationOperation * operation);

static napi_value fdn_device_enumerate_applications (napi_env env, napi_callback_info info);
static gboolean fdn_device_enumerate_applications_begin (gpointer user_data);
static void fdn_device_enumerate_applications_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void fdn_device_enumerate_applications_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void fdn_device_enumerate_applications_operation_free (FdnDeviceEnumerateApplicationsOperation * operation);

static napi_value fdn_device_get_process_by_pid (napi_env env, napi_callback_info info);
static gboolean fdn_device_get_process_by_pid_begin (gpointer user_data);
static void fdn_device_get_process_by_pid_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void fdn_device_get_process_by_pid_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void fdn_device_get_process_by_pid_operation_free (FdnDeviceGetProcessByPidOperation * operation);

static napi_value fdn_device_get_process_by_name (napi_env env, napi_callback_info info);
static gboolean fdn_device_get_process_by_name_begin (gpointer user_data);
static void fdn_device_get_process_by_name_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void fdn_device_get_process_by_name_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void fdn_device_get_process_by_name_operation_free (FdnDeviceGetProcessByNameOperation * operation);

static napi_value fdn_device_find_process_by_pid (napi_env env, napi_callback_info info);
static gboolean fdn_device_find_process_by_pid_begin (gpointer user_data);
static void fdn_device_find_process_by_pid_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void fdn_device_find_process_by_pid_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void fdn_device_find_process_by_pid_operation_free (FdnDeviceFindProcessByPidOperation * operation);

static napi_value fdn_device_find_process_by_name (napi_env env, napi_callback_info info);
static gboolean fdn_device_find_process_by_name_begin (gpointer user_data);
static void fdn_device_find_process_by_name_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void fdn_device_find_process_by_name_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void fdn_device_find_process_by_name_operation_free (FdnDeviceFindProcessByNameOperation * operation);

static napi_value fdn_device_enumerate_processes (napi_env env, napi_callback_info info);
static gboolean fdn_device_enumerate_processes_begin (gpointer user_data);
static void fdn_device_enumerate_processes_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void fdn_device_enumerate_processes_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void fdn_device_enumerate_processes_operation_free (FdnDeviceEnumerateProcessesOperation * operation);

static napi_value fdn_device_enable_spawn_gating (napi_env env, napi_callback_info info);
static gboolean fdn_device_enable_spawn_gating_begin (gpointer user_data);
static void fdn_device_enable_spawn_gating_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void fdn_device_enable_spawn_gating_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void fdn_device_enable_spawn_gating_operation_free (FdnDeviceEnableSpawnGatingOperation * operation);

static napi_value fdn_device_disable_spawn_gating (napi_env env, napi_callback_info info);
static gboolean fdn_device_disable_spawn_gating_begin (gpointer user_data);
static void fdn_device_disable_spawn_gating_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void fdn_device_disable_spawn_gating_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void fdn_device_disable_spawn_gating_operation_free (FdnDeviceDisableSpawnGatingOperation * operation);

static napi_value fdn_device_enumerate_pending_spawn (napi_env env, napi_callback_info info);
static gboolean fdn_device_enumerate_pending_spawn_begin (gpointer user_data);
static void fdn_device_enumerate_pending_spawn_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void fdn_device_enumerate_pending_spawn_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void fdn_device_enumerate_pending_spawn_operation_free (FdnDeviceEnumeratePendingSpawnOperation * operation);

static napi_value fdn_device_enumerate_pending_children (napi_env env, napi_callback_info info);
static gboolean fdn_device_enumerate_pending_children_begin (gpointer user_data);
static void fdn_device_enumerate_pending_children_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void fdn_device_enumerate_pending_children_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void fdn_device_enumerate_pending_children_operation_free (FdnDeviceEnumeratePendingChildrenOperation * operation);

static napi_value fdn_device_spawn (napi_env env, napi_callback_info info);
static gboolean fdn_device_spawn_begin (gpointer user_data);
static void fdn_device_spawn_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void fdn_device_spawn_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void fdn_device_spawn_operation_free (FdnDeviceSpawnOperation * operation);

static napi_value fdn_device_input (napi_env env, napi_callback_info info);
static gboolean fdn_device_input_begin (gpointer user_data);
static void fdn_device_input_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void fdn_device_input_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void fdn_device_input_operation_free (FdnDeviceInputOperation * operation);

static napi_value fdn_device_resume (napi_env env, napi_callback_info info);
static gboolean fdn_device_resume_begin (gpointer user_data);
static void fdn_device_resume_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void fdn_device_resume_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void fdn_device_resume_operation_free (FdnDeviceResumeOperation * operation);

static napi_value fdn_device_kill (napi_env env, napi_callback_info info);
static gboolean fdn_device_kill_begin (gpointer user_data);
static void fdn_device_kill_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void fdn_device_kill_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void fdn_device_kill_operation_free (FdnDeviceKillOperation * operation);

static napi_value fdn_device_attach (napi_env env, napi_callback_info info);
static gboolean fdn_device_attach_begin (gpointer user_data);
static void fdn_device_attach_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void fdn_device_attach_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void fdn_device_attach_operation_free (FdnDeviceAttachOperation * operation);

static napi_value fdn_device_inject_library_file (napi_env env, napi_callback_info info);
static gboolean fdn_device_inject_library_file_begin (gpointer user_data);
static void fdn_device_inject_library_file_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void fdn_device_inject_library_file_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void fdn_device_inject_library_file_operation_free (FdnDeviceInjectLibraryFileOperation * operation);

static napi_value fdn_device_inject_library_blob (napi_env env, napi_callback_info info);
static gboolean fdn_device_inject_library_blob_begin (gpointer user_data);
static void fdn_device_inject_library_blob_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void fdn_device_inject_library_blob_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void fdn_device_inject_library_blob_operation_free (FdnDeviceInjectLibraryBlobOperation * operation);

static napi_value fdn_device_open_channel (napi_env env, napi_callback_info info);
static gboolean fdn_device_open_channel_begin (gpointer user_data);
static void fdn_device_open_channel_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void fdn_device_open_channel_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void fdn_device_open_channel_operation_free (FdnDeviceOpenChannelOperation * operation);

static napi_value fdn_device_open_service (napi_env env, napi_callback_info info);
static gboolean fdn_device_open_service_begin (gpointer user_data);
static void fdn_device_open_service_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void fdn_device_open_service_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void fdn_device_open_service_operation_free (FdnDeviceOpenServiceOperation * operation);

static napi_value fdn_device_unpair (napi_env env, napi_callback_info info);
static gboolean fdn_device_unpair_begin (gpointer user_data);
static void fdn_device_unpair_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void fdn_device_unpair_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void fdn_device_unpair_operation_free (FdnDeviceUnpairOperation * operation);

static napi_value fdn_device_get_host_session (napi_env env, napi_callback_info info);
static gboolean fdn_device_get_host_session_begin (gpointer user_data);
static void fdn_device_get_host_session_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void fdn_device_get_host_session_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void fdn_device_get_host_session_operation_free (FdnDeviceGetHostSessionOperation * operation);

static napi_value fdn_device_get_id (napi_env env, napi_callback_info info);

static napi_value fdn_device_get_name (napi_env env, napi_callback_info info);

static napi_value fdn_device_get_icon (napi_env env, napi_callback_info info);

static napi_value fdn_device_get_dtype (napi_env env, napi_callback_info info);

static napi_value fdn_device_get_bus (napi_env env, napi_callback_info info);

static napi_value fdn_device_get_provider (napi_env env, napi_callback_info info);

static napi_value fdn_device_get_manager (napi_env env, napi_callback_info info);

static void fdn_cancellable_register (napi_env env, napi_value exports);
static gboolean fdn_cancellable_from_value (napi_env env, napi_value value, GCancellable ** result);
static napi_value fdn_cancellable_to_value (napi_env env, GCancellable * handle);
static napi_value fdn_cancellable_construct (napi_env env, napi_callback_info info);

static napi_value fdn_cancellable_cancel (napi_env env, napi_callback_info info);

static napi_value fdn_cancellable_disconnect (napi_env env, napi_callback_info info);

static napi_value fdn_cancellable_get_fd (napi_env env, napi_callback_info info);

static napi_value fdn_cancellable_is_cancelled (napi_env env, napi_callback_info info);

static napi_value fdn_cancellable_pop_current (napi_env env, napi_callback_info info);

static napi_value fdn_cancellable_push_current (napi_env env, napi_callback_info info);

static napi_value fdn_cancellable_reset (napi_env env, napi_callback_info info);

static napi_value fdn_cancellable_throw_if_cancelled (napi_env env, napi_callback_info info);

static napi_value fdn_boolean_to_value (napi_env env, gboolean value);
static gboolean fdn_int_from_value (napi_env env, napi_value value, gint * result);
static napi_value fdn_int_to_value (napi_env env, gint value);
static gboolean fdn_ulong_from_value (napi_env env, napi_value value, gulong * result);
static gboolean fdn_utf8_from_value (napi_env env, napi_value value, gchar ** str);

static napi_type_tag fdn_device_manager_type_tag = { 0xd2b1ceaa6a47478d, 0x85a09853ae47a97a };
static napi_type_tag fdn_device_type_tag = { 0x29b76d8bd2b648bf, 0x9276d1b278402c15 };
static napi_type_tag fdn_cancellable_type_tag = { 0x82b40fe2e82f47e5, 0x86fc43ab085bc81a };

static napi_ref fdn_device_manager_constructor;
static napi_ref fdn_device_constructor;
static napi_ref fdn_cancellable_constructor;

static napi_threadsafe_function fdn_device_manager_close_tsfn;
static napi_threadsafe_function fdn_device_manager_get_device_by_id_tsfn;
static napi_threadsafe_function fdn_device_manager_get_device_by_type_tsfn;
static napi_threadsafe_function fdn_device_manager_find_device_by_id_tsfn;
static napi_threadsafe_function fdn_device_manager_find_device_by_type_tsfn;
static napi_threadsafe_function fdn_device_manager_enumerate_devices_tsfn;
static napi_threadsafe_function fdn_device_manager_add_remote_device_tsfn;
static napi_threadsafe_function fdn_device_manager_remove_remote_device_tsfn;

static napi_threadsafe_function fdn_device_query_system_parameters_tsfn;
static napi_threadsafe_function fdn_device_get_frontmost_application_tsfn;
static napi_threadsafe_function fdn_device_enumerate_applications_tsfn;
static napi_threadsafe_function fdn_device_get_process_by_pid_tsfn;
static napi_threadsafe_function fdn_device_get_process_by_name_tsfn;
static napi_threadsafe_function fdn_device_find_process_by_pid_tsfn;
static napi_threadsafe_function fdn_device_find_process_by_name_tsfn;
static napi_threadsafe_function fdn_device_enumerate_processes_tsfn;
static napi_threadsafe_function fdn_device_enable_spawn_gating_tsfn;
static napi_threadsafe_function fdn_device_disable_spawn_gating_tsfn;
static napi_threadsafe_function fdn_device_enumerate_pending_spawn_tsfn;
static napi_threadsafe_function fdn_device_enumerate_pending_children_tsfn;
static napi_threadsafe_function fdn_device_spawn_tsfn;
static napi_threadsafe_function fdn_device_input_tsfn;
static napi_threadsafe_function fdn_device_resume_tsfn;
static napi_threadsafe_function fdn_device_kill_tsfn;
static napi_threadsafe_function fdn_device_attach_tsfn;
static napi_threadsafe_function fdn_device_inject_library_file_tsfn;
static napi_threadsafe_function fdn_device_inject_library_blob_tsfn;
static napi_threadsafe_function fdn_device_open_channel_tsfn;
static napi_threadsafe_function fdn_device_open_service_tsfn;
static napi_threadsafe_function fdn_device_unpair_tsfn;
static napi_threadsafe_function fdn_device_get_host_session_tsfn;

static napi_value
Init (napi_env env,
      napi_value exports)
{
  fdn_device_manager_register (env, exports);
  fdn_device_register (env, exports);
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
    { "close", NULL, fdn_device_manager_close, NULL, NULL, NULL, napi_default, NULL },
    { "getDeviceById", NULL, fdn_device_manager_get_device_by_id, NULL, NULL, NULL, napi_default, NULL },
    { "getDeviceByType", NULL, fdn_device_manager_get_device_by_type, NULL, NULL, NULL, napi_default, NULL },
    { "findDeviceById", NULL, fdn_device_manager_find_device_by_id, NULL, NULL, NULL, napi_default, NULL },
    { "findDeviceByType", NULL, fdn_device_manager_find_device_by_type, NULL, NULL, NULL, napi_default, NULL },
    { "enumerateDevices", NULL, fdn_device_manager_enumerate_devices, NULL, NULL, NULL, napi_default, NULL },
    { "addRemoteDevice", NULL, fdn_device_manager_add_remote_device, NULL, NULL, NULL, napi_default, NULL },
    { "removeRemoteDevice", NULL, fdn_device_manager_remove_remote_device, NULL, NULL, NULL, napi_default, NULL },
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
fdn_device_register (napi_env env,
                     napi_value exports)
{
  napi_property_descriptor properties[] =
  {
    { "isLost", NULL, fdn_device_is_lost, NULL, NULL, NULL, napi_default, NULL },
    { "querySystemParameters", NULL, fdn_device_query_system_parameters, NULL, NULL, NULL, napi_default, NULL },
    { "getFrontmostApplication", NULL, fdn_device_get_frontmost_application, NULL, NULL, NULL, napi_default, NULL },
    { "enumerateApplications", NULL, fdn_device_enumerate_applications, NULL, NULL, NULL, napi_default, NULL },
    { "getProcessByPid", NULL, fdn_device_get_process_by_pid, NULL, NULL, NULL, napi_default, NULL },
    { "getProcessByName", NULL, fdn_device_get_process_by_name, NULL, NULL, NULL, napi_default, NULL },
    { "findProcessByPid", NULL, fdn_device_find_process_by_pid, NULL, NULL, NULL, napi_default, NULL },
    { "findProcessByName", NULL, fdn_device_find_process_by_name, NULL, NULL, NULL, napi_default, NULL },
    { "enumerateProcesses", NULL, fdn_device_enumerate_processes, NULL, NULL, NULL, napi_default, NULL },
    { "enableSpawnGating", NULL, fdn_device_enable_spawn_gating, NULL, NULL, NULL, napi_default, NULL },
    { "disableSpawnGating", NULL, fdn_device_disable_spawn_gating, NULL, NULL, NULL, napi_default, NULL },
    { "enumeratePendingSpawn", NULL, fdn_device_enumerate_pending_spawn, NULL, NULL, NULL, napi_default, NULL },
    { "enumeratePendingChildren", NULL, fdn_device_enumerate_pending_children, NULL, NULL, NULL, napi_default, NULL },
    { "spawn", NULL, fdn_device_spawn, NULL, NULL, NULL, napi_default, NULL },
    { "input", NULL, fdn_device_input, NULL, NULL, NULL, napi_default, NULL },
    { "resume", NULL, fdn_device_resume, NULL, NULL, NULL, napi_default, NULL },
    { "kill", NULL, fdn_device_kill, NULL, NULL, NULL, napi_default, NULL },
    { "attach", NULL, fdn_device_attach, NULL, NULL, NULL, napi_default, NULL },
    { "injectLibraryFile", NULL, fdn_device_inject_library_file, NULL, NULL, NULL, napi_default, NULL },
    { "injectLibraryBlob", NULL, fdn_device_inject_library_blob, NULL, NULL, NULL, napi_default, NULL },
    { "openChannel", NULL, fdn_device_open_channel, NULL, NULL, NULL, napi_default, NULL },
    { "openService", NULL, fdn_device_open_service, NULL, NULL, NULL, napi_default, NULL },
    { "unpair", NULL, fdn_device_unpair, NULL, NULL, NULL, napi_default, NULL },
    { "getHostSession", NULL, fdn_device_get_host_session, NULL, NULL, NULL, napi_default, NULL },
    { "getId", NULL, fdn_device_get_id, NULL, NULL, NULL, napi_default, NULL },
    { "getName", NULL, fdn_device_get_name, NULL, NULL, NULL, napi_default, NULL },
    { "getIcon", NULL, fdn_device_get_icon, NULL, NULL, NULL, napi_default, NULL },
    { "getDtype", NULL, fdn_device_get_dtype, NULL, NULL, NULL, napi_default, NULL },
    { "getBus", NULL, fdn_device_get_bus, NULL, NULL, NULL, napi_default, NULL },
    { "getProvider", NULL, fdn_device_get_provider, NULL, NULL, NULL, napi_default, NULL },
    { "getManager", NULL, fdn_device_get_manager, NULL, NULL, NULL, napi_default, NULL },
  };

  napi_value constructor;
  napi_define_class (env, "Device", NAPI_AUTO_LENGTH, fdn_device_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_device_constructor);

  napi_set_named_property (env, exports, "Device", constructor);

  napi_value resource_name;

  napi_create_string_utf8 (env, "querySystemParameters", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_device_query_system_parameters_deliver, &fdn_device_query_system_parameters_tsfn);

  napi_create_string_utf8 (env, "getFrontmostApplication", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_device_get_frontmost_application_deliver, &fdn_device_get_frontmost_application_tsfn);

  napi_create_string_utf8 (env, "enumerateApplications", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_device_enumerate_applications_deliver, &fdn_device_enumerate_applications_tsfn);

  napi_create_string_utf8 (env, "getProcessByPid", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_device_get_process_by_pid_deliver, &fdn_device_get_process_by_pid_tsfn);

  napi_create_string_utf8 (env, "getProcessByName", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_device_get_process_by_name_deliver, &fdn_device_get_process_by_name_tsfn);

  napi_create_string_utf8 (env, "findProcessByPid", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_device_find_process_by_pid_deliver, &fdn_device_find_process_by_pid_tsfn);

  napi_create_string_utf8 (env, "findProcessByName", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_device_find_process_by_name_deliver, &fdn_device_find_process_by_name_tsfn);

  napi_create_string_utf8 (env, "enumerateProcesses", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_device_enumerate_processes_deliver, &fdn_device_enumerate_processes_tsfn);

  napi_create_string_utf8 (env, "enableSpawnGating", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_device_enable_spawn_gating_deliver, &fdn_device_enable_spawn_gating_tsfn);

  napi_create_string_utf8 (env, "disableSpawnGating", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_device_disable_spawn_gating_deliver, &fdn_device_disable_spawn_gating_tsfn);

  napi_create_string_utf8 (env, "enumeratePendingSpawn", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_device_enumerate_pending_spawn_deliver, &fdn_device_enumerate_pending_spawn_tsfn);

  napi_create_string_utf8 (env, "enumeratePendingChildren", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_device_enumerate_pending_children_deliver, &fdn_device_enumerate_pending_children_tsfn);

  napi_create_string_utf8 (env, "spawn", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_device_spawn_deliver, &fdn_device_spawn_tsfn);

  napi_create_string_utf8 (env, "input", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_device_input_deliver, &fdn_device_input_tsfn);

  napi_create_string_utf8 (env, "resume", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_device_resume_deliver, &fdn_device_resume_tsfn);

  napi_create_string_utf8 (env, "kill", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_device_kill_deliver, &fdn_device_kill_tsfn);

  napi_create_string_utf8 (env, "attach", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_device_attach_deliver, &fdn_device_attach_tsfn);

  napi_create_string_utf8 (env, "injectLibraryFile", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_device_inject_library_file_deliver, &fdn_device_inject_library_file_tsfn);

  napi_create_string_utf8 (env, "injectLibraryBlob", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_device_inject_library_blob_deliver, &fdn_device_inject_library_blob_tsfn);

  napi_create_string_utf8 (env, "openChannel", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_device_open_channel_deliver, &fdn_device_open_channel_tsfn);

  napi_create_string_utf8 (env, "openService", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_device_open_service_deliver, &fdn_device_open_service_tsfn);

  napi_create_string_utf8 (env, "unpair", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_device_unpair_deliver, &fdn_device_unpair_tsfn);

  napi_create_string_utf8 (env, "getHostSession", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_device_get_host_session_deliver, &fdn_device_get_host_session_tsfn);
}

static gboolean
fdn_device_from_value (napi_env env,
                       napi_value value,
                       FridaDevice ** result)
{
  napi_status status;
  bool is_instance;
  FridaDevice * handle;

  status = napi_check_object_type_tag (env, value, &fdn_device_type_tag, &is_instance);
  if (status != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of Device");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) &handle);

  g_object_ref (handle);
  *result = handle;

  return TRUE;
}

static napi_value
fdn_device_to_value (napi_env env,
                     FridaDevice * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_device_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_device_construct (napi_env env,
                      napi_callback_info info)
{
  napi_throw_error (env, NULL, "class Device cannot be constructed because it lacks a default constructor");
  return NULL;
}

static napi_value
fdn_device_is_lost (napi_env env,
                    napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaDevice * handle;
  gboolean return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_device_is_lost (handle);

  result = fdn_boolean_to_value (env, return_value);

  return result;
}

static napi_value
fdn_device_query_system_parameters (napi_env env,
                                    napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaDevice * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnDeviceQuerySystemParametersOperation * operation;
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

  operation = g_slice_new0 (FdnDeviceQuerySystemParametersOperation);
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
  g_source_set_callback (source, fdn_device_query_system_parameters_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, fdn_device_query_system_parameters_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    fdn_device_query_system_parameters_operation_free (operation);
    return NULL;
  }
}

static gboolean
fdn_device_query_system_parameters_begin (gpointer user_data)
{
  FdnDeviceQuerySystemParametersOperation * operation = user_data;

  frida_device_query_system_parameters (operation->handle,
      operation->cancellable,
      fdn_device_query_system_parameters_end, operation);

  return G_SOURCE_REMOVE;
}

static void
fdn_device_query_system_parameters_end (GObject * source_object,
                                        GAsyncResult * res,
                                        gpointer user_data)
{
  FdnDeviceQuerySystemParametersOperation * operation = user_data;

  

  operation->return_value = frida_device_query_system_parameters_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (fdn_device_query_system_parameters_tsfn, operation, napi_tsfn_blocking);
}

static void
fdn_device_query_system_parameters_deliver (napi_env env,
                                            napi_value js_cb,
                                            void * context,
                                            void * data)
{
  FdnDeviceQuerySystemParametersOperation * operation = data;

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
    result = fdn_hash_table_to_value (env, operation->return_value);
    napi_resolve_deferred (env, operation->deferred, result);
  }

  fdn_device_query_system_parameters_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_device_query_system_parameters_tsfn);
}

static void
fdn_device_query_system_parameters_operation_free (FdnDeviceQuerySystemParametersOperation * operation)
{
  g_slice_free (FdnDeviceQuerySystemParametersOperation, operation);
}

static napi_value
fdn_device_get_frontmost_application (napi_env env,
                                      napi_callback_info info)
{
  size_t argc = 2;
  napi_value args[2];
  napi_status status;
  napi_value jsthis;
  FridaDevice * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnDeviceGetFrontmostApplicationOperation * operation;
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

  operation = g_slice_new0 (FdnDeviceGetFrontmostApplicationOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0)
  {
    if (!fdn_frontmost_query_options_from_value (env, args[0], &operation->options))
      goto invalid_argument;
  }
  else
  {
    operation->options = NULL;
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
  g_source_set_callback (source, fdn_device_get_frontmost_application_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, fdn_device_get_frontmost_application_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    fdn_device_get_frontmost_application_operation_free (operation);
    return NULL;
  }
}

static gboolean
fdn_device_get_frontmost_application_begin (gpointer user_data)
{
  FdnDeviceGetFrontmostApplicationOperation * operation = user_data;

  frida_device_get_frontmost_application (operation->handle,
      operation->options, operation->cancellable,
      fdn_device_get_frontmost_application_end, operation);

  return G_SOURCE_REMOVE;
}

static void
fdn_device_get_frontmost_application_end (GObject * source_object,
                                          GAsyncResult * res,
                                          gpointer user_data)
{
  FdnDeviceGetFrontmostApplicationOperation * operation = user_data;

  

  operation->return_value = frida_device_get_frontmost_application_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (fdn_device_get_frontmost_application_tsfn, operation, napi_tsfn_blocking);
}

static void
fdn_device_get_frontmost_application_deliver (napi_env env,
                                              napi_value js_cb,
                                              void * context,
                                              void * data)
{
  FdnDeviceGetFrontmostApplicationOperation * operation = data;

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
    result = fdn_application_to_value (env, operation->return_value);
    napi_resolve_deferred (env, operation->deferred, result);
  }

  fdn_device_get_frontmost_application_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_device_get_frontmost_application_tsfn);
}

static void
fdn_device_get_frontmost_application_operation_free (FdnDeviceGetFrontmostApplicationOperation * operation)
{
  g_slice_free (FdnDeviceGetFrontmostApplicationOperation, operation);
}

static napi_value
fdn_device_enumerate_applications (napi_env env,
                                   napi_callback_info info)
{
  size_t argc = 2;
  napi_value args[2];
  napi_status status;
  napi_value jsthis;
  FridaDevice * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnDeviceEnumerateApplicationsOperation * operation;
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

  operation = g_slice_new0 (FdnDeviceEnumerateApplicationsOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0)
  {
    if (!fdn_application_query_options_from_value (env, args[0], &operation->options))
      goto invalid_argument;
  }
  else
  {
    operation->options = NULL;
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
  g_source_set_callback (source, fdn_device_enumerate_applications_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, fdn_device_enumerate_applications_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    fdn_device_enumerate_applications_operation_free (operation);
    return NULL;
  }
}

static gboolean
fdn_device_enumerate_applications_begin (gpointer user_data)
{
  FdnDeviceEnumerateApplicationsOperation * operation = user_data;

  frida_device_enumerate_applications (operation->handle,
      operation->options, operation->cancellable,
      fdn_device_enumerate_applications_end, operation);

  return G_SOURCE_REMOVE;
}

static void
fdn_device_enumerate_applications_end (GObject * source_object,
                                       GAsyncResult * res,
                                       gpointer user_data)
{
  FdnDeviceEnumerateApplicationsOperation * operation = user_data;

  

  operation->return_value = frida_device_enumerate_applications_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (fdn_device_enumerate_applications_tsfn, operation, napi_tsfn_blocking);
}

static void
fdn_device_enumerate_applications_deliver (napi_env env,
                                           napi_value js_cb,
                                           void * context,
                                           void * data)
{
  FdnDeviceEnumerateApplicationsOperation * operation = data;

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
    result = fdn_application_list_to_value (env, operation->return_value);
    napi_resolve_deferred (env, operation->deferred, result);
  }

  fdn_device_enumerate_applications_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_device_enumerate_applications_tsfn);
}

static void
fdn_device_enumerate_applications_operation_free (FdnDeviceEnumerateApplicationsOperation * operation)
{
  g_slice_free (FdnDeviceEnumerateApplicationsOperation, operation);
}

static napi_value
fdn_device_get_process_by_pid (napi_env env,
                               napi_callback_info info)
{
  size_t argc = 3;
  napi_value args[3];
  napi_status status;
  napi_value jsthis;
  FridaDevice * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnDeviceGetProcessByPidOperation * operation;
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

  operation = g_slice_new0 (FdnDeviceGetProcessByPidOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0)
  {
    if (!fdn_uint_from_value (env, args[0], &operation->pid))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: pid");
    goto invalid_argument;
  }

  if (argc > 1)
  {
    if (!fdn_process_match_options_from_value (env, args[1], &operation->options))
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
  g_source_set_callback (source, fdn_device_get_process_by_pid_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, fdn_device_get_process_by_pid_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    fdn_device_get_process_by_pid_operation_free (operation);
    return NULL;
  }
}

static gboolean
fdn_device_get_process_by_pid_begin (gpointer user_data)
{
  FdnDeviceGetProcessByPidOperation * operation = user_data;

  frida_device_get_process_by_pid (operation->handle,
      operation->pid, operation->options, operation->cancellable,
      fdn_device_get_process_by_pid_end, operation);

  return G_SOURCE_REMOVE;
}

static void
fdn_device_get_process_by_pid_end (GObject * source_object,
                                   GAsyncResult * res,
                                   gpointer user_data)
{
  FdnDeviceGetProcessByPidOperation * operation = user_data;

  

  operation->return_value = frida_device_get_process_by_pid_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (fdn_device_get_process_by_pid_tsfn, operation, napi_tsfn_blocking);
}

static void
fdn_device_get_process_by_pid_deliver (napi_env env,
                                       napi_value js_cb,
                                       void * context,
                                       void * data)
{
  FdnDeviceGetProcessByPidOperation * operation = data;

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
    result = fdn_process_to_value (env, operation->return_value);
    napi_resolve_deferred (env, operation->deferred, result);
  }

  fdn_device_get_process_by_pid_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_device_get_process_by_pid_tsfn);
}

static void
fdn_device_get_process_by_pid_operation_free (FdnDeviceGetProcessByPidOperation * operation)
{
  g_slice_free (FdnDeviceGetProcessByPidOperation, operation);
}

static napi_value
fdn_device_get_process_by_name (napi_env env,
                                napi_callback_info info)
{
  size_t argc = 3;
  napi_value args[3];
  napi_status status;
  napi_value jsthis;
  FridaDevice * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnDeviceGetProcessByNameOperation * operation;
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

  operation = g_slice_new0 (FdnDeviceGetProcessByNameOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0)
  {
    if (!fdn_utf8_from_value (env, args[0], &operation->name))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: name");
    goto invalid_argument;
  }

  if (argc > 1)
  {
    if (!fdn_process_match_options_from_value (env, args[1], &operation->options))
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
  g_source_set_callback (source, fdn_device_get_process_by_name_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, fdn_device_get_process_by_name_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    fdn_device_get_process_by_name_operation_free (operation);
    return NULL;
  }
}

static gboolean
fdn_device_get_process_by_name_begin (gpointer user_data)
{
  FdnDeviceGetProcessByNameOperation * operation = user_data;

  frida_device_get_process_by_name (operation->handle,
      operation->name, operation->options, operation->cancellable,
      fdn_device_get_process_by_name_end, operation);

  return G_SOURCE_REMOVE;
}

static void
fdn_device_get_process_by_name_end (GObject * source_object,
                                    GAsyncResult * res,
                                    gpointer user_data)
{
  FdnDeviceGetProcessByNameOperation * operation = user_data;

  

  operation->return_value = frida_device_get_process_by_name_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (fdn_device_get_process_by_name_tsfn, operation, napi_tsfn_blocking);
}

static void
fdn_device_get_process_by_name_deliver (napi_env env,
                                        napi_value js_cb,
                                        void * context,
                                        void * data)
{
  FdnDeviceGetProcessByNameOperation * operation = data;

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
    result = fdn_process_to_value (env, operation->return_value);
    napi_resolve_deferred (env, operation->deferred, result);
  }

  fdn_device_get_process_by_name_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_device_get_process_by_name_tsfn);
}

static void
fdn_device_get_process_by_name_operation_free (FdnDeviceGetProcessByNameOperation * operation)
{
  g_free (operation->name);
  g_slice_free (FdnDeviceGetProcessByNameOperation, operation);
}

static napi_value
fdn_device_find_process_by_pid (napi_env env,
                                napi_callback_info info)
{
  size_t argc = 3;
  napi_value args[3];
  napi_status status;
  napi_value jsthis;
  FridaDevice * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnDeviceFindProcessByPidOperation * operation;
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

  operation = g_slice_new0 (FdnDeviceFindProcessByPidOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0)
  {
    if (!fdn_uint_from_value (env, args[0], &operation->pid))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: pid");
    goto invalid_argument;
  }

  if (argc > 1)
  {
    if (!fdn_process_match_options_from_value (env, args[1], &operation->options))
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
  g_source_set_callback (source, fdn_device_find_process_by_pid_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, fdn_device_find_process_by_pid_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    fdn_device_find_process_by_pid_operation_free (operation);
    return NULL;
  }
}

static gboolean
fdn_device_find_process_by_pid_begin (gpointer user_data)
{
  FdnDeviceFindProcessByPidOperation * operation = user_data;

  frida_device_find_process_by_pid (operation->handle,
      operation->pid, operation->options, operation->cancellable,
      fdn_device_find_process_by_pid_end, operation);

  return G_SOURCE_REMOVE;
}

static void
fdn_device_find_process_by_pid_end (GObject * source_object,
                                    GAsyncResult * res,
                                    gpointer user_data)
{
  FdnDeviceFindProcessByPidOperation * operation = user_data;

  

  operation->return_value = frida_device_find_process_by_pid_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (fdn_device_find_process_by_pid_tsfn, operation, napi_tsfn_blocking);
}

static void
fdn_device_find_process_by_pid_deliver (napi_env env,
                                        napi_value js_cb,
                                        void * context,
                                        void * data)
{
  FdnDeviceFindProcessByPidOperation * operation = data;

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
    result = fdn_process_to_value (env, operation->return_value);
    napi_resolve_deferred (env, operation->deferred, result);
  }

  fdn_device_find_process_by_pid_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_device_find_process_by_pid_tsfn);
}

static void
fdn_device_find_process_by_pid_operation_free (FdnDeviceFindProcessByPidOperation * operation)
{
  g_slice_free (FdnDeviceFindProcessByPidOperation, operation);
}

static napi_value
fdn_device_find_process_by_name (napi_env env,
                                 napi_callback_info info)
{
  size_t argc = 3;
  napi_value args[3];
  napi_status status;
  napi_value jsthis;
  FridaDevice * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnDeviceFindProcessByNameOperation * operation;
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

  operation = g_slice_new0 (FdnDeviceFindProcessByNameOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0)
  {
    if (!fdn_utf8_from_value (env, args[0], &operation->name))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: name");
    goto invalid_argument;
  }

  if (argc > 1)
  {
    if (!fdn_process_match_options_from_value (env, args[1], &operation->options))
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
  g_source_set_callback (source, fdn_device_find_process_by_name_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, fdn_device_find_process_by_name_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    fdn_device_find_process_by_name_operation_free (operation);
    return NULL;
  }
}

static gboolean
fdn_device_find_process_by_name_begin (gpointer user_data)
{
  FdnDeviceFindProcessByNameOperation * operation = user_data;

  frida_device_find_process_by_name (operation->handle,
      operation->name, operation->options, operation->cancellable,
      fdn_device_find_process_by_name_end, operation);

  return G_SOURCE_REMOVE;
}

static void
fdn_device_find_process_by_name_end (GObject * source_object,
                                     GAsyncResult * res,
                                     gpointer user_data)
{
  FdnDeviceFindProcessByNameOperation * operation = user_data;

  

  operation->return_value = frida_device_find_process_by_name_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (fdn_device_find_process_by_name_tsfn, operation, napi_tsfn_blocking);
}

static void
fdn_device_find_process_by_name_deliver (napi_env env,
                                         napi_value js_cb,
                                         void * context,
                                         void * data)
{
  FdnDeviceFindProcessByNameOperation * operation = data;

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
    result = fdn_process_to_value (env, operation->return_value);
    napi_resolve_deferred (env, operation->deferred, result);
  }

  fdn_device_find_process_by_name_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_device_find_process_by_name_tsfn);
}

static void
fdn_device_find_process_by_name_operation_free (FdnDeviceFindProcessByNameOperation * operation)
{
  g_free (operation->name);
  g_slice_free (FdnDeviceFindProcessByNameOperation, operation);
}

static napi_value
fdn_device_enumerate_processes (napi_env env,
                                napi_callback_info info)
{
  size_t argc = 2;
  napi_value args[2];
  napi_status status;
  napi_value jsthis;
  FridaDevice * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnDeviceEnumerateProcessesOperation * operation;
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

  operation = g_slice_new0 (FdnDeviceEnumerateProcessesOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0)
  {
    if (!fdn_process_query_options_from_value (env, args[0], &operation->options))
      goto invalid_argument;
  }
  else
  {
    operation->options = NULL;
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
  g_source_set_callback (source, fdn_device_enumerate_processes_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, fdn_device_enumerate_processes_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    fdn_device_enumerate_processes_operation_free (operation);
    return NULL;
  }
}

static gboolean
fdn_device_enumerate_processes_begin (gpointer user_data)
{
  FdnDeviceEnumerateProcessesOperation * operation = user_data;

  frida_device_enumerate_processes (operation->handle,
      operation->options, operation->cancellable,
      fdn_device_enumerate_processes_end, operation);

  return G_SOURCE_REMOVE;
}

static void
fdn_device_enumerate_processes_end (GObject * source_object,
                                    GAsyncResult * res,
                                    gpointer user_data)
{
  FdnDeviceEnumerateProcessesOperation * operation = user_data;

  

  operation->return_value = frida_device_enumerate_processes_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (fdn_device_enumerate_processes_tsfn, operation, napi_tsfn_blocking);
}

static void
fdn_device_enumerate_processes_deliver (napi_env env,
                                        napi_value js_cb,
                                        void * context,
                                        void * data)
{
  FdnDeviceEnumerateProcessesOperation * operation = data;

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
    result = fdn_process_list_to_value (env, operation->return_value);
    napi_resolve_deferred (env, operation->deferred, result);
  }

  fdn_device_enumerate_processes_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_device_enumerate_processes_tsfn);
}

static void
fdn_device_enumerate_processes_operation_free (FdnDeviceEnumerateProcessesOperation * operation)
{
  g_slice_free (FdnDeviceEnumerateProcessesOperation, operation);
}

static napi_value
fdn_device_enable_spawn_gating (napi_env env,
                                napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaDevice * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnDeviceEnableSpawnGatingOperation * operation;
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

  operation = g_slice_new0 (FdnDeviceEnableSpawnGatingOperation);
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
  g_source_set_callback (source, fdn_device_enable_spawn_gating_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, fdn_device_enable_spawn_gating_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    fdn_device_enable_spawn_gating_operation_free (operation);
    return NULL;
  }
}

static gboolean
fdn_device_enable_spawn_gating_begin (gpointer user_data)
{
  FdnDeviceEnableSpawnGatingOperation * operation = user_data;

  frida_device_enable_spawn_gating (operation->handle,
      operation->cancellable,
      fdn_device_enable_spawn_gating_end, operation);

  return G_SOURCE_REMOVE;
}

static void
fdn_device_enable_spawn_gating_end (GObject * source_object,
                                    GAsyncResult * res,
                                    gpointer user_data)
{
  FdnDeviceEnableSpawnGatingOperation * operation = user_data;

  frida_device_enable_spawn_gating_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (fdn_device_enable_spawn_gating_tsfn, operation, napi_tsfn_blocking);
}

static void
fdn_device_enable_spawn_gating_deliver (napi_env env,
                                        napi_value js_cb,
                                        void * context,
                                        void * data)
{
  FdnDeviceEnableSpawnGatingOperation * operation = data;

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

  fdn_device_enable_spawn_gating_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_device_enable_spawn_gating_tsfn);
}

static void
fdn_device_enable_spawn_gating_operation_free (FdnDeviceEnableSpawnGatingOperation * operation)
{
  g_slice_free (FdnDeviceEnableSpawnGatingOperation, operation);
}

static napi_value
fdn_device_disable_spawn_gating (napi_env env,
                                 napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaDevice * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnDeviceDisableSpawnGatingOperation * operation;
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

  operation = g_slice_new0 (FdnDeviceDisableSpawnGatingOperation);
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
  g_source_set_callback (source, fdn_device_disable_spawn_gating_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, fdn_device_disable_spawn_gating_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    fdn_device_disable_spawn_gating_operation_free (operation);
    return NULL;
  }
}

static gboolean
fdn_device_disable_spawn_gating_begin (gpointer user_data)
{
  FdnDeviceDisableSpawnGatingOperation * operation = user_data;

  frida_device_disable_spawn_gating (operation->handle,
      operation->cancellable,
      fdn_device_disable_spawn_gating_end, operation);

  return G_SOURCE_REMOVE;
}

static void
fdn_device_disable_spawn_gating_end (GObject * source_object,
                                     GAsyncResult * res,
                                     gpointer user_data)
{
  FdnDeviceDisableSpawnGatingOperation * operation = user_data;

  frida_device_disable_spawn_gating_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (fdn_device_disable_spawn_gating_tsfn, operation, napi_tsfn_blocking);
}

static void
fdn_device_disable_spawn_gating_deliver (napi_env env,
                                         napi_value js_cb,
                                         void * context,
                                         void * data)
{
  FdnDeviceDisableSpawnGatingOperation * operation = data;

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

  fdn_device_disable_spawn_gating_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_device_disable_spawn_gating_tsfn);
}

static void
fdn_device_disable_spawn_gating_operation_free (FdnDeviceDisableSpawnGatingOperation * operation)
{
  g_slice_free (FdnDeviceDisableSpawnGatingOperation, operation);
}

static napi_value
fdn_device_enumerate_pending_spawn (napi_env env,
                                    napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaDevice * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnDeviceEnumeratePendingSpawnOperation * operation;
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

  operation = g_slice_new0 (FdnDeviceEnumeratePendingSpawnOperation);
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
  g_source_set_callback (source, fdn_device_enumerate_pending_spawn_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, fdn_device_enumerate_pending_spawn_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    fdn_device_enumerate_pending_spawn_operation_free (operation);
    return NULL;
  }
}

static gboolean
fdn_device_enumerate_pending_spawn_begin (gpointer user_data)
{
  FdnDeviceEnumeratePendingSpawnOperation * operation = user_data;

  frida_device_enumerate_pending_spawn (operation->handle,
      operation->cancellable,
      fdn_device_enumerate_pending_spawn_end, operation);

  return G_SOURCE_REMOVE;
}

static void
fdn_device_enumerate_pending_spawn_end (GObject * source_object,
                                        GAsyncResult * res,
                                        gpointer user_data)
{
  FdnDeviceEnumeratePendingSpawnOperation * operation = user_data;

  

  operation->return_value = frida_device_enumerate_pending_spawn_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (fdn_device_enumerate_pending_spawn_tsfn, operation, napi_tsfn_blocking);
}

static void
fdn_device_enumerate_pending_spawn_deliver (napi_env env,
                                            napi_value js_cb,
                                            void * context,
                                            void * data)
{
  FdnDeviceEnumeratePendingSpawnOperation * operation = data;

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
    result = fdn_spawn_list_to_value (env, operation->return_value);
    napi_resolve_deferred (env, operation->deferred, result);
  }

  fdn_device_enumerate_pending_spawn_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_device_enumerate_pending_spawn_tsfn);
}

static void
fdn_device_enumerate_pending_spawn_operation_free (FdnDeviceEnumeratePendingSpawnOperation * operation)
{
  g_slice_free (FdnDeviceEnumeratePendingSpawnOperation, operation);
}

static napi_value
fdn_device_enumerate_pending_children (napi_env env,
                                       napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaDevice * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnDeviceEnumeratePendingChildrenOperation * operation;
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

  operation = g_slice_new0 (FdnDeviceEnumeratePendingChildrenOperation);
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
  g_source_set_callback (source, fdn_device_enumerate_pending_children_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, fdn_device_enumerate_pending_children_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    fdn_device_enumerate_pending_children_operation_free (operation);
    return NULL;
  }
}

static gboolean
fdn_device_enumerate_pending_children_begin (gpointer user_data)
{
  FdnDeviceEnumeratePendingChildrenOperation * operation = user_data;

  frida_device_enumerate_pending_children (operation->handle,
      operation->cancellable,
      fdn_device_enumerate_pending_children_end, operation);

  return G_SOURCE_REMOVE;
}

static void
fdn_device_enumerate_pending_children_end (GObject * source_object,
                                           GAsyncResult * res,
                                           gpointer user_data)
{
  FdnDeviceEnumeratePendingChildrenOperation * operation = user_data;

  

  operation->return_value = frida_device_enumerate_pending_children_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (fdn_device_enumerate_pending_children_tsfn, operation, napi_tsfn_blocking);
}

static void
fdn_device_enumerate_pending_children_deliver (napi_env env,
                                               napi_value js_cb,
                                               void * context,
                                               void * data)
{
  FdnDeviceEnumeratePendingChildrenOperation * operation = data;

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
    result = fdn_child_list_to_value (env, operation->return_value);
    napi_resolve_deferred (env, operation->deferred, result);
  }

  fdn_device_enumerate_pending_children_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_device_enumerate_pending_children_tsfn);
}

static void
fdn_device_enumerate_pending_children_operation_free (FdnDeviceEnumeratePendingChildrenOperation * operation)
{
  g_slice_free (FdnDeviceEnumeratePendingChildrenOperation, operation);
}

static napi_value
fdn_device_spawn (napi_env env,
                  napi_callback_info info)
{
  size_t argc = 3;
  napi_value args[3];
  napi_status status;
  napi_value jsthis;
  FridaDevice * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnDeviceSpawnOperation * operation;
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

  operation = g_slice_new0 (FdnDeviceSpawnOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0)
  {
    if (!fdn_utf8_from_value (env, args[0], &operation->program))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: program");
    goto invalid_argument;
  }

  if (argc > 1)
  {
    if (!fdn_spawn_options_from_value (env, args[1], &operation->options))
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
  g_source_set_callback (source, fdn_device_spawn_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, fdn_device_spawn_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    fdn_device_spawn_operation_free (operation);
    return NULL;
  }
}

static gboolean
fdn_device_spawn_begin (gpointer user_data)
{
  FdnDeviceSpawnOperation * operation = user_data;

  frida_device_spawn (operation->handle,
      operation->program, operation->options, operation->cancellable,
      fdn_device_spawn_end, operation);

  return G_SOURCE_REMOVE;
}

static void
fdn_device_spawn_end (GObject * source_object,
                      GAsyncResult * res,
                      gpointer user_data)
{
  FdnDeviceSpawnOperation * operation = user_data;

  

  operation->return_value = frida_device_spawn_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (fdn_device_spawn_tsfn, operation, napi_tsfn_blocking);
}

static void
fdn_device_spawn_deliver (napi_env env,
                          napi_value js_cb,
                          void * context,
                          void * data)
{
  FdnDeviceSpawnOperation * operation = data;

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
    result = fdn_uint_to_value (env, operation->return_value);
    napi_resolve_deferred (env, operation->deferred, result);
  }

  fdn_device_spawn_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_device_spawn_tsfn);
}

static void
fdn_device_spawn_operation_free (FdnDeviceSpawnOperation * operation)
{
  g_free (operation->program);
  g_slice_free (FdnDeviceSpawnOperation, operation);
}

static napi_value
fdn_device_input (napi_env env,
                  napi_callback_info info)
{
  size_t argc = 3;
  napi_value args[3];
  napi_status status;
  napi_value jsthis;
  FridaDevice * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnDeviceInputOperation * operation;
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

  operation = g_slice_new0 (FdnDeviceInputOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0)
  {
    if (!fdn_uint_from_value (env, args[0], &operation->pid))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: pid");
    goto invalid_argument;
  }

  if (argc > 1)
  {
    if (!fdn_bytes_from_value (env, args[1], &operation->data))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: data");
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
  g_source_set_callback (source, fdn_device_input_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, fdn_device_input_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    fdn_device_input_operation_free (operation);
    return NULL;
  }
}

static gboolean
fdn_device_input_begin (gpointer user_data)
{
  FdnDeviceInputOperation * operation = user_data;

  frida_device_input (operation->handle,
      operation->pid, operation->data, operation->cancellable,
      fdn_device_input_end, operation);

  return G_SOURCE_REMOVE;
}

static void
fdn_device_input_end (GObject * source_object,
                      GAsyncResult * res,
                      gpointer user_data)
{
  FdnDeviceInputOperation * operation = user_data;

  frida_device_input_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (fdn_device_input_tsfn, operation, napi_tsfn_blocking);
}

static void
fdn_device_input_deliver (napi_env env,
                          napi_value js_cb,
                          void * context,
                          void * data)
{
  FdnDeviceInputOperation * operation = data;

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

  fdn_device_input_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_device_input_tsfn);
}

static void
fdn_device_input_operation_free (FdnDeviceInputOperation * operation)
{
  g_slice_free (FdnDeviceInputOperation, operation);
}

static napi_value
fdn_device_resume (napi_env env,
                   napi_callback_info info)
{
  size_t argc = 2;
  napi_value args[2];
  napi_status status;
  napi_value jsthis;
  FridaDevice * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnDeviceResumeOperation * operation;
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

  operation = g_slice_new0 (FdnDeviceResumeOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0)
  {
    if (!fdn_uint_from_value (env, args[0], &operation->pid))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: pid");
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
  g_source_set_callback (source, fdn_device_resume_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, fdn_device_resume_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    fdn_device_resume_operation_free (operation);
    return NULL;
  }
}

static gboolean
fdn_device_resume_begin (gpointer user_data)
{
  FdnDeviceResumeOperation * operation = user_data;

  frida_device_resume (operation->handle,
      operation->pid, operation->cancellable,
      fdn_device_resume_end, operation);

  return G_SOURCE_REMOVE;
}

static void
fdn_device_resume_end (GObject * source_object,
                       GAsyncResult * res,
                       gpointer user_data)
{
  FdnDeviceResumeOperation * operation = user_data;

  frida_device_resume_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (fdn_device_resume_tsfn, operation, napi_tsfn_blocking);
}

static void
fdn_device_resume_deliver (napi_env env,
                           napi_value js_cb,
                           void * context,
                           void * data)
{
  FdnDeviceResumeOperation * operation = data;

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

  fdn_device_resume_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_device_resume_tsfn);
}

static void
fdn_device_resume_operation_free (FdnDeviceResumeOperation * operation)
{
  g_slice_free (FdnDeviceResumeOperation, operation);
}

static napi_value
fdn_device_kill (napi_env env,
                 napi_callback_info info)
{
  size_t argc = 2;
  napi_value args[2];
  napi_status status;
  napi_value jsthis;
  FridaDevice * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnDeviceKillOperation * operation;
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

  operation = g_slice_new0 (FdnDeviceKillOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0)
  {
    if (!fdn_uint_from_value (env, args[0], &operation->pid))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: pid");
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
  g_source_set_callback (source, fdn_device_kill_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, fdn_device_kill_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    fdn_device_kill_operation_free (operation);
    return NULL;
  }
}

static gboolean
fdn_device_kill_begin (gpointer user_data)
{
  FdnDeviceKillOperation * operation = user_data;

  frida_device_kill (operation->handle,
      operation->pid, operation->cancellable,
      fdn_device_kill_end, operation);

  return G_SOURCE_REMOVE;
}

static void
fdn_device_kill_end (GObject * source_object,
                     GAsyncResult * res,
                     gpointer user_data)
{
  FdnDeviceKillOperation * operation = user_data;

  frida_device_kill_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (fdn_device_kill_tsfn, operation, napi_tsfn_blocking);
}

static void
fdn_device_kill_deliver (napi_env env,
                         napi_value js_cb,
                         void * context,
                         void * data)
{
  FdnDeviceKillOperation * operation = data;

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

  fdn_device_kill_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_device_kill_tsfn);
}

static void
fdn_device_kill_operation_free (FdnDeviceKillOperation * operation)
{
  g_slice_free (FdnDeviceKillOperation, operation);
}

static napi_value
fdn_device_attach (napi_env env,
                   napi_callback_info info)
{
  size_t argc = 3;
  napi_value args[3];
  napi_status status;
  napi_value jsthis;
  FridaDevice * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnDeviceAttachOperation * operation;
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

  operation = g_slice_new0 (FdnDeviceAttachOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0)
  {
    if (!fdn_uint_from_value (env, args[0], &operation->pid))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: pid");
    goto invalid_argument;
  }

  if (argc > 1)
  {
    if (!fdn_session_options_from_value (env, args[1], &operation->options))
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
  g_source_set_callback (source, fdn_device_attach_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, fdn_device_attach_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    fdn_device_attach_operation_free (operation);
    return NULL;
  }
}

static gboolean
fdn_device_attach_begin (gpointer user_data)
{
  FdnDeviceAttachOperation * operation = user_data;

  frida_device_attach (operation->handle,
      operation->pid, operation->options, operation->cancellable,
      fdn_device_attach_end, operation);

  return G_SOURCE_REMOVE;
}

static void
fdn_device_attach_end (GObject * source_object,
                       GAsyncResult * res,
                       gpointer user_data)
{
  FdnDeviceAttachOperation * operation = user_data;

  

  operation->return_value = frida_device_attach_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (fdn_device_attach_tsfn, operation, napi_tsfn_blocking);
}

static void
fdn_device_attach_deliver (napi_env env,
                           napi_value js_cb,
                           void * context,
                           void * data)
{
  FdnDeviceAttachOperation * operation = data;

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
    result = fdn_session_to_value (env, operation->return_value);
    napi_resolve_deferred (env, operation->deferred, result);
  }

  fdn_device_attach_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_device_attach_tsfn);
}

static void
fdn_device_attach_operation_free (FdnDeviceAttachOperation * operation)
{
  g_slice_free (FdnDeviceAttachOperation, operation);
}

static napi_value
fdn_device_inject_library_file (napi_env env,
                                napi_callback_info info)
{
  size_t argc = 5;
  napi_value args[5];
  napi_status status;
  napi_value jsthis;
  FridaDevice * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnDeviceInjectLibraryFileOperation * operation;
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

  operation = g_slice_new0 (FdnDeviceInjectLibraryFileOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0)
  {
    if (!fdn_uint_from_value (env, args[0], &operation->pid))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: pid");
    goto invalid_argument;
  }

  if (argc > 1)
  {
    if (!fdn_utf8_from_value (env, args[1], &operation->path))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: path");
    goto invalid_argument;
  }

  if (argc > 2)
  {
    if (!fdn_utf8_from_value (env, args[2], &operation->entrypoint))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: entrypoint");
    goto invalid_argument;
  }

  if (argc > 3)
  {
    if (!fdn_utf8_from_value (env, args[3], &operation->data))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: data");
    goto invalid_argument;
  }

  if (argc > 4)
  {
    if (!fdn_cancellable_from_value (env, args[4], &operation->cancellable))
      goto invalid_argument;
  }
  else
  {
    operation->cancellable = NULL;
  }

  source = g_idle_source_new ();
  g_source_set_callback (source, fdn_device_inject_library_file_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, fdn_device_inject_library_file_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    fdn_device_inject_library_file_operation_free (operation);
    return NULL;
  }
}

static gboolean
fdn_device_inject_library_file_begin (gpointer user_data)
{
  FdnDeviceInjectLibraryFileOperation * operation = user_data;

  frida_device_inject_library_file (operation->handle,
      operation->pid, operation->path, operation->entrypoint, operation->data, operation->cancellable,
      fdn_device_inject_library_file_end, operation);

  return G_SOURCE_REMOVE;
}

static void
fdn_device_inject_library_file_end (GObject * source_object,
                                    GAsyncResult * res,
                                    gpointer user_data)
{
  FdnDeviceInjectLibraryFileOperation * operation = user_data;

  

  operation->return_value = frida_device_inject_library_file_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (fdn_device_inject_library_file_tsfn, operation, napi_tsfn_blocking);
}

static void
fdn_device_inject_library_file_deliver (napi_env env,
                                        napi_value js_cb,
                                        void * context,
                                        void * data)
{
  FdnDeviceInjectLibraryFileOperation * operation = data;

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
    result = fdn_uint_to_value (env, operation->return_value);
    napi_resolve_deferred (env, operation->deferred, result);
  }

  fdn_device_inject_library_file_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_device_inject_library_file_tsfn);
}

static void
fdn_device_inject_library_file_operation_free (FdnDeviceInjectLibraryFileOperation * operation)
{
  g_free (operation->path);
  g_free (operation->entrypoint);
  g_free (operation->data);
  g_slice_free (FdnDeviceInjectLibraryFileOperation, operation);
}

static napi_value
fdn_device_inject_library_blob (napi_env env,
                                napi_callback_info info)
{
  size_t argc = 5;
  napi_value args[5];
  napi_status status;
  napi_value jsthis;
  FridaDevice * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnDeviceInjectLibraryBlobOperation * operation;
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

  operation = g_slice_new0 (FdnDeviceInjectLibraryBlobOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0)
  {
    if (!fdn_uint_from_value (env, args[0], &operation->pid))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: pid");
    goto invalid_argument;
  }

  if (argc > 1)
  {
    if (!fdn_bytes_from_value (env, args[1], &operation->blob))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: blob");
    goto invalid_argument;
  }

  if (argc > 2)
  {
    if (!fdn_utf8_from_value (env, args[2], &operation->entrypoint))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: entrypoint");
    goto invalid_argument;
  }

  if (argc > 3)
  {
    if (!fdn_utf8_from_value (env, args[3], &operation->data))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: data");
    goto invalid_argument;
  }

  if (argc > 4)
  {
    if (!fdn_cancellable_from_value (env, args[4], &operation->cancellable))
      goto invalid_argument;
  }
  else
  {
    operation->cancellable = NULL;
  }

  source = g_idle_source_new ();
  g_source_set_callback (source, fdn_device_inject_library_blob_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, fdn_device_inject_library_blob_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    fdn_device_inject_library_blob_operation_free (operation);
    return NULL;
  }
}

static gboolean
fdn_device_inject_library_blob_begin (gpointer user_data)
{
  FdnDeviceInjectLibraryBlobOperation * operation = user_data;

  frida_device_inject_library_blob (operation->handle,
      operation->pid, operation->blob, operation->entrypoint, operation->data, operation->cancellable,
      fdn_device_inject_library_blob_end, operation);

  return G_SOURCE_REMOVE;
}

static void
fdn_device_inject_library_blob_end (GObject * source_object,
                                    GAsyncResult * res,
                                    gpointer user_data)
{
  FdnDeviceInjectLibraryBlobOperation * operation = user_data;

  

  operation->return_value = frida_device_inject_library_blob_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (fdn_device_inject_library_blob_tsfn, operation, napi_tsfn_blocking);
}

static void
fdn_device_inject_library_blob_deliver (napi_env env,
                                        napi_value js_cb,
                                        void * context,
                                        void * data)
{
  FdnDeviceInjectLibraryBlobOperation * operation = data;

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
    result = fdn_uint_to_value (env, operation->return_value);
    napi_resolve_deferred (env, operation->deferred, result);
  }

  fdn_device_inject_library_blob_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_device_inject_library_blob_tsfn);
}

static void
fdn_device_inject_library_blob_operation_free (FdnDeviceInjectLibraryBlobOperation * operation)
{
  g_free (operation->entrypoint);
  g_free (operation->data);
  g_slice_free (FdnDeviceInjectLibraryBlobOperation, operation);
}

static napi_value
fdn_device_open_channel (napi_env env,
                         napi_callback_info info)
{
  size_t argc = 2;
  napi_value args[2];
  napi_status status;
  napi_value jsthis;
  FridaDevice * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnDeviceOpenChannelOperation * operation;
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

  operation = g_slice_new0 (FdnDeviceOpenChannelOperation);
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
  g_source_set_callback (source, fdn_device_open_channel_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, fdn_device_open_channel_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    fdn_device_open_channel_operation_free (operation);
    return NULL;
  }
}

static gboolean
fdn_device_open_channel_begin (gpointer user_data)
{
  FdnDeviceOpenChannelOperation * operation = user_data;

  frida_device_open_channel (operation->handle,
      operation->address, operation->cancellable,
      fdn_device_open_channel_end, operation);

  return G_SOURCE_REMOVE;
}

static void
fdn_device_open_channel_end (GObject * source_object,
                             GAsyncResult * res,
                             gpointer user_data)
{
  FdnDeviceOpenChannelOperation * operation = user_data;

  

  operation->return_value = frida_device_open_channel_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (fdn_device_open_channel_tsfn, operation, napi_tsfn_blocking);
}

static void
fdn_device_open_channel_deliver (napi_env env,
                                 napi_value js_cb,
                                 void * context,
                                 void * data)
{
  FdnDeviceOpenChannelOperation * operation = data;

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
    result = fdn_i_o_stream_to_value (env, operation->return_value);
    napi_resolve_deferred (env, operation->deferred, result);
  }

  fdn_device_open_channel_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_device_open_channel_tsfn);
}

static void
fdn_device_open_channel_operation_free (FdnDeviceOpenChannelOperation * operation)
{
  g_free (operation->address);
  g_slice_free (FdnDeviceOpenChannelOperation, operation);
}

static napi_value
fdn_device_open_service (napi_env env,
                         napi_callback_info info)
{
  size_t argc = 2;
  napi_value args[2];
  napi_status status;
  napi_value jsthis;
  FridaDevice * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnDeviceOpenServiceOperation * operation;
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

  operation = g_slice_new0 (FdnDeviceOpenServiceOperation);
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
  g_source_set_callback (source, fdn_device_open_service_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, fdn_device_open_service_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    fdn_device_open_service_operation_free (operation);
    return NULL;
  }
}

static gboolean
fdn_device_open_service_begin (gpointer user_data)
{
  FdnDeviceOpenServiceOperation * operation = user_data;

  frida_device_open_service (operation->handle,
      operation->address, operation->cancellable,
      fdn_device_open_service_end, operation);

  return G_SOURCE_REMOVE;
}

static void
fdn_device_open_service_end (GObject * source_object,
                             GAsyncResult * res,
                             gpointer user_data)
{
  FdnDeviceOpenServiceOperation * operation = user_data;

  

  operation->return_value = frida_device_open_service_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (fdn_device_open_service_tsfn, operation, napi_tsfn_blocking);
}

static void
fdn_device_open_service_deliver (napi_env env,
                                 napi_value js_cb,
                                 void * context,
                                 void * data)
{
  FdnDeviceOpenServiceOperation * operation = data;

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
    result = fdn_service_to_value (env, operation->return_value);
    napi_resolve_deferred (env, operation->deferred, result);
  }

  fdn_device_open_service_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_device_open_service_tsfn);
}

static void
fdn_device_open_service_operation_free (FdnDeviceOpenServiceOperation * operation)
{
  g_free (operation->address);
  g_slice_free (FdnDeviceOpenServiceOperation, operation);
}

static napi_value
fdn_device_unpair (napi_env env,
                   napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaDevice * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnDeviceUnpairOperation * operation;
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

  operation = g_slice_new0 (FdnDeviceUnpairOperation);
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
  g_source_set_callback (source, fdn_device_unpair_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, fdn_device_unpair_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    fdn_device_unpair_operation_free (operation);
    return NULL;
  }
}

static gboolean
fdn_device_unpair_begin (gpointer user_data)
{
  FdnDeviceUnpairOperation * operation = user_data;

  frida_device_unpair (operation->handle,
      operation->cancellable,
      fdn_device_unpair_end, operation);

  return G_SOURCE_REMOVE;
}

static void
fdn_device_unpair_end (GObject * source_object,
                       GAsyncResult * res,
                       gpointer user_data)
{
  FdnDeviceUnpairOperation * operation = user_data;

  frida_device_unpair_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (fdn_device_unpair_tsfn, operation, napi_tsfn_blocking);
}

static void
fdn_device_unpair_deliver (napi_env env,
                           napi_value js_cb,
                           void * context,
                           void * data)
{
  FdnDeviceUnpairOperation * operation = data;

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

  fdn_device_unpair_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_device_unpair_tsfn);
}

static void
fdn_device_unpair_operation_free (FdnDeviceUnpairOperation * operation)
{
  g_slice_free (FdnDeviceUnpairOperation, operation);
}

static napi_value
fdn_device_get_host_session (napi_env env,
                             napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaDevice * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnDeviceGetHostSessionOperation * operation;
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

  operation = g_slice_new0 (FdnDeviceGetHostSessionOperation);
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
  g_source_set_callback (source, fdn_device_get_host_session_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, fdn_device_get_host_session_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    fdn_device_get_host_session_operation_free (operation);
    return NULL;
  }
}

static gboolean
fdn_device_get_host_session_begin (gpointer user_data)
{
  FdnDeviceGetHostSessionOperation * operation = user_data;

  frida_device_get_host_session (operation->handle,
      operation->cancellable,
      fdn_device_get_host_session_end, operation);

  return G_SOURCE_REMOVE;
}

static void
fdn_device_get_host_session_end (GObject * source_object,
                                 GAsyncResult * res,
                                 gpointer user_data)
{
  FdnDeviceGetHostSessionOperation * operation = user_data;

  

  operation->return_value = frida_device_get_host_session_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (fdn_device_get_host_session_tsfn, operation, napi_tsfn_blocking);
}

static void
fdn_device_get_host_session_deliver (napi_env env,
                                     napi_value js_cb,
                                     void * context,
                                     void * data)
{
  FdnDeviceGetHostSessionOperation * operation = data;

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
    result = fdn_host_session_to_value (env, operation->return_value);
    napi_resolve_deferred (env, operation->deferred, result);
  }

  fdn_device_get_host_session_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_device_get_host_session_tsfn);
}

static void
fdn_device_get_host_session_operation_free (FdnDeviceGetHostSessionOperation * operation)
{
  g_slice_free (FdnDeviceGetHostSessionOperation, operation);
}

static napi_value
fdn_device_get_id (napi_env env,
                   napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaDevice * handle;
  gchar * return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_device_get_id (handle);

  result = fdn_utf8_to_value (env, return_value);

  return result;
}

static napi_value
fdn_device_get_name (napi_env env,
                     napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaDevice * handle;
  gchar * return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_device_get_name (handle);

  result = fdn_utf8_to_value (env, return_value);

  return result;
}

static napi_value
fdn_device_get_icon (napi_env env,
                     napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaDevice * handle;
  GVariant * return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_device_get_icon (handle);

  result = fdn_variant_to_value (env, return_value);

  return result;
}

static napi_value
fdn_device_get_dtype (napi_env env,
                      napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaDevice * handle;
  FridaDeviceType return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_device_get_dtype (handle);

  result = fdn_device_type_to_value (env, return_value);

  return result;
}

static napi_value
fdn_device_get_bus (napi_env env,
                    napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaDevice * handle;
  FridaBus * return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_device_get_bus (handle);

  result = fdn_bus_to_value (env, return_value);

  return result;
}

static napi_value
fdn_device_get_provider (napi_env env,
                         napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaDevice * handle;
  FridaHostSessionProvider * return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_device_get_provider (handle);

  result = fdn_host_session_provider_to_value (env, return_value);

  return result;
}

static napi_value
fdn_device_get_manager (napi_env env,
                        napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaDevice * handle;
  FridaDeviceManager * return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_device_get_manager (handle);

  result = fdn_device_manager_to_value (env, return_value);

  return result;
}

static void
fdn_cancellable_register (napi_env env,
                          napi_value exports)
{
  napi_property_descriptor properties[] =
  {
    { "cancel", NULL, fdn_cancellable_cancel, NULL, NULL, NULL, napi_default, NULL },
    { "disconnect", NULL, fdn_cancellable_disconnect, NULL, NULL, NULL, napi_default, NULL },
    { "getFd", NULL, fdn_cancellable_get_fd, NULL, NULL, NULL, napi_default, NULL },
    { "isCancelled", NULL, fdn_cancellable_is_cancelled, NULL, NULL, NULL, napi_default, NULL },
    { "popCurrent", NULL, fdn_cancellable_pop_current, NULL, NULL, NULL, napi_default, NULL },
    { "pushCurrent", NULL, fdn_cancellable_push_current, NULL, NULL, NULL, napi_default, NULL },
    { "reset", NULL, fdn_cancellable_reset, NULL, NULL, NULL, napi_default, NULL },
    { "throwIfCancelled", NULL, fdn_cancellable_throw_if_cancelled, NULL, NULL, NULL, napi_default, NULL },
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
  gulong handler_id;

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
    napi_throw_type_error (env, NULL, "missing argument: handlerId");
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
fdn_cancellable_throw_if_cancelled (napi_env env,
                                    napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  GCancellable * handle;
  GError * error = NULL;
  gboolean return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = g_cancellable_set_error_if_cancelled (handle, &error);

  if (error != NULL)
  {
    napi_throw_error (env, NULL, error->message);
    g_error_free (error);
    return NULL;
  }

  result = fdn_boolean_to_value (env, return_value);

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
fdn_int_from_value (napi_env env,
                    napi_value value,
                    gint * result)
{
  int32_t number;

  if (napi_get_value_int32 (env, value, &number) != napi_ok)
    goto invalid_argument;

  *result = number;
  return TRUE;

invalid_argument:
  {
    napi_throw_error (env, NULL, "expected an integer");
    g_free (result);
    return FALSE;
  }
}

static napi_value
fdn_int_to_value (napi_env env,
                  gint value)
{
  napi_value result;
  napi_create_int32 (env, value, &result);
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

  if (number < 0 || number > G_MAXULONG)
    goto invalid_argument;

  *result = number;
  return TRUE;

invalid_argument:
  {
    napi_throw_error (env, NULL, "expected an unsigned integer");
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
