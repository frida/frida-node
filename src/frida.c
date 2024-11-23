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
  FridaBus * handle;
  GError * error;
  GCancellable * cancellable;
} FdnBusAttachOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaSession * handle;
  GError * error;
  GCancellable * cancellable;
} FdnSessionDetachOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaSession * handle;
  GError * error;
  GCancellable * cancellable;
} FdnSessionResumeOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaSession * handle;
  GError * error;
  GCancellable * cancellable;
} FdnSessionEnableChildGatingOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaSession * handle;
  GError * error;
  GCancellable * cancellable;
} FdnSessionDisableChildGatingOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaSession * handle;
  GError * error;
  gchar * source;
  FridaScriptOptions * options;
  GCancellable * cancellable;
  FridaScript * return_value;
} FdnSessionCreateScriptOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaSession * handle;
  GError * error;
  GBytes * bytes;
  FridaScriptOptions * options;
  GCancellable * cancellable;
  FridaScript * return_value;
} FdnSessionCreateScriptFromBytesOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaSession * handle;
  GError * error;
  gchar * source;
  FridaScriptOptions * options;
  GCancellable * cancellable;
  GBytes * return_value;
} FdnSessionCompileScriptOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaSession * handle;
  GError * error;
  gchar * embed_script;
  FridaSnapshotOptions * options;
  GCancellable * cancellable;
  GBytes * return_value;
} FdnSessionSnapshotScriptOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaSession * handle;
  GError * error;
  FridaPeerOptions * options;
  GCancellable * cancellable;
} FdnSessionSetupPeerConnectionOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaSession * handle;
  GError * error;
  gchar * address;
  FridaPortalOptions * options;
  GCancellable * cancellable;
  FridaPortalMembership * return_value;
} FdnSessionJoinPortalOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaScript * handle;
  GError * error;
  GCancellable * cancellable;
} FdnScriptLoadOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaScript * handle;
  GError * error;
  GCancellable * cancellable;
} FdnScriptUnloadOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaScript * handle;
  GError * error;
  GCancellable * cancellable;
} FdnScriptEternalizeOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaScript * handle;
  GError * error;
  guint16 port;
  GCancellable * cancellable;
} FdnScriptEnableDebuggerOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaScript * handle;
  GError * error;
  GCancellable * cancellable;
} FdnScriptDisableDebuggerOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaPortalMembership * handle;
  GError * error;
  GCancellable * cancellable;
} FdnPortalMembershipTerminateOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaPortalService * handle;
  GError * error;
  GCancellable * cancellable;
} FdnPortalServiceStartOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaPortalService * handle;
  GError * error;
  GCancellable * cancellable;
} FdnPortalServiceStopOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaFileMonitor * handle;
  GError * error;
  GCancellable * cancellable;
} FdnFileMonitorEnableOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaFileMonitor * handle;
  GError * error;
  GCancellable * cancellable;
} FdnFileMonitorDisableOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaCompiler * handle;
  GError * error;
  gchar * entrypoint;
  FridaBuildOptions * options;
  GCancellable * cancellable;
  gchar * return_value;
} FdnCompilerBuildOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaCompiler * handle;
  GError * error;
  gchar * entrypoint;
  FridaWatchOptions * options;
  GCancellable * cancellable;
} FdnCompilerWatchOperation;


static void fdn_device_manager_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_device_manager_from_value (napi_env env, napi_value value, FridaDeviceManager ** result);
G_GNUC_UNUSED static napi_value fdn_device_manager_to_value (napi_env env, FridaDeviceManager * handle);
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

static void fdn_device_list_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_device_list_from_value (napi_env env, napi_value value, FridaDeviceList ** result);
G_GNUC_UNUSED static napi_value fdn_device_list_to_value (napi_env env, FridaDeviceList * handle);
static napi_value fdn_device_list_construct (napi_env env, napi_callback_info info);

static napi_value fdn_device_list_size (napi_env env, napi_callback_info info);

static napi_value fdn_device_list_get (napi_env env, napi_callback_info info);

static void fdn_device_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_device_from_value (napi_env env, napi_value value, FridaDevice ** result);
G_GNUC_UNUSED static napi_value fdn_device_to_value (napi_env env, FridaDevice * handle);
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

static napi_value fdn_device_get_id (napi_env env, napi_callback_info info);

static napi_value fdn_device_get_name (napi_env env, napi_callback_info info);

static napi_value fdn_device_get_icon (napi_env env, napi_callback_info info);

static napi_value fdn_device_get_dtype (napi_env env, napi_callback_info info);

static napi_value fdn_device_get_bus (napi_env env, napi_callback_info info);

static napi_value fdn_device_get_manager (napi_env env, napi_callback_info info);

static void fdn_remote_device_options_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_remote_device_options_from_value (napi_env env, napi_value value, FridaRemoteDeviceOptions ** result);
G_GNUC_UNUSED static napi_value fdn_remote_device_options_to_value (napi_env env, FridaRemoteDeviceOptions * handle);
static napi_value fdn_remote_device_options_construct (napi_env env, napi_callback_info info);

static napi_value fdn_remote_device_options_get_certificate (napi_env env, napi_callback_info info);

static napi_value fdn_remote_device_options_set_certificate (napi_env env, napi_callback_info info);

static napi_value fdn_remote_device_options_get_origin (napi_env env, napi_callback_info info);

static napi_value fdn_remote_device_options_set_origin (napi_env env, napi_callback_info info);

static napi_value fdn_remote_device_options_get_token (napi_env env, napi_callback_info info);

static napi_value fdn_remote_device_options_set_token (napi_env env, napi_callback_info info);

static napi_value fdn_remote_device_options_get_keepalive_interval (napi_env env, napi_callback_info info);

static napi_value fdn_remote_device_options_set_keepalive_interval (napi_env env, napi_callback_info info);

static void fdn_application_list_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_application_list_from_value (napi_env env, napi_value value, FridaApplicationList ** result);
G_GNUC_UNUSED static napi_value fdn_application_list_to_value (napi_env env, FridaApplicationList * handle);
static napi_value fdn_application_list_construct (napi_env env, napi_callback_info info);

static napi_value fdn_application_list_size (napi_env env, napi_callback_info info);

static napi_value fdn_application_list_get (napi_env env, napi_callback_info info);

static void fdn_application_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_application_from_value (napi_env env, napi_value value, FridaApplication ** result);
G_GNUC_UNUSED static napi_value fdn_application_to_value (napi_env env, FridaApplication * handle);
static napi_value fdn_application_construct (napi_env env, napi_callback_info info);

static napi_value fdn_application_get_identifier (napi_env env, napi_callback_info info);

static napi_value fdn_application_get_name (napi_env env, napi_callback_info info);

static napi_value fdn_application_get_pid (napi_env env, napi_callback_info info);

static napi_value fdn_application_get_parameters (napi_env env, napi_callback_info info);

static void fdn_process_list_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_process_list_from_value (napi_env env, napi_value value, FridaProcessList ** result);
G_GNUC_UNUSED static napi_value fdn_process_list_to_value (napi_env env, FridaProcessList * handle);
static napi_value fdn_process_list_construct (napi_env env, napi_callback_info info);

static napi_value fdn_process_list_size (napi_env env, napi_callback_info info);

static napi_value fdn_process_list_get (napi_env env, napi_callback_info info);

static void fdn_process_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_process_from_value (napi_env env, napi_value value, FridaProcess ** result);
G_GNUC_UNUSED static napi_value fdn_process_to_value (napi_env env, FridaProcess * handle);
static napi_value fdn_process_construct (napi_env env, napi_callback_info info);

static napi_value fdn_process_get_pid (napi_env env, napi_callback_info info);

static napi_value fdn_process_get_name (napi_env env, napi_callback_info info);

static napi_value fdn_process_get_parameters (napi_env env, napi_callback_info info);

static void fdn_process_match_options_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_process_match_options_from_value (napi_env env, napi_value value, FridaProcessMatchOptions ** result);
G_GNUC_UNUSED static napi_value fdn_process_match_options_to_value (napi_env env, FridaProcessMatchOptions * handle);
static napi_value fdn_process_match_options_construct (napi_env env, napi_callback_info info);

static napi_value fdn_process_match_options_get_timeout (napi_env env, napi_callback_info info);

static napi_value fdn_process_match_options_set_timeout (napi_env env, napi_callback_info info);

static napi_value fdn_process_match_options_get_scope (napi_env env, napi_callback_info info);

static napi_value fdn_process_match_options_set_scope (napi_env env, napi_callback_info info);

static void fdn_spawn_options_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_spawn_options_from_value (napi_env env, napi_value value, FridaSpawnOptions ** result);
G_GNUC_UNUSED static napi_value fdn_spawn_options_to_value (napi_env env, FridaSpawnOptions * handle);
static napi_value fdn_spawn_options_construct (napi_env env, napi_callback_info info);

static napi_value fdn_spawn_options_get_argv (napi_env env, napi_callback_info info);

static napi_value fdn_spawn_options_set_argv (napi_env env, napi_callback_info info);

static napi_value fdn_spawn_options_get_envp (napi_env env, napi_callback_info info);

static napi_value fdn_spawn_options_set_envp (napi_env env, napi_callback_info info);

static napi_value fdn_spawn_options_get_env (napi_env env, napi_callback_info info);

static napi_value fdn_spawn_options_set_env (napi_env env, napi_callback_info info);

static napi_value fdn_spawn_options_get_cwd (napi_env env, napi_callback_info info);

static napi_value fdn_spawn_options_set_cwd (napi_env env, napi_callback_info info);

static napi_value fdn_spawn_options_get_stdio (napi_env env, napi_callback_info info);

static napi_value fdn_spawn_options_set_stdio (napi_env env, napi_callback_info info);

static napi_value fdn_spawn_options_get_aux (napi_env env, napi_callback_info info);

static napi_value fdn_spawn_options_set_aux (napi_env env, napi_callback_info info);

static void fdn_spawn_list_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_spawn_list_from_value (napi_env env, napi_value value, FridaSpawnList ** result);
G_GNUC_UNUSED static napi_value fdn_spawn_list_to_value (napi_env env, FridaSpawnList * handle);
static napi_value fdn_spawn_list_construct (napi_env env, napi_callback_info info);

static napi_value fdn_spawn_list_size (napi_env env, napi_callback_info info);

static napi_value fdn_spawn_list_get (napi_env env, napi_callback_info info);

static void fdn_spawn_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_spawn_from_value (napi_env env, napi_value value, FridaSpawn ** result);
G_GNUC_UNUSED static napi_value fdn_spawn_to_value (napi_env env, FridaSpawn * handle);
static napi_value fdn_spawn_construct (napi_env env, napi_callback_info info);

static napi_value fdn_spawn_get_pid (napi_env env, napi_callback_info info);

static napi_value fdn_spawn_get_identifier (napi_env env, napi_callback_info info);

static void fdn_child_list_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_child_list_from_value (napi_env env, napi_value value, FridaChildList ** result);
G_GNUC_UNUSED static napi_value fdn_child_list_to_value (napi_env env, FridaChildList * handle);
static napi_value fdn_child_list_construct (napi_env env, napi_callback_info info);

static napi_value fdn_child_list_size (napi_env env, napi_callback_info info);

static napi_value fdn_child_list_get (napi_env env, napi_callback_info info);

static void fdn_child_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_child_from_value (napi_env env, napi_value value, FridaChild ** result);
G_GNUC_UNUSED static napi_value fdn_child_to_value (napi_env env, FridaChild * handle);
static napi_value fdn_child_construct (napi_env env, napi_callback_info info);

static napi_value fdn_child_get_pid (napi_env env, napi_callback_info info);

static napi_value fdn_child_get_parent_pid (napi_env env, napi_callback_info info);

static napi_value fdn_child_get_origin (napi_env env, napi_callback_info info);

static napi_value fdn_child_get_identifier (napi_env env, napi_callback_info info);

static napi_value fdn_child_get_path (napi_env env, napi_callback_info info);

static napi_value fdn_child_get_argv (napi_env env, napi_callback_info info);

static napi_value fdn_child_get_envp (napi_env env, napi_callback_info info);

static void fdn_crash_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_crash_from_value (napi_env env, napi_value value, FridaCrash ** result);
G_GNUC_UNUSED static napi_value fdn_crash_to_value (napi_env env, FridaCrash * handle);
static napi_value fdn_crash_construct (napi_env env, napi_callback_info info);

static napi_value fdn_crash_get_pid (napi_env env, napi_callback_info info);

static napi_value fdn_crash_get_process_name (napi_env env, napi_callback_info info);

static napi_value fdn_crash_get_summary (napi_env env, napi_callback_info info);

static napi_value fdn_crash_get_report (napi_env env, napi_callback_info info);

static napi_value fdn_crash_get_parameters (napi_env env, napi_callback_info info);

static void fdn_bus_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_bus_from_value (napi_env env, napi_value value, FridaBus ** result);
G_GNUC_UNUSED static napi_value fdn_bus_to_value (napi_env env, FridaBus * handle);
static napi_value fdn_bus_construct (napi_env env, napi_callback_info info);

static napi_value fdn_bus_is_detached (napi_env env, napi_callback_info info);

static napi_value fdn_bus_attach (napi_env env, napi_callback_info info);
static gboolean fdn_bus_attach_begin (gpointer user_data);
static void fdn_bus_attach_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void fdn_bus_attach_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void fdn_bus_attach_operation_free (FdnBusAttachOperation * operation);

static napi_value fdn_bus_post (napi_env env, napi_callback_info info);

static napi_value fdn_bus_get_device (napi_env env, napi_callback_info info);

static void fdn_session_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_session_from_value (napi_env env, napi_value value, FridaSession ** result);
G_GNUC_UNUSED static napi_value fdn_session_to_value (napi_env env, FridaSession * handle);
static napi_value fdn_session_construct (napi_env env, napi_callback_info info);

static napi_value fdn_session_is_detached (napi_env env, napi_callback_info info);

static napi_value fdn_session_detach (napi_env env, napi_callback_info info);
static gboolean fdn_session_detach_begin (gpointer user_data);
static void fdn_session_detach_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void fdn_session_detach_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void fdn_session_detach_operation_free (FdnSessionDetachOperation * operation);

static napi_value fdn_session_resume (napi_env env, napi_callback_info info);
static gboolean fdn_session_resume_begin (gpointer user_data);
static void fdn_session_resume_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void fdn_session_resume_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void fdn_session_resume_operation_free (FdnSessionResumeOperation * operation);

static napi_value fdn_session_enable_child_gating (napi_env env, napi_callback_info info);
static gboolean fdn_session_enable_child_gating_begin (gpointer user_data);
static void fdn_session_enable_child_gating_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void fdn_session_enable_child_gating_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void fdn_session_enable_child_gating_operation_free (FdnSessionEnableChildGatingOperation * operation);

static napi_value fdn_session_disable_child_gating (napi_env env, napi_callback_info info);
static gboolean fdn_session_disable_child_gating_begin (gpointer user_data);
static void fdn_session_disable_child_gating_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void fdn_session_disable_child_gating_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void fdn_session_disable_child_gating_operation_free (FdnSessionDisableChildGatingOperation * operation);

static napi_value fdn_session_create_script (napi_env env, napi_callback_info info);
static gboolean fdn_session_create_script_begin (gpointer user_data);
static void fdn_session_create_script_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void fdn_session_create_script_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void fdn_session_create_script_operation_free (FdnSessionCreateScriptOperation * operation);

static napi_value fdn_session_create_script_from_bytes (napi_env env, napi_callback_info info);
static gboolean fdn_session_create_script_from_bytes_begin (gpointer user_data);
static void fdn_session_create_script_from_bytes_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void fdn_session_create_script_from_bytes_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void fdn_session_create_script_from_bytes_operation_free (FdnSessionCreateScriptFromBytesOperation * operation);

static napi_value fdn_session_compile_script (napi_env env, napi_callback_info info);
static gboolean fdn_session_compile_script_begin (gpointer user_data);
static void fdn_session_compile_script_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void fdn_session_compile_script_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void fdn_session_compile_script_operation_free (FdnSessionCompileScriptOperation * operation);

static napi_value fdn_session_snapshot_script (napi_env env, napi_callback_info info);
static gboolean fdn_session_snapshot_script_begin (gpointer user_data);
static void fdn_session_snapshot_script_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void fdn_session_snapshot_script_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void fdn_session_snapshot_script_operation_free (FdnSessionSnapshotScriptOperation * operation);

static napi_value fdn_session_setup_peer_connection (napi_env env, napi_callback_info info);
static gboolean fdn_session_setup_peer_connection_begin (gpointer user_data);
static void fdn_session_setup_peer_connection_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void fdn_session_setup_peer_connection_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void fdn_session_setup_peer_connection_operation_free (FdnSessionSetupPeerConnectionOperation * operation);

static napi_value fdn_session_join_portal (napi_env env, napi_callback_info info);
static gboolean fdn_session_join_portal_begin (gpointer user_data);
static void fdn_session_join_portal_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void fdn_session_join_portal_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void fdn_session_join_portal_operation_free (FdnSessionJoinPortalOperation * operation);

static napi_value fdn_session_get_pid (napi_env env, napi_callback_info info);

static napi_value fdn_session_get_session (napi_env env, napi_callback_info info);

static napi_value fdn_session_get_persist_timeout (napi_env env, napi_callback_info info);

static napi_value fdn_session_get_device (napi_env env, napi_callback_info info);

static void fdn_script_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_script_from_value (napi_env env, napi_value value, FridaScript ** result);
G_GNUC_UNUSED static napi_value fdn_script_to_value (napi_env env, FridaScript * handle);
static napi_value fdn_script_construct (napi_env env, napi_callback_info info);

static napi_value fdn_script_is_destroyed (napi_env env, napi_callback_info info);

static napi_value fdn_script_load (napi_env env, napi_callback_info info);
static gboolean fdn_script_load_begin (gpointer user_data);
static void fdn_script_load_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void fdn_script_load_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void fdn_script_load_operation_free (FdnScriptLoadOperation * operation);

static napi_value fdn_script_unload (napi_env env, napi_callback_info info);
static gboolean fdn_script_unload_begin (gpointer user_data);
static void fdn_script_unload_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void fdn_script_unload_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void fdn_script_unload_operation_free (FdnScriptUnloadOperation * operation);

static napi_value fdn_script_eternalize (napi_env env, napi_callback_info info);
static gboolean fdn_script_eternalize_begin (gpointer user_data);
static void fdn_script_eternalize_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void fdn_script_eternalize_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void fdn_script_eternalize_operation_free (FdnScriptEternalizeOperation * operation);

static napi_value fdn_script_post (napi_env env, napi_callback_info info);

static napi_value fdn_script_enable_debugger (napi_env env, napi_callback_info info);
static gboolean fdn_script_enable_debugger_begin (gpointer user_data);
static void fdn_script_enable_debugger_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void fdn_script_enable_debugger_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void fdn_script_enable_debugger_operation_free (FdnScriptEnableDebuggerOperation * operation);

static napi_value fdn_script_disable_debugger (napi_env env, napi_callback_info info);
static gboolean fdn_script_disable_debugger_begin (gpointer user_data);
static void fdn_script_disable_debugger_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void fdn_script_disable_debugger_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void fdn_script_disable_debugger_operation_free (FdnScriptDisableDebuggerOperation * operation);

static napi_value fdn_script_get_id (napi_env env, napi_callback_info info);

static napi_value fdn_script_get_session (napi_env env, napi_callback_info info);

static void fdn_portal_membership_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_portal_membership_from_value (napi_env env, napi_value value, FridaPortalMembership ** result);
G_GNUC_UNUSED static napi_value fdn_portal_membership_to_value (napi_env env, FridaPortalMembership * handle);
static napi_value fdn_portal_membership_construct (napi_env env, napi_callback_info info);

static napi_value fdn_portal_membership_terminate (napi_env env, napi_callback_info info);
static gboolean fdn_portal_membership_terminate_begin (gpointer user_data);
static void fdn_portal_membership_terminate_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void fdn_portal_membership_terminate_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void fdn_portal_membership_terminate_operation_free (FdnPortalMembershipTerminateOperation * operation);

static napi_value fdn_portal_membership_get_id (napi_env env, napi_callback_info info);

static napi_value fdn_portal_membership_get_session (napi_env env, napi_callback_info info);

static void fdn_control_service_options_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_control_service_options_from_value (napi_env env, napi_value value, FridaControlServiceOptions ** result);
G_GNUC_UNUSED static napi_value fdn_control_service_options_to_value (napi_env env, FridaControlServiceOptions * handle);
static napi_value fdn_control_service_options_construct (napi_env env, napi_callback_info info);

static napi_value fdn_control_service_options_get_sysroot (napi_env env, napi_callback_info info);

static napi_value fdn_control_service_options_set_sysroot (napi_env env, napi_callback_info info);

static napi_value fdn_control_service_options_get_enable_preload (napi_env env, napi_callback_info info);

static napi_value fdn_control_service_options_set_enable_preload (napi_env env, napi_callback_info info);

static napi_value fdn_control_service_options_get_report_crashes (napi_env env, napi_callback_info info);

static napi_value fdn_control_service_options_set_report_crashes (napi_env env, napi_callback_info info);

static void fdn_portal_service_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_portal_service_from_value (napi_env env, napi_value value, FridaPortalService ** result);
G_GNUC_UNUSED static napi_value fdn_portal_service_to_value (napi_env env, FridaPortalService * handle);
static napi_value fdn_portal_service_construct (napi_env env, napi_callback_info info);

static napi_value fdn_portal_service_start (napi_env env, napi_callback_info info);
static gboolean fdn_portal_service_start_begin (gpointer user_data);
static void fdn_portal_service_start_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void fdn_portal_service_start_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void fdn_portal_service_start_operation_free (FdnPortalServiceStartOperation * operation);

static napi_value fdn_portal_service_stop (napi_env env, napi_callback_info info);
static gboolean fdn_portal_service_stop_begin (gpointer user_data);
static void fdn_portal_service_stop_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void fdn_portal_service_stop_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void fdn_portal_service_stop_operation_free (FdnPortalServiceStopOperation * operation);

static napi_value fdn_portal_service_kick (napi_env env, napi_callback_info info);

static napi_value fdn_portal_service_post (napi_env env, napi_callback_info info);

static napi_value fdn_portal_service_narrowcast (napi_env env, napi_callback_info info);

static napi_value fdn_portal_service_broadcast (napi_env env, napi_callback_info info);

static napi_value fdn_portal_service_enumerate_tags (napi_env env, napi_callback_info info);

static napi_value fdn_portal_service_tag (napi_env env, napi_callback_info info);

static napi_value fdn_portal_service_untag (napi_env env, napi_callback_info info);

static napi_value fdn_portal_service_get_device (napi_env env, napi_callback_info info);

static napi_value fdn_portal_service_get_cluster_params (napi_env env, napi_callback_info info);

static napi_value fdn_portal_service_get_control_params (napi_env env, napi_callback_info info);

static void fdn_file_monitor_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_file_monitor_from_value (napi_env env, napi_value value, FridaFileMonitor ** result);
G_GNUC_UNUSED static napi_value fdn_file_monitor_to_value (napi_env env, FridaFileMonitor * handle);
static napi_value fdn_file_monitor_construct (napi_env env, napi_callback_info info);

static napi_value fdn_file_monitor_enable (napi_env env, napi_callback_info info);
static gboolean fdn_file_monitor_enable_begin (gpointer user_data);
static void fdn_file_monitor_enable_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void fdn_file_monitor_enable_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void fdn_file_monitor_enable_operation_free (FdnFileMonitorEnableOperation * operation);

static napi_value fdn_file_monitor_disable (napi_env env, napi_callback_info info);
static gboolean fdn_file_monitor_disable_begin (gpointer user_data);
static void fdn_file_monitor_disable_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void fdn_file_monitor_disable_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void fdn_file_monitor_disable_operation_free (FdnFileMonitorDisableOperation * operation);

static napi_value fdn_file_monitor_get_path (napi_env env, napi_callback_info info);

static void fdn_compiler_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_compiler_from_value (napi_env env, napi_value value, FridaCompiler ** result);
G_GNUC_UNUSED static napi_value fdn_compiler_to_value (napi_env env, FridaCompiler * handle);
static napi_value fdn_compiler_construct (napi_env env, napi_callback_info info);

static napi_value fdn_compiler_build (napi_env env, napi_callback_info info);
static gboolean fdn_compiler_build_begin (gpointer user_data);
static void fdn_compiler_build_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void fdn_compiler_build_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void fdn_compiler_build_operation_free (FdnCompilerBuildOperation * operation);

static napi_value fdn_compiler_watch (napi_env env, napi_callback_info info);
static gboolean fdn_compiler_watch_begin (gpointer user_data);
static void fdn_compiler_watch_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void fdn_compiler_watch_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void fdn_compiler_watch_operation_free (FdnCompilerWatchOperation * operation);

static napi_value fdn_compiler_get_manager (napi_env env, napi_callback_info info);

static void fdn_compiler_options_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_compiler_options_from_value (napi_env env, napi_value value, FridaCompilerOptions ** result);
G_GNUC_UNUSED static napi_value fdn_compiler_options_to_value (napi_env env, FridaCompilerOptions * handle);
static napi_value fdn_compiler_options_construct (napi_env env, napi_callback_info info);

static napi_value fdn_compiler_options_get_project_root (napi_env env, napi_callback_info info);

static napi_value fdn_compiler_options_set_project_root (napi_env env, napi_callback_info info);

static napi_value fdn_compiler_options_get_source_maps (napi_env env, napi_callback_info info);

static napi_value fdn_compiler_options_set_source_maps (napi_env env, napi_callback_info info);

static napi_value fdn_compiler_options_get_compression (napi_env env, napi_callback_info info);

static napi_value fdn_compiler_options_set_compression (napi_env env, napi_callback_info info);

static void fdn_build_options_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_build_options_from_value (napi_env env, napi_value value, FridaBuildOptions ** result);
G_GNUC_UNUSED static napi_value fdn_build_options_to_value (napi_env env, FridaBuildOptions * handle);
static napi_value fdn_build_options_construct (napi_env env, napi_callback_info info);

static void fdn_watch_options_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_watch_options_from_value (napi_env env, napi_value value, FridaWatchOptions ** result);
G_GNUC_UNUSED static napi_value fdn_watch_options_to_value (napi_env env, FridaWatchOptions * handle);
static napi_value fdn_watch_options_construct (napi_env env, napi_callback_info info);

static void fdn_static_authentication_service_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_static_authentication_service_from_value (napi_env env, napi_value value, FridaStaticAuthenticationService ** result);
G_GNUC_UNUSED static napi_value fdn_static_authentication_service_to_value (napi_env env, FridaStaticAuthenticationService * handle);
static napi_value fdn_static_authentication_service_construct (napi_env env, napi_callback_info info);

static napi_value fdn_static_authentication_service_get_token_hash (napi_env env, napi_callback_info info);

static void fdn_frontmost_query_options_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_frontmost_query_options_from_value (napi_env env, napi_value value, FridaFrontmostQueryOptions ** result);
G_GNUC_UNUSED static napi_value fdn_frontmost_query_options_to_value (napi_env env, FridaFrontmostQueryOptions * handle);
static napi_value fdn_frontmost_query_options_construct (napi_env env, napi_callback_info info);

static napi_value fdn_frontmost_query_options_get_scope (napi_env env, napi_callback_info info);

static napi_value fdn_frontmost_query_options_set_scope (napi_env env, napi_callback_info info);

static void fdn_application_query_options_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_application_query_options_from_value (napi_env env, napi_value value, FridaApplicationQueryOptions ** result);
G_GNUC_UNUSED static napi_value fdn_application_query_options_to_value (napi_env env, FridaApplicationQueryOptions * handle);
static napi_value fdn_application_query_options_construct (napi_env env, napi_callback_info info);

static napi_value fdn_application_query_options_select_identifier (napi_env env, napi_callback_info info);

static napi_value fdn_application_query_options_has_selected_identifiers (napi_env env, napi_callback_info info);

static napi_value fdn_application_query_options_get_scope (napi_env env, napi_callback_info info);

static napi_value fdn_application_query_options_set_scope (napi_env env, napi_callback_info info);

static void fdn_process_query_options_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_process_query_options_from_value (napi_env env, napi_value value, FridaProcessQueryOptions ** result);
G_GNUC_UNUSED static napi_value fdn_process_query_options_to_value (napi_env env, FridaProcessQueryOptions * handle);
static napi_value fdn_process_query_options_construct (napi_env env, napi_callback_info info);

static napi_value fdn_process_query_options_select_pid (napi_env env, napi_callback_info info);

static napi_value fdn_process_query_options_has_selected_pids (napi_env env, napi_callback_info info);

static napi_value fdn_process_query_options_get_scope (napi_env env, napi_callback_info info);

static napi_value fdn_process_query_options_set_scope (napi_env env, napi_callback_info info);

static void fdn_session_options_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_session_options_from_value (napi_env env, napi_value value, FridaSessionOptions ** result);
G_GNUC_UNUSED static napi_value fdn_session_options_to_value (napi_env env, FridaSessionOptions * handle);
static napi_value fdn_session_options_construct (napi_env env, napi_callback_info info);

static napi_value fdn_session_options_get_realm (napi_env env, napi_callback_info info);

static napi_value fdn_session_options_set_realm (napi_env env, napi_callback_info info);

static napi_value fdn_session_options_get_persist_timeout (napi_env env, napi_callback_info info);

static napi_value fdn_session_options_set_persist_timeout (napi_env env, napi_callback_info info);

static napi_value fdn_session_options_get_emulated_agent_path (napi_env env, napi_callback_info info);

static napi_value fdn_session_options_set_emulated_agent_path (napi_env env, napi_callback_info info);

static void fdn_script_options_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_script_options_from_value (napi_env env, napi_value value, FridaScriptOptions ** result);
G_GNUC_UNUSED static napi_value fdn_script_options_to_value (napi_env env, FridaScriptOptions * handle);
static napi_value fdn_script_options_construct (napi_env env, napi_callback_info info);

static napi_value fdn_script_options_get_name (napi_env env, napi_callback_info info);

static napi_value fdn_script_options_set_name (napi_env env, napi_callback_info info);

static napi_value fdn_script_options_get_snapshot (napi_env env, napi_callback_info info);

static napi_value fdn_script_options_set_snapshot (napi_env env, napi_callback_info info);

static napi_value fdn_script_options_get_snapshot_transport (napi_env env, napi_callback_info info);

static napi_value fdn_script_options_set_snapshot_transport (napi_env env, napi_callback_info info);

static napi_value fdn_script_options_get_runtime (napi_env env, napi_callback_info info);

static napi_value fdn_script_options_set_runtime (napi_env env, napi_callback_info info);

static void fdn_snapshot_options_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_snapshot_options_from_value (napi_env env, napi_value value, FridaSnapshotOptions ** result);
G_GNUC_UNUSED static napi_value fdn_snapshot_options_to_value (napi_env env, FridaSnapshotOptions * handle);
static napi_value fdn_snapshot_options_construct (napi_env env, napi_callback_info info);

static napi_value fdn_snapshot_options_get_warmup_script (napi_env env, napi_callback_info info);

static napi_value fdn_snapshot_options_set_warmup_script (napi_env env, napi_callback_info info);

static napi_value fdn_snapshot_options_get_runtime (napi_env env, napi_callback_info info);

static napi_value fdn_snapshot_options_set_runtime (napi_env env, napi_callback_info info);

static void fdn_portal_options_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_portal_options_from_value (napi_env env, napi_value value, FridaPortalOptions ** result);
G_GNUC_UNUSED static napi_value fdn_portal_options_to_value (napi_env env, FridaPortalOptions * handle);
static napi_value fdn_portal_options_construct (napi_env env, napi_callback_info info);

static napi_value fdn_portal_options_get_certificate (napi_env env, napi_callback_info info);

static napi_value fdn_portal_options_set_certificate (napi_env env, napi_callback_info info);

static napi_value fdn_portal_options_get_token (napi_env env, napi_callback_info info);

static napi_value fdn_portal_options_set_token (napi_env env, napi_callback_info info);

static napi_value fdn_portal_options_get_acl (napi_env env, napi_callback_info info);

static napi_value fdn_portal_options_set_acl (napi_env env, napi_callback_info info);

static void fdn_peer_options_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_peer_options_from_value (napi_env env, napi_value value, FridaPeerOptions ** result);
G_GNUC_UNUSED static napi_value fdn_peer_options_to_value (napi_env env, FridaPeerOptions * handle);
static napi_value fdn_peer_options_construct (napi_env env, napi_callback_info info);

static napi_value fdn_peer_options_clear_relays (napi_env env, napi_callback_info info);

static napi_value fdn_peer_options_add_relay (napi_env env, napi_callback_info info);

static napi_value fdn_peer_options_get_stun_server (napi_env env, napi_callback_info info);

static napi_value fdn_peer_options_set_stun_server (napi_env env, napi_callback_info info);

static void fdn_relay_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_relay_from_value (napi_env env, napi_value value, FridaRelay ** result);
G_GNUC_UNUSED static napi_value fdn_relay_to_value (napi_env env, FridaRelay * handle);
static napi_value fdn_relay_construct (napi_env env, napi_callback_info info);

static napi_value fdn_relay_get_address (napi_env env, napi_callback_info info);

static napi_value fdn_relay_get_username (napi_env env, napi_callback_info info);

static napi_value fdn_relay_get_password (napi_env env, napi_callback_info info);

static napi_value fdn_relay_get_kind (napi_env env, napi_callback_info info);

static void fdn_endpoint_parameters_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_endpoint_parameters_from_value (napi_env env, napi_value value, FridaEndpointParameters ** result);
G_GNUC_UNUSED static napi_value fdn_endpoint_parameters_to_value (napi_env env, FridaEndpointParameters * handle);
static napi_value fdn_endpoint_parameters_construct (napi_env env, napi_callback_info info);

static napi_value fdn_endpoint_parameters_get_address (napi_env env, napi_callback_info info);

static napi_value fdn_endpoint_parameters_get_port (napi_env env, napi_callback_info info);

static napi_value fdn_endpoint_parameters_get_certificate (napi_env env, napi_callback_info info);

static napi_value fdn_endpoint_parameters_get_origin (napi_env env, napi_callback_info info);

static napi_value fdn_endpoint_parameters_get_auth_service (napi_env env, napi_callback_info info);

static napi_value fdn_endpoint_parameters_get_asset_root (napi_env env, napi_callback_info info);

static napi_value fdn_endpoint_parameters_set_asset_root (napi_env env, napi_callback_info info);

static void fdn_cancellable_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_cancellable_from_value (napi_env env, napi_value value, GCancellable ** result);
G_GNUC_UNUSED static napi_value fdn_cancellable_to_value (napi_env env, GCancellable * handle);
static napi_value fdn_cancellable_construct (napi_env env, napi_callback_info info);

static napi_value fdn_cancellable_cancel (napi_env env, napi_callback_info info);

static napi_value fdn_cancellable_disconnect (napi_env env, napi_callback_info info);

static napi_value fdn_cancellable_get_fd (napi_env env, napi_callback_info info);

static napi_value fdn_cancellable_is_cancelled (napi_env env, napi_callback_info info);

static napi_value fdn_cancellable_pop_current (napi_env env, napi_callback_info info);

static napi_value fdn_cancellable_push_current (napi_env env, napi_callback_info info);

static napi_value fdn_cancellable_reset (napi_env env, napi_callback_info info);

static napi_value fdn_cancellable_throw_if_cancelled (napi_env env, napi_callback_info info);

G_GNUC_UNUSED static gboolean fdn_runtime_from_value (napi_env env, napi_value value, FridaRuntime * result);
G_GNUC_UNUSED static napi_value fdn_runtime_to_value (napi_env env, FridaRuntime value);

G_GNUC_UNUSED static gboolean fdn_device_type_from_value (napi_env env, napi_value value, FridaDeviceType * result);
G_GNUC_UNUSED static napi_value fdn_device_type_to_value (napi_env env, FridaDeviceType value);

G_GNUC_UNUSED static gboolean fdn_source_maps_from_value (napi_env env, napi_value value, FridaSourceMaps * result);
G_GNUC_UNUSED static napi_value fdn_source_maps_to_value (napi_env env, FridaSourceMaps value);

G_GNUC_UNUSED static gboolean fdn_js_compression_from_value (napi_env env, napi_value value, FridaJsCompression * result);
G_GNUC_UNUSED static napi_value fdn_js_compression_to_value (napi_env env, FridaJsCompression value);

G_GNUC_UNUSED static gboolean fdn_agent_message_kind_from_value (napi_env env, napi_value value, FridaAgentMessageKind * result);
G_GNUC_UNUSED static napi_value fdn_agent_message_kind_to_value (napi_env env, FridaAgentMessageKind value);

G_GNUC_UNUSED static gboolean fdn_realm_from_value (napi_env env, napi_value value, FridaRealm * result);
G_GNUC_UNUSED static napi_value fdn_realm_to_value (napi_env env, FridaRealm value);

G_GNUC_UNUSED static gboolean fdn_unload_policy_from_value (napi_env env, napi_value value, FridaUnloadPolicy * result);
G_GNUC_UNUSED static napi_value fdn_unload_policy_to_value (napi_env env, FridaUnloadPolicy value);

G_GNUC_UNUSED static gboolean fdn_session_detach_reason_from_value (napi_env env, napi_value value, FridaSessionDetachReason * result);
G_GNUC_UNUSED static napi_value fdn_session_detach_reason_to_value (napi_env env, FridaSessionDetachReason value);

G_GNUC_UNUSED static gboolean fdn_scope_from_value (napi_env env, napi_value value, FridaScope * result);
G_GNUC_UNUSED static napi_value fdn_scope_to_value (napi_env env, FridaScope value);

G_GNUC_UNUSED static gboolean fdn_stdio_from_value (napi_env env, napi_value value, FridaStdio * result);
G_GNUC_UNUSED static napi_value fdn_stdio_to_value (napi_env env, FridaStdio value);

G_GNUC_UNUSED static gboolean fdn_child_origin_from_value (napi_env env, napi_value value, FridaChildOrigin * result);
G_GNUC_UNUSED static napi_value fdn_child_origin_to_value (napi_env env, FridaChildOrigin value);

G_GNUC_UNUSED static gboolean fdn_snapshot_transport_from_value (napi_env env, napi_value value, FridaSnapshotTransport * result);
G_GNUC_UNUSED static napi_value fdn_snapshot_transport_to_value (napi_env env, FridaSnapshotTransport value);

G_GNUC_UNUSED static gboolean fdn_script_runtime_from_value (napi_env env, napi_value value, FridaScriptRuntime * result);
G_GNUC_UNUSED static napi_value fdn_script_runtime_to_value (napi_env env, FridaScriptRuntime value);

G_GNUC_UNUSED static gboolean fdn_relay_kind_from_value (napi_env env, napi_value value, FridaRelayKind * result);
G_GNUC_UNUSED static napi_value fdn_relay_kind_to_value (napi_env env, FridaRelayKind value);

G_GNUC_UNUSED static gboolean fdn_peer_setup_from_value (napi_env env, napi_value value, FridaPeerSetup * result);
G_GNUC_UNUSED static napi_value fdn_peer_setup_to_value (napi_env env, FridaPeerSetup value);

G_GNUC_UNUSED static gboolean fdn_web_service_transport_from_value (napi_env env, napi_value value, FridaWebServiceTransport * result);
G_GNUC_UNUSED static napi_value fdn_web_service_transport_to_value (napi_env env, FridaWebServiceTransport value);

G_GNUC_UNUSED static gboolean fdn_web_service_flavor_from_value (napi_env env, napi_value value, FridaWebServiceFlavor * result);
G_GNUC_UNUSED static napi_value fdn_web_service_flavor_to_value (napi_env env, FridaWebServiceFlavor value);

G_GNUC_UNUSED static gboolean fdn_port_conflict_behavior_from_value (napi_env env, napi_value value, FridaPortConflictBehavior * result);
G_GNUC_UNUSED static napi_value fdn_port_conflict_behavior_to_value (napi_env env, FridaPortConflictBehavior value);

G_GNUC_UNUSED static gboolean fdn_string_terminator_from_value (napi_env env, napi_value value, FridaStringTerminator * result);
G_GNUC_UNUSED static napi_value fdn_string_terminator_to_value (napi_env env, FridaStringTerminator value);

static napi_value fdn_boolean_to_value (napi_env env, gboolean value);
static gboolean fdn_int_from_value (napi_env env, napi_value value, gint * result);
static napi_value fdn_int_to_value (napi_env env, gint value);
static gboolean fdn_uint_from_value (napi_env env, napi_value value, guint * result);
static napi_value fdn_uint_to_value (napi_env env, guint value);
static gboolean fdn_ulong_from_value (napi_env env, napi_value value, gulong * result);
static gboolean fdn_utf8_from_value (napi_env env, napi_value value, gchar ** str);
static napi_value fdn_utf8_to_value (napi_env env, const gchar * str);
static gboolean fdn_enum_from_value (napi_env env, GType enum_type, napi_value value, gint * result);
static napi_value fdn_enum_to_value (napi_env env, GType enum_type, gint value);

static napi_type_tag fdn_device_manager_type_tag = { 0x05f6bfbbd4aa4537, 0x8d1583d2acbdaef8 };
static napi_type_tag fdn_device_list_type_tag = { 0x27f15837384944ec, 0x84a128e5d77ab93c };
static napi_type_tag fdn_device_type_tag = { 0xe58dd9a80d3e4ce1, 0x8a8beeb08528ae31 };
static napi_type_tag fdn_remote_device_options_type_tag = { 0xf8557922de3d4ccf, 0x9ad91b41dd0af865 };
static napi_type_tag fdn_application_list_type_tag = { 0x18411c8353ac470e, 0x8e1f4b297c317dd0 };
static napi_type_tag fdn_application_type_tag = { 0x919f44a5bc7c47f4, 0x90d839ccfbc8b8fb };
static napi_type_tag fdn_process_list_type_tag = { 0x49fee2ad1ff04c0a, 0xbdc1b35727c60733 };
static napi_type_tag fdn_process_type_tag = { 0x511ce7eb1dbd4fe8, 0xb04a5b211a9b4ff5 };
static napi_type_tag fdn_process_match_options_type_tag = { 0x7f42da2851d34fd6, 0x81d69bb61bd17e77 };
static napi_type_tag fdn_spawn_options_type_tag = { 0x3d07276db4244f38, 0xadd92c428c0266c9 };
static napi_type_tag fdn_spawn_list_type_tag = { 0xaefff959485a4ae2, 0xad98a0774eb347a4 };
static napi_type_tag fdn_spawn_type_tag = { 0xcf2a6d4a365d4e5a, 0x82df59cc4453b387 };
static napi_type_tag fdn_child_list_type_tag = { 0xb50a4a24f87d4c5f, 0xbcb5700430da0d91 };
static napi_type_tag fdn_child_type_tag = { 0xe858cbb88ba84cdb, 0xae0ab388ccc4a72d };
static napi_type_tag fdn_crash_type_tag = { 0x6265dac6465e4725, 0x817cc5d4acac4ce0 };
static napi_type_tag fdn_bus_type_tag = { 0x8d86c6b59024422b, 0x9c01cdbf16449dda };
static napi_type_tag fdn_session_type_tag = { 0x0fb915770e4945a4, 0xbe2c47191a1aa633 };
static napi_type_tag fdn_script_type_tag = { 0xd6fcfe99dbd6421e, 0xa9fdf80461132675 };
static napi_type_tag fdn_portal_membership_type_tag = { 0x44f104191fd74966, 0x9714a3a01bda89a3 };
static napi_type_tag fdn_control_service_options_type_tag = { 0x3b4fdc31b14c409b, 0xa7b73e1c68a3ee82 };
static napi_type_tag fdn_portal_service_type_tag = { 0xd5ef2bb845214aad, 0xa3b5b633d818cd23 };
static napi_type_tag fdn_file_monitor_type_tag = { 0x4ede99185b1f48e0, 0xad1a768c1fe0a0f3 };
static napi_type_tag fdn_compiler_type_tag = { 0x956c552fd9fd47ff, 0x82f7acbc316380f1 };
static napi_type_tag fdn_compiler_options_type_tag = { 0x428592c3b5ef4c5f, 0xb68a1e1d530ab28a };
static napi_type_tag fdn_build_options_type_tag = { 0xbb188399e6b54400, 0x90ccac36d4c282eb };
static napi_type_tag fdn_watch_options_type_tag = { 0xcf6b0f704f2347de, 0x86d777fadc7612fb };
static napi_type_tag fdn_static_authentication_service_type_tag = { 0x465f3df715e54b6e, 0xa6e6df2a25eb9766 };
static napi_type_tag fdn_frontmost_query_options_type_tag = { 0x7089cb96cf2b412c, 0xae3478e64ea9d0a5 };
static napi_type_tag fdn_application_query_options_type_tag = { 0xe99971ae56fa40f2, 0x828dc4dba4e49c5f };
static napi_type_tag fdn_process_query_options_type_tag = { 0x6f0c31f85021491c, 0x9f5a953864fc2d48 };
static napi_type_tag fdn_session_options_type_tag = { 0xe5abf2819cf040dd, 0x9451e8082d9f9426 };
static napi_type_tag fdn_script_options_type_tag = { 0x8ab470a6828745ca, 0x9947b401e2f429af };
static napi_type_tag fdn_snapshot_options_type_tag = { 0xf29cc1e3abdb48a6, 0xb45377d26ae79c92 };
static napi_type_tag fdn_portal_options_type_tag = { 0xccca43cce0ba4850, 0x95be8669d3c23539 };
static napi_type_tag fdn_peer_options_type_tag = { 0x0588fb6688c64a6b, 0x9117979325c56c76 };
static napi_type_tag fdn_relay_type_tag = { 0x192f0d235c2847a8, 0x8af9a4448a0f03e8 };
static napi_type_tag fdn_endpoint_parameters_type_tag = { 0xa17f4922e21e4b4d, 0x9478e0edad32d40e };
static napi_type_tag fdn_cancellable_type_tag = { 0xbe112c9314654150, 0xb8adb254b31808e1 };

static napi_ref fdn_device_manager_constructor;
static napi_ref fdn_device_list_constructor;
static napi_ref fdn_device_constructor;
static napi_ref fdn_remote_device_options_constructor;
static napi_ref fdn_application_list_constructor;
static napi_ref fdn_application_constructor;
static napi_ref fdn_process_list_constructor;
static napi_ref fdn_process_constructor;
static napi_ref fdn_process_match_options_constructor;
static napi_ref fdn_spawn_options_constructor;
static napi_ref fdn_spawn_list_constructor;
static napi_ref fdn_spawn_constructor;
static napi_ref fdn_child_list_constructor;
static napi_ref fdn_child_constructor;
static napi_ref fdn_crash_constructor;
static napi_ref fdn_bus_constructor;
static napi_ref fdn_session_constructor;
static napi_ref fdn_script_constructor;
static napi_ref fdn_portal_membership_constructor;
static napi_ref fdn_control_service_options_constructor;
static napi_ref fdn_portal_service_constructor;
static napi_ref fdn_file_monitor_constructor;
static napi_ref fdn_compiler_constructor;
static napi_ref fdn_compiler_options_constructor;
static napi_ref fdn_build_options_constructor;
static napi_ref fdn_watch_options_constructor;
static napi_ref fdn_static_authentication_service_constructor;
static napi_ref fdn_frontmost_query_options_constructor;
static napi_ref fdn_application_query_options_constructor;
static napi_ref fdn_process_query_options_constructor;
static napi_ref fdn_session_options_constructor;
static napi_ref fdn_script_options_constructor;
static napi_ref fdn_snapshot_options_constructor;
static napi_ref fdn_portal_options_constructor;
static napi_ref fdn_peer_options_constructor;
static napi_ref fdn_relay_constructor;
static napi_ref fdn_endpoint_parameters_constructor;
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

static napi_threadsafe_function fdn_bus_attach_tsfn;

static napi_threadsafe_function fdn_session_detach_tsfn;
static napi_threadsafe_function fdn_session_resume_tsfn;
static napi_threadsafe_function fdn_session_enable_child_gating_tsfn;
static napi_threadsafe_function fdn_session_disable_child_gating_tsfn;
static napi_threadsafe_function fdn_session_create_script_tsfn;
static napi_threadsafe_function fdn_session_create_script_from_bytes_tsfn;
static napi_threadsafe_function fdn_session_compile_script_tsfn;
static napi_threadsafe_function fdn_session_snapshot_script_tsfn;
static napi_threadsafe_function fdn_session_setup_peer_connection_tsfn;
static napi_threadsafe_function fdn_session_join_portal_tsfn;

static napi_threadsafe_function fdn_script_load_tsfn;
static napi_threadsafe_function fdn_script_unload_tsfn;
static napi_threadsafe_function fdn_script_eternalize_tsfn;
static napi_threadsafe_function fdn_script_enable_debugger_tsfn;
static napi_threadsafe_function fdn_script_disable_debugger_tsfn;

static napi_threadsafe_function fdn_portal_membership_terminate_tsfn;

static napi_threadsafe_function fdn_portal_service_start_tsfn;
static napi_threadsafe_function fdn_portal_service_stop_tsfn;

static napi_threadsafe_function fdn_file_monitor_enable_tsfn;
static napi_threadsafe_function fdn_file_monitor_disable_tsfn;

static napi_threadsafe_function fdn_compiler_build_tsfn;
static napi_threadsafe_function fdn_compiler_watch_tsfn;

static napi_value
Init (napi_env env,
      napi_value exports)
{
  fdn_device_manager_register (env, exports);
  fdn_device_list_register (env, exports);
  fdn_device_register (env, exports);
  fdn_remote_device_options_register (env, exports);
  fdn_application_list_register (env, exports);
  fdn_application_register (env, exports);
  fdn_process_list_register (env, exports);
  fdn_process_register (env, exports);
  fdn_process_match_options_register (env, exports);
  fdn_spawn_options_register (env, exports);
  fdn_spawn_list_register (env, exports);
  fdn_spawn_register (env, exports);
  fdn_child_list_register (env, exports);
  fdn_child_register (env, exports);
  fdn_crash_register (env, exports);
  fdn_bus_register (env, exports);
  fdn_session_register (env, exports);
  fdn_script_register (env, exports);
  fdn_portal_membership_register (env, exports);
  fdn_control_service_options_register (env, exports);
  fdn_portal_service_register (env, exports);
  fdn_file_monitor_register (env, exports);
  fdn_compiler_register (env, exports);
  fdn_compiler_options_register (env, exports);
  fdn_build_options_register (env, exports);
  fdn_watch_options_register (env, exports);
  fdn_static_authentication_service_register (env, exports);
  fdn_frontmost_query_options_register (env, exports);
  fdn_application_query_options_register (env, exports);
  fdn_process_query_options_register (env, exports);
  fdn_session_options_register (env, exports);
  fdn_script_options_register (env, exports);
  fdn_snapshot_options_register (env, exports);
  fdn_portal_options_register (env, exports);
  fdn_peer_options_register (env, exports);
  fdn_relay_register (env, exports);
  fdn_endpoint_parameters_register (env, exports);
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
fdn_device_list_register (napi_env env,
                          napi_value exports)
{
  napi_property_descriptor properties[] =
  {
    { "size", NULL, fdn_device_list_size, NULL, NULL, NULL, napi_default, NULL },
    { "get", NULL, fdn_device_list_get, NULL, NULL, NULL, napi_default, NULL },
  };

  napi_value constructor;
  napi_define_class (env, "DeviceList", NAPI_AUTO_LENGTH, fdn_device_list_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_device_list_constructor);

  napi_set_named_property (env, exports, "DeviceList", constructor);
}

static gboolean
fdn_device_list_from_value (napi_env env,
                            napi_value value,
                            FridaDeviceList ** result)
{
  napi_status status;
  bool is_instance;
  FridaDeviceList * handle;

  status = napi_check_object_type_tag (env, value, &fdn_device_list_type_tag, &is_instance);
  if (status != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of DeviceList");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) &handle);

  g_object_ref (handle);
  *result = handle;

  return TRUE;
}

static napi_value
fdn_device_list_to_value (napi_env env,
                          FridaDeviceList * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_device_list_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_device_list_construct (napi_env env,
                           napi_callback_info info)
{
  napi_throw_error (env, NULL, "class DeviceList cannot be constructed because it lacks a default constructor");
  return NULL;
}

static napi_value
fdn_device_list_size (napi_env env,
                      napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaDeviceList * handle;
  gint return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_device_list_size (handle);

  result = fdn_int_to_value (env, return_value);

  return result;
}

static napi_value
fdn_device_list_get (napi_env env,
                     napi_callback_info info)
{
  napi_value result;
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaDeviceList * handle;
  gint index;
  FridaDevice * return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  if (argc > 0)
  {
    if (!fdn_int_from_value (env, args[0], &index))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: index");
    goto invalid_argument;
  }

  return_value = frida_device_list_get (handle, index);

  result = fdn_device_to_value (env, return_value);

  return result;

invalid_argument:
  {
    return NULL;
  }
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
    { "getId", NULL, fdn_device_get_id, NULL, NULL, NULL, napi_default, NULL },
    { "getName", NULL, fdn_device_get_name, NULL, NULL, NULL, napi_default, NULL },
    { "getIcon", NULL, fdn_device_get_icon, NULL, NULL, NULL, napi_default, NULL },
    { "getDtype", NULL, fdn_device_get_dtype, NULL, NULL, NULL, napi_default, NULL },
    { "getBus", NULL, fdn_device_get_bus, NULL, NULL, NULL, napi_default, NULL },
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
fdn_remote_device_options_register (napi_env env,
                                    napi_value exports)
{
  napi_property_descriptor properties[] =
  {
    { "getCertificate", NULL, fdn_remote_device_options_get_certificate, NULL, NULL, NULL, napi_default, NULL },
    { "setCertificate", NULL, fdn_remote_device_options_set_certificate, NULL, NULL, NULL, napi_default, NULL },
    { "getOrigin", NULL, fdn_remote_device_options_get_origin, NULL, NULL, NULL, napi_default, NULL },
    { "setOrigin", NULL, fdn_remote_device_options_set_origin, NULL, NULL, NULL, napi_default, NULL },
    { "getToken", NULL, fdn_remote_device_options_get_token, NULL, NULL, NULL, napi_default, NULL },
    { "setToken", NULL, fdn_remote_device_options_set_token, NULL, NULL, NULL, napi_default, NULL },
    { "getKeepaliveInterval", NULL, fdn_remote_device_options_get_keepalive_interval, NULL, NULL, NULL, napi_default, NULL },
    { "setKeepaliveInterval", NULL, fdn_remote_device_options_set_keepalive_interval, NULL, NULL, NULL, napi_default, NULL },
  };

  napi_value constructor;
  napi_define_class (env, "RemoteDeviceOptions", NAPI_AUTO_LENGTH, fdn_remote_device_options_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_remote_device_options_constructor);

  napi_set_named_property (env, exports, "RemoteDeviceOptions", constructor);
}

static gboolean
fdn_remote_device_options_from_value (napi_env env,
                                      napi_value value,
                                      FridaRemoteDeviceOptions ** result)
{
  napi_status status;
  bool is_instance;
  FridaRemoteDeviceOptions * handle;

  status = napi_check_object_type_tag (env, value, &fdn_remote_device_options_type_tag, &is_instance);
  if (status != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of RemoteDeviceOptions");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) &handle);

  g_object_ref (handle);
  *result = handle;

  return TRUE;
}

static napi_value
fdn_remote_device_options_to_value (napi_env env,
                                    FridaRemoteDeviceOptions * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_remote_device_options_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_remote_device_options_construct (napi_env env,
                                     napi_callback_info info)
{
  size_t argc = 0;
  napi_value jsthis;
  napi_status status;
  FridaRemoteDeviceOptions * handle;

  status = napi_get_cb_info (env, info, &argc, NULL, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  handle = frida_remote_device_options_new ();

  status = napi_type_tag_object (env, jsthis, &fdn_remote_device_options_type_tag);
  if (status != napi_ok)
    return NULL;

  status = napi_wrap (env, jsthis, handle, NULL, NULL, NULL);
  if (status != napi_ok)
    return NULL;

  return jsthis;
}

static napi_value
fdn_remote_device_options_get_certificate (napi_env env,
                                           napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaRemoteDeviceOptions * handle;
  GTlsCertificate * return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_remote_device_options_get_certificate (handle);

  result = fdn_tls_certificate_to_value (env, return_value);

  return result;
}

static napi_value
fdn_remote_device_options_set_certificate (napi_env env,
                                           napi_callback_info info)
{
  napi_value result;
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaRemoteDeviceOptions * handle;
  GTlsCertificate * value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  if (argc > 0)
  {
    if (!fdn_tls_certificate_from_value (env, args[0], &value))
      goto invalid_argument;
  }
  else
  {
    value = NULL;
  }

  frida_remote_device_options_set_certificate (handle, value);

  napi_get_undefined (env, &result);

  return result;

invalid_argument:
  {
    return NULL;
  }
}

static napi_value
fdn_remote_device_options_get_origin (napi_env env,
                                      napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaRemoteDeviceOptions * handle;
  gchar * return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_remote_device_options_get_origin (handle);

  result = fdn_utf8_to_value (env, return_value);

  return result;
}

static napi_value
fdn_remote_device_options_set_origin (napi_env env,
                                      napi_callback_info info)
{
  napi_value result;
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaRemoteDeviceOptions * handle;
  gchar * value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  if (argc > 0)
  {
    if (!fdn_utf8_from_value (env, args[0], &value))
      goto invalid_argument;
  }
  else
  {
    value = NULL;
  }

  frida_remote_device_options_set_origin (handle, value);

  
  g_free (operation->value);napi_get_undefined (env, &result);

  return result;

invalid_argument:
  {
    
  g_free (operation->value);return NULL;
  }
}

static napi_value
fdn_remote_device_options_get_token (napi_env env,
                                     napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaRemoteDeviceOptions * handle;
  gchar * return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_remote_device_options_get_token (handle);

  result = fdn_utf8_to_value (env, return_value);

  return result;
}

static napi_value
fdn_remote_device_options_set_token (napi_env env,
                                     napi_callback_info info)
{
  napi_value result;
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaRemoteDeviceOptions * handle;
  gchar * value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  if (argc > 0)
  {
    if (!fdn_utf8_from_value (env, args[0], &value))
      goto invalid_argument;
  }
  else
  {
    value = NULL;
  }

  frida_remote_device_options_set_token (handle, value);

  
  g_free (operation->value);napi_get_undefined (env, &result);

  return result;

invalid_argument:
  {
    
  g_free (operation->value);return NULL;
  }
}

static napi_value
fdn_remote_device_options_get_keepalive_interval (napi_env env,
                                                  napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaRemoteDeviceOptions * handle;
  gint return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_remote_device_options_get_keepalive_interval (handle);

  result = fdn_int_to_value (env, return_value);

  return result;
}

static napi_value
fdn_remote_device_options_set_keepalive_interval (napi_env env,
                                                  napi_callback_info info)
{
  napi_value result;
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaRemoteDeviceOptions * handle;
  gint value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  if (argc > 0)
  {
    if (!fdn_int_from_value (env, args[0], &value))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: value");
    goto invalid_argument;
  }

  frida_remote_device_options_set_keepalive_interval (handle, value);

  napi_get_undefined (env, &result);

  return result;

invalid_argument:
  {
    return NULL;
  }
}

static void
fdn_application_list_register (napi_env env,
                               napi_value exports)
{
  napi_property_descriptor properties[] =
  {
    { "size", NULL, fdn_application_list_size, NULL, NULL, NULL, napi_default, NULL },
    { "get", NULL, fdn_application_list_get, NULL, NULL, NULL, napi_default, NULL },
  };

  napi_value constructor;
  napi_define_class (env, "ApplicationList", NAPI_AUTO_LENGTH, fdn_application_list_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_application_list_constructor);

  napi_set_named_property (env, exports, "ApplicationList", constructor);
}

static gboolean
fdn_application_list_from_value (napi_env env,
                                 napi_value value,
                                 FridaApplicationList ** result)
{
  napi_status status;
  bool is_instance;
  FridaApplicationList * handle;

  status = napi_check_object_type_tag (env, value, &fdn_application_list_type_tag, &is_instance);
  if (status != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of ApplicationList");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) &handle);

  g_object_ref (handle);
  *result = handle;

  return TRUE;
}

static napi_value
fdn_application_list_to_value (napi_env env,
                               FridaApplicationList * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_application_list_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_application_list_construct (napi_env env,
                                napi_callback_info info)
{
  napi_throw_error (env, NULL, "class ApplicationList cannot be constructed because it lacks a default constructor");
  return NULL;
}

static napi_value
fdn_application_list_size (napi_env env,
                           napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaApplicationList * handle;
  gint return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_application_list_size (handle);

  result = fdn_int_to_value (env, return_value);

  return result;
}

static napi_value
fdn_application_list_get (napi_env env,
                          napi_callback_info info)
{
  napi_value result;
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaApplicationList * handle;
  gint index;
  FridaApplication * return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  if (argc > 0)
  {
    if (!fdn_int_from_value (env, args[0], &index))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: index");
    goto invalid_argument;
  }

  return_value = frida_application_list_get (handle, index);

  result = fdn_application_to_value (env, return_value);

  return result;

invalid_argument:
  {
    return NULL;
  }
}

static void
fdn_application_register (napi_env env,
                          napi_value exports)
{
  napi_property_descriptor properties[] =
  {
    { "getIdentifier", NULL, fdn_application_get_identifier, NULL, NULL, NULL, napi_default, NULL },
    { "getName", NULL, fdn_application_get_name, NULL, NULL, NULL, napi_default, NULL },
    { "getPid", NULL, fdn_application_get_pid, NULL, NULL, NULL, napi_default, NULL },
    { "getParameters", NULL, fdn_application_get_parameters, NULL, NULL, NULL, napi_default, NULL },
  };

  napi_value constructor;
  napi_define_class (env, "Application", NAPI_AUTO_LENGTH, fdn_application_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_application_constructor);

  napi_set_named_property (env, exports, "Application", constructor);
}

static gboolean
fdn_application_from_value (napi_env env,
                            napi_value value,
                            FridaApplication ** result)
{
  napi_status status;
  bool is_instance;
  FridaApplication * handle;

  status = napi_check_object_type_tag (env, value, &fdn_application_type_tag, &is_instance);
  if (status != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of Application");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) &handle);

  g_object_ref (handle);
  *result = handle;

  return TRUE;
}

static napi_value
fdn_application_to_value (napi_env env,
                          FridaApplication * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_application_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_application_construct (napi_env env,
                           napi_callback_info info)
{
  napi_throw_error (env, NULL, "class Application cannot be constructed because it lacks a default constructor");
  return NULL;
}

static napi_value
fdn_application_get_identifier (napi_env env,
                                napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaApplication * handle;
  gchar * return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_application_get_identifier (handle);

  result = fdn_utf8_to_value (env, return_value);

  return result;
}

static napi_value
fdn_application_get_name (napi_env env,
                          napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaApplication * handle;
  gchar * return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_application_get_name (handle);

  result = fdn_utf8_to_value (env, return_value);

  return result;
}

static napi_value
fdn_application_get_pid (napi_env env,
                         napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaApplication * handle;
  guint return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_application_get_pid (handle);

  result = fdn_uint_to_value (env, return_value);

  return result;
}

static napi_value
fdn_application_get_parameters (napi_env env,
                                napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaApplication * handle;
  GHashTable * return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_application_get_parameters (handle);

  result = fdn_hash_table_to_value (env, return_value);

  return result;
}

static void
fdn_process_list_register (napi_env env,
                           napi_value exports)
{
  napi_property_descriptor properties[] =
  {
    { "size", NULL, fdn_process_list_size, NULL, NULL, NULL, napi_default, NULL },
    { "get", NULL, fdn_process_list_get, NULL, NULL, NULL, napi_default, NULL },
  };

  napi_value constructor;
  napi_define_class (env, "ProcessList", NAPI_AUTO_LENGTH, fdn_process_list_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_process_list_constructor);

  napi_set_named_property (env, exports, "ProcessList", constructor);
}

static gboolean
fdn_process_list_from_value (napi_env env,
                             napi_value value,
                             FridaProcessList ** result)
{
  napi_status status;
  bool is_instance;
  FridaProcessList * handle;

  status = napi_check_object_type_tag (env, value, &fdn_process_list_type_tag, &is_instance);
  if (status != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of ProcessList");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) &handle);

  g_object_ref (handle);
  *result = handle;

  return TRUE;
}

static napi_value
fdn_process_list_to_value (napi_env env,
                           FridaProcessList * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_process_list_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_process_list_construct (napi_env env,
                            napi_callback_info info)
{
  napi_throw_error (env, NULL, "class ProcessList cannot be constructed because it lacks a default constructor");
  return NULL;
}

static napi_value
fdn_process_list_size (napi_env env,
                       napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaProcessList * handle;
  gint return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_process_list_size (handle);

  result = fdn_int_to_value (env, return_value);

  return result;
}

static napi_value
fdn_process_list_get (napi_env env,
                      napi_callback_info info)
{
  napi_value result;
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaProcessList * handle;
  gint index;
  FridaProcess * return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  if (argc > 0)
  {
    if (!fdn_int_from_value (env, args[0], &index))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: index");
    goto invalid_argument;
  }

  return_value = frida_process_list_get (handle, index);

  result = fdn_process_to_value (env, return_value);

  return result;

invalid_argument:
  {
    return NULL;
  }
}

static void
fdn_process_register (napi_env env,
                      napi_value exports)
{
  napi_property_descriptor properties[] =
  {
    { "getPid", NULL, fdn_process_get_pid, NULL, NULL, NULL, napi_default, NULL },
    { "getName", NULL, fdn_process_get_name, NULL, NULL, NULL, napi_default, NULL },
    { "getParameters", NULL, fdn_process_get_parameters, NULL, NULL, NULL, napi_default, NULL },
  };

  napi_value constructor;
  napi_define_class (env, "Process", NAPI_AUTO_LENGTH, fdn_process_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_process_constructor);

  napi_set_named_property (env, exports, "Process", constructor);
}

static gboolean
fdn_process_from_value (napi_env env,
                        napi_value value,
                        FridaProcess ** result)
{
  napi_status status;
  bool is_instance;
  FridaProcess * handle;

  status = napi_check_object_type_tag (env, value, &fdn_process_type_tag, &is_instance);
  if (status != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of Process");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) &handle);

  g_object_ref (handle);
  *result = handle;

  return TRUE;
}

static napi_value
fdn_process_to_value (napi_env env,
                      FridaProcess * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_process_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_process_construct (napi_env env,
                       napi_callback_info info)
{
  napi_throw_error (env, NULL, "class Process cannot be constructed because it lacks a default constructor");
  return NULL;
}

static napi_value
fdn_process_get_pid (napi_env env,
                     napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaProcess * handle;
  guint return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_process_get_pid (handle);

  result = fdn_uint_to_value (env, return_value);

  return result;
}

static napi_value
fdn_process_get_name (napi_env env,
                      napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaProcess * handle;
  gchar * return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_process_get_name (handle);

  result = fdn_utf8_to_value (env, return_value);

  return result;
}

static napi_value
fdn_process_get_parameters (napi_env env,
                            napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaProcess * handle;
  GHashTable * return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_process_get_parameters (handle);

  result = fdn_hash_table_to_value (env, return_value);

  return result;
}

static void
fdn_process_match_options_register (napi_env env,
                                    napi_value exports)
{
  napi_property_descriptor properties[] =
  {
    { "getTimeout", NULL, fdn_process_match_options_get_timeout, NULL, NULL, NULL, napi_default, NULL },
    { "setTimeout", NULL, fdn_process_match_options_set_timeout, NULL, NULL, NULL, napi_default, NULL },
    { "getScope", NULL, fdn_process_match_options_get_scope, NULL, NULL, NULL, napi_default, NULL },
    { "setScope", NULL, fdn_process_match_options_set_scope, NULL, NULL, NULL, napi_default, NULL },
  };

  napi_value constructor;
  napi_define_class (env, "ProcessMatchOptions", NAPI_AUTO_LENGTH, fdn_process_match_options_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_process_match_options_constructor);

  napi_set_named_property (env, exports, "ProcessMatchOptions", constructor);
}

static gboolean
fdn_process_match_options_from_value (napi_env env,
                                      napi_value value,
                                      FridaProcessMatchOptions ** result)
{
  napi_status status;
  bool is_instance;
  FridaProcessMatchOptions * handle;

  status = napi_check_object_type_tag (env, value, &fdn_process_match_options_type_tag, &is_instance);
  if (status != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of ProcessMatchOptions");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) &handle);

  g_object_ref (handle);
  *result = handle;

  return TRUE;
}

static napi_value
fdn_process_match_options_to_value (napi_env env,
                                    FridaProcessMatchOptions * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_process_match_options_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_process_match_options_construct (napi_env env,
                                     napi_callback_info info)
{
  size_t argc = 0;
  napi_value jsthis;
  napi_status status;
  FridaProcessMatchOptions * handle;

  status = napi_get_cb_info (env, info, &argc, NULL, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  handle = frida_process_match_options_new ();

  status = napi_type_tag_object (env, jsthis, &fdn_process_match_options_type_tag);
  if (status != napi_ok)
    return NULL;

  status = napi_wrap (env, jsthis, handle, NULL, NULL, NULL);
  if (status != napi_ok)
    return NULL;

  return jsthis;
}

static napi_value
fdn_process_match_options_get_timeout (napi_env env,
                                       napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaProcessMatchOptions * handle;
  gint return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_process_match_options_get_timeout (handle);

  result = fdn_int_to_value (env, return_value);

  return result;
}

static napi_value
fdn_process_match_options_set_timeout (napi_env env,
                                       napi_callback_info info)
{
  napi_value result;
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaProcessMatchOptions * handle;
  gint value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  if (argc > 0)
  {
    if (!fdn_int_from_value (env, args[0], &value))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: value");
    goto invalid_argument;
  }

  frida_process_match_options_set_timeout (handle, value);

  napi_get_undefined (env, &result);

  return result;

invalid_argument:
  {
    return NULL;
  }
}

static napi_value
fdn_process_match_options_get_scope (napi_env env,
                                     napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaProcessMatchOptions * handle;
  FridaScope return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_process_match_options_get_scope (handle);

  result = fdn_scope_to_value (env, return_value);

  return result;
}

static napi_value
fdn_process_match_options_set_scope (napi_env env,
                                     napi_callback_info info)
{
  napi_value result;
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaProcessMatchOptions * handle;
  FridaScope value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  if (argc > 0)
  {
    if (!fdn_scope_from_value (env, args[0], &value))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: value");
    goto invalid_argument;
  }

  frida_process_match_options_set_scope (handle, value);

  napi_get_undefined (env, &result);

  return result;

invalid_argument:
  {
    return NULL;
  }
}

static void
fdn_spawn_options_register (napi_env env,
                            napi_value exports)
{
  napi_property_descriptor properties[] =
  {
    { "getArgv", NULL, fdn_spawn_options_get_argv, NULL, NULL, NULL, napi_default, NULL },
    { "setArgv", NULL, fdn_spawn_options_set_argv, NULL, NULL, NULL, napi_default, NULL },
    { "getEnvp", NULL, fdn_spawn_options_get_envp, NULL, NULL, NULL, napi_default, NULL },
    { "setEnvp", NULL, fdn_spawn_options_set_envp, NULL, NULL, NULL, napi_default, NULL },
    { "getEnv", NULL, fdn_spawn_options_get_env, NULL, NULL, NULL, napi_default, NULL },
    { "setEnv", NULL, fdn_spawn_options_set_env, NULL, NULL, NULL, napi_default, NULL },
    { "getCwd", NULL, fdn_spawn_options_get_cwd, NULL, NULL, NULL, napi_default, NULL },
    { "setCwd", NULL, fdn_spawn_options_set_cwd, NULL, NULL, NULL, napi_default, NULL },
    { "getStdio", NULL, fdn_spawn_options_get_stdio, NULL, NULL, NULL, napi_default, NULL },
    { "setStdio", NULL, fdn_spawn_options_set_stdio, NULL, NULL, NULL, napi_default, NULL },
    { "getAux", NULL, fdn_spawn_options_get_aux, NULL, NULL, NULL, napi_default, NULL },
    { "setAux", NULL, fdn_spawn_options_set_aux, NULL, NULL, NULL, napi_default, NULL },
  };

  napi_value constructor;
  napi_define_class (env, "SpawnOptions", NAPI_AUTO_LENGTH, fdn_spawn_options_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_spawn_options_constructor);

  napi_set_named_property (env, exports, "SpawnOptions", constructor);
}

static gboolean
fdn_spawn_options_from_value (napi_env env,
                              napi_value value,
                              FridaSpawnOptions ** result)
{
  napi_status status;
  bool is_instance;
  FridaSpawnOptions * handle;

  status = napi_check_object_type_tag (env, value, &fdn_spawn_options_type_tag, &is_instance);
  if (status != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of SpawnOptions");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) &handle);

  g_object_ref (handle);
  *result = handle;

  return TRUE;
}

static napi_value
fdn_spawn_options_to_value (napi_env env,
                            FridaSpawnOptions * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_spawn_options_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_spawn_options_construct (napi_env env,
                             napi_callback_info info)
{
  size_t argc = 0;
  napi_value jsthis;
  napi_status status;
  FridaSpawnOptions * handle;

  status = napi_get_cb_info (env, info, &argc, NULL, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  handle = frida_spawn_options_new ();

  status = napi_type_tag_object (env, jsthis, &fdn_spawn_options_type_tag);
  if (status != napi_ok)
    return NULL;

  status = napi_wrap (env, jsthis, handle, NULL, NULL, NULL);
  if (status != napi_ok)
    return NULL;

  return jsthis;
}

static napi_value
fdn_spawn_options_get_argv (napi_env env,
                            napi_callback_info info)
{
  napi_value result;
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaSpawnOptions * handle;
  gint * result_length1;
  gchar ** return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  if (argc > 0)
  {
    if (!fdn_int_from_value (env, args[0], &result_length1))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: resultLength1");
    goto invalid_argument;
  }

  return_value = frida_spawn_options_get_argv (handle, result_length1);

  result = fdn_strv_to_value (env, return_value);

  return result;

invalid_argument:
  {
    return NULL;
  }
}

static napi_value
fdn_spawn_options_set_argv (napi_env env,
                            napi_callback_info info)
{
  napi_value result;
  size_t argc = 2;
  napi_value args[2];
  napi_status status;
  napi_value jsthis;
  FridaSpawnOptions * handle;
  gchar ** value;
  gint value_length1;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  if (argc > 0)
  {
    if (!fdn_strv_from_value (env, args[0], &value))
      goto invalid_argument;
  }
  else
  {
    value = NULL;
  }
  if (argc > 1)
  {
    if (!fdn_int_from_value (env, args[1], &value_length1))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: valueLength1");
    goto invalid_argument;
  }

  frida_spawn_options_set_argv (handle, value, value_length1);

  napi_get_undefined (env, &result);

  return result;

invalid_argument:
  {
    return NULL;
  }
}

static napi_value
fdn_spawn_options_get_envp (napi_env env,
                            napi_callback_info info)
{
  napi_value result;
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaSpawnOptions * handle;
  gint * result_length1;
  gchar ** return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  if (argc > 0)
  {
    if (!fdn_int_from_value (env, args[0], &result_length1))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: resultLength1");
    goto invalid_argument;
  }

  return_value = frida_spawn_options_get_envp (handle, result_length1);

  result = fdn_strv_to_value (env, return_value);

  return result;

invalid_argument:
  {
    return NULL;
  }
}

static napi_value
fdn_spawn_options_set_envp (napi_env env,
                            napi_callback_info info)
{
  napi_value result;
  size_t argc = 2;
  napi_value args[2];
  napi_status status;
  napi_value jsthis;
  FridaSpawnOptions * handle;
  gchar ** value;
  gint value_length1;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  if (argc > 0)
  {
    if (!fdn_strv_from_value (env, args[0], &value))
      goto invalid_argument;
  }
  else
  {
    value = NULL;
  }
  if (argc > 1)
  {
    if (!fdn_int_from_value (env, args[1], &value_length1))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: valueLength1");
    goto invalid_argument;
  }

  frida_spawn_options_set_envp (handle, value, value_length1);

  napi_get_undefined (env, &result);

  return result;

invalid_argument:
  {
    return NULL;
  }
}

static napi_value
fdn_spawn_options_get_env (napi_env env,
                           napi_callback_info info)
{
  napi_value result;
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaSpawnOptions * handle;
  gint * result_length1;
  gchar ** return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  if (argc > 0)
  {
    if (!fdn_int_from_value (env, args[0], &result_length1))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: resultLength1");
    goto invalid_argument;
  }

  return_value = frida_spawn_options_get_env (handle, result_length1);

  result = fdn_strv_to_value (env, return_value);

  return result;

invalid_argument:
  {
    return NULL;
  }
}

static napi_value
fdn_spawn_options_set_env (napi_env env,
                           napi_callback_info info)
{
  napi_value result;
  size_t argc = 2;
  napi_value args[2];
  napi_status status;
  napi_value jsthis;
  FridaSpawnOptions * handle;
  gchar ** value;
  gint value_length1;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  if (argc > 0)
  {
    if (!fdn_strv_from_value (env, args[0], &value))
      goto invalid_argument;
  }
  else
  {
    value = NULL;
  }
  if (argc > 1)
  {
    if (!fdn_int_from_value (env, args[1], &value_length1))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: valueLength1");
    goto invalid_argument;
  }

  frida_spawn_options_set_env (handle, value, value_length1);

  napi_get_undefined (env, &result);

  return result;

invalid_argument:
  {
    return NULL;
  }
}

static napi_value
fdn_spawn_options_get_cwd (napi_env env,
                           napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaSpawnOptions * handle;
  gchar * return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_spawn_options_get_cwd (handle);

  result = fdn_utf8_to_value (env, return_value);

  return result;
}

static napi_value
fdn_spawn_options_set_cwd (napi_env env,
                           napi_callback_info info)
{
  napi_value result;
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaSpawnOptions * handle;
  gchar * value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  if (argc > 0)
  {
    if (!fdn_utf8_from_value (env, args[0], &value))
      goto invalid_argument;
  }
  else
  {
    value = NULL;
  }

  frida_spawn_options_set_cwd (handle, value);

  
  g_free (operation->value);napi_get_undefined (env, &result);

  return result;

invalid_argument:
  {
    
  g_free (operation->value);return NULL;
  }
}

static napi_value
fdn_spawn_options_get_stdio (napi_env env,
                             napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaSpawnOptions * handle;
  FridaStdio return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_spawn_options_get_stdio (handle);

  result = fdn_stdio_to_value (env, return_value);

  return result;
}

static napi_value
fdn_spawn_options_set_stdio (napi_env env,
                             napi_callback_info info)
{
  napi_value result;
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaSpawnOptions * handle;
  FridaStdio value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  if (argc > 0)
  {
    if (!fdn_stdio_from_value (env, args[0], &value))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: value");
    goto invalid_argument;
  }

  frida_spawn_options_set_stdio (handle, value);

  napi_get_undefined (env, &result);

  return result;

invalid_argument:
  {
    return NULL;
  }
}

static napi_value
fdn_spawn_options_get_aux (napi_env env,
                           napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaSpawnOptions * handle;
  GHashTable * return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_spawn_options_get_aux (handle);

  result = fdn_hash_table_to_value (env, return_value);

  return result;
}

static napi_value
fdn_spawn_options_set_aux (napi_env env,
                           napi_callback_info info)
{
  napi_value result;
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaSpawnOptions * handle;
  GHashTable * value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  if (argc > 0)
  {
    if (!fdn_hash_table_from_value (env, args[0], &value))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: value");
    goto invalid_argument;
  }

  frida_spawn_options_set_aux (handle, value);

  napi_get_undefined (env, &result);

  return result;

invalid_argument:
  {
    return NULL;
  }
}

static void
fdn_spawn_list_register (napi_env env,
                         napi_value exports)
{
  napi_property_descriptor properties[] =
  {
    { "size", NULL, fdn_spawn_list_size, NULL, NULL, NULL, napi_default, NULL },
    { "get", NULL, fdn_spawn_list_get, NULL, NULL, NULL, napi_default, NULL },
  };

  napi_value constructor;
  napi_define_class (env, "SpawnList", NAPI_AUTO_LENGTH, fdn_spawn_list_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_spawn_list_constructor);

  napi_set_named_property (env, exports, "SpawnList", constructor);
}

static gboolean
fdn_spawn_list_from_value (napi_env env,
                           napi_value value,
                           FridaSpawnList ** result)
{
  napi_status status;
  bool is_instance;
  FridaSpawnList * handle;

  status = napi_check_object_type_tag (env, value, &fdn_spawn_list_type_tag, &is_instance);
  if (status != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of SpawnList");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) &handle);

  g_object_ref (handle);
  *result = handle;

  return TRUE;
}

static napi_value
fdn_spawn_list_to_value (napi_env env,
                         FridaSpawnList * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_spawn_list_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_spawn_list_construct (napi_env env,
                          napi_callback_info info)
{
  napi_throw_error (env, NULL, "class SpawnList cannot be constructed because it lacks a default constructor");
  return NULL;
}

static napi_value
fdn_spawn_list_size (napi_env env,
                     napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaSpawnList * handle;
  gint return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_spawn_list_size (handle);

  result = fdn_int_to_value (env, return_value);

  return result;
}

static napi_value
fdn_spawn_list_get (napi_env env,
                    napi_callback_info info)
{
  napi_value result;
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaSpawnList * handle;
  gint index;
  FridaSpawn * return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  if (argc > 0)
  {
    if (!fdn_int_from_value (env, args[0], &index))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: index");
    goto invalid_argument;
  }

  return_value = frida_spawn_list_get (handle, index);

  result = fdn_spawn_to_value (env, return_value);

  return result;

invalid_argument:
  {
    return NULL;
  }
}

static void
fdn_spawn_register (napi_env env,
                    napi_value exports)
{
  napi_property_descriptor properties[] =
  {
    { "getPid", NULL, fdn_spawn_get_pid, NULL, NULL, NULL, napi_default, NULL },
    { "getIdentifier", NULL, fdn_spawn_get_identifier, NULL, NULL, NULL, napi_default, NULL },
  };

  napi_value constructor;
  napi_define_class (env, "Spawn", NAPI_AUTO_LENGTH, fdn_spawn_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_spawn_constructor);

  napi_set_named_property (env, exports, "Spawn", constructor);
}

static gboolean
fdn_spawn_from_value (napi_env env,
                      napi_value value,
                      FridaSpawn ** result)
{
  napi_status status;
  bool is_instance;
  FridaSpawn * handle;

  status = napi_check_object_type_tag (env, value, &fdn_spawn_type_tag, &is_instance);
  if (status != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of Spawn");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) &handle);

  g_object_ref (handle);
  *result = handle;

  return TRUE;
}

static napi_value
fdn_spawn_to_value (napi_env env,
                    FridaSpawn * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_spawn_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_spawn_construct (napi_env env,
                     napi_callback_info info)
{
  napi_throw_error (env, NULL, "class Spawn cannot be constructed because it lacks a default constructor");
  return NULL;
}

static napi_value
fdn_spawn_get_pid (napi_env env,
                   napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaSpawn * handle;
  guint return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_spawn_get_pid (handle);

  result = fdn_uint_to_value (env, return_value);

  return result;
}

static napi_value
fdn_spawn_get_identifier (napi_env env,
                          napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaSpawn * handle;
  gchar * return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_spawn_get_identifier (handle);

  result = fdn_utf8_to_value (env, return_value);

  return result;
}

static void
fdn_child_list_register (napi_env env,
                         napi_value exports)
{
  napi_property_descriptor properties[] =
  {
    { "size", NULL, fdn_child_list_size, NULL, NULL, NULL, napi_default, NULL },
    { "get", NULL, fdn_child_list_get, NULL, NULL, NULL, napi_default, NULL },
  };

  napi_value constructor;
  napi_define_class (env, "ChildList", NAPI_AUTO_LENGTH, fdn_child_list_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_child_list_constructor);

  napi_set_named_property (env, exports, "ChildList", constructor);
}

static gboolean
fdn_child_list_from_value (napi_env env,
                           napi_value value,
                           FridaChildList ** result)
{
  napi_status status;
  bool is_instance;
  FridaChildList * handle;

  status = napi_check_object_type_tag (env, value, &fdn_child_list_type_tag, &is_instance);
  if (status != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of ChildList");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) &handle);

  g_object_ref (handle);
  *result = handle;

  return TRUE;
}

static napi_value
fdn_child_list_to_value (napi_env env,
                         FridaChildList * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_child_list_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_child_list_construct (napi_env env,
                          napi_callback_info info)
{
  napi_throw_error (env, NULL, "class ChildList cannot be constructed because it lacks a default constructor");
  return NULL;
}

static napi_value
fdn_child_list_size (napi_env env,
                     napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaChildList * handle;
  gint return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_child_list_size (handle);

  result = fdn_int_to_value (env, return_value);

  return result;
}

static napi_value
fdn_child_list_get (napi_env env,
                    napi_callback_info info)
{
  napi_value result;
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaChildList * handle;
  gint index;
  FridaChild * return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  if (argc > 0)
  {
    if (!fdn_int_from_value (env, args[0], &index))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: index");
    goto invalid_argument;
  }

  return_value = frida_child_list_get (handle, index);

  result = fdn_child_to_value (env, return_value);

  return result;

invalid_argument:
  {
    return NULL;
  }
}

static void
fdn_child_register (napi_env env,
                    napi_value exports)
{
  napi_property_descriptor properties[] =
  {
    { "getPid", NULL, fdn_child_get_pid, NULL, NULL, NULL, napi_default, NULL },
    { "getParentPid", NULL, fdn_child_get_parent_pid, NULL, NULL, NULL, napi_default, NULL },
    { "getOrigin", NULL, fdn_child_get_origin, NULL, NULL, NULL, napi_default, NULL },
    { "getIdentifier", NULL, fdn_child_get_identifier, NULL, NULL, NULL, napi_default, NULL },
    { "getPath", NULL, fdn_child_get_path, NULL, NULL, NULL, napi_default, NULL },
    { "getArgv", NULL, fdn_child_get_argv, NULL, NULL, NULL, napi_default, NULL },
    { "getEnvp", NULL, fdn_child_get_envp, NULL, NULL, NULL, napi_default, NULL },
  };

  napi_value constructor;
  napi_define_class (env, "Child", NAPI_AUTO_LENGTH, fdn_child_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_child_constructor);

  napi_set_named_property (env, exports, "Child", constructor);
}

static gboolean
fdn_child_from_value (napi_env env,
                      napi_value value,
                      FridaChild ** result)
{
  napi_status status;
  bool is_instance;
  FridaChild * handle;

  status = napi_check_object_type_tag (env, value, &fdn_child_type_tag, &is_instance);
  if (status != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of Child");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) &handle);

  g_object_ref (handle);
  *result = handle;

  return TRUE;
}

static napi_value
fdn_child_to_value (napi_env env,
                    FridaChild * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_child_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_child_construct (napi_env env,
                     napi_callback_info info)
{
  napi_throw_error (env, NULL, "class Child cannot be constructed because it lacks a default constructor");
  return NULL;
}

static napi_value
fdn_child_get_pid (napi_env env,
                   napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaChild * handle;
  guint return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_child_get_pid (handle);

  result = fdn_uint_to_value (env, return_value);

  return result;
}

static napi_value
fdn_child_get_parent_pid (napi_env env,
                          napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaChild * handle;
  guint return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_child_get_parent_pid (handle);

  result = fdn_uint_to_value (env, return_value);

  return result;
}

static napi_value
fdn_child_get_origin (napi_env env,
                      napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaChild * handle;
  FridaChildOrigin return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_child_get_origin (handle);

  result = fdn_child_origin_to_value (env, return_value);

  return result;
}

static napi_value
fdn_child_get_identifier (napi_env env,
                          napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaChild * handle;
  gchar * return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_child_get_identifier (handle);

  result = fdn_utf8_to_value (env, return_value);

  return result;
}

static napi_value
fdn_child_get_path (napi_env env,
                    napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaChild * handle;
  gchar * return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_child_get_path (handle);

  result = fdn_utf8_to_value (env, return_value);

  return result;
}

static napi_value
fdn_child_get_argv (napi_env env,
                    napi_callback_info info)
{
  napi_value result;
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaChild * handle;
  gint * result_length1;
  gchar ** return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  if (argc > 0)
  {
    if (!fdn_int_from_value (env, args[0], &result_length1))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: resultLength1");
    goto invalid_argument;
  }

  return_value = frida_child_get_argv (handle, result_length1);

  result = fdn_strv_to_value (env, return_value);

  return result;

invalid_argument:
  {
    return NULL;
  }
}

static napi_value
fdn_child_get_envp (napi_env env,
                    napi_callback_info info)
{
  napi_value result;
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaChild * handle;
  gint * result_length1;
  gchar ** return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  if (argc > 0)
  {
    if (!fdn_int_from_value (env, args[0], &result_length1))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: resultLength1");
    goto invalid_argument;
  }

  return_value = frida_child_get_envp (handle, result_length1);

  result = fdn_strv_to_value (env, return_value);

  return result;

invalid_argument:
  {
    return NULL;
  }
}

static void
fdn_crash_register (napi_env env,
                    napi_value exports)
{
  napi_property_descriptor properties[] =
  {
    { "getPid", NULL, fdn_crash_get_pid, NULL, NULL, NULL, napi_default, NULL },
    { "getProcessName", NULL, fdn_crash_get_process_name, NULL, NULL, NULL, napi_default, NULL },
    { "getSummary", NULL, fdn_crash_get_summary, NULL, NULL, NULL, napi_default, NULL },
    { "getReport", NULL, fdn_crash_get_report, NULL, NULL, NULL, napi_default, NULL },
    { "getParameters", NULL, fdn_crash_get_parameters, NULL, NULL, NULL, napi_default, NULL },
  };

  napi_value constructor;
  napi_define_class (env, "Crash", NAPI_AUTO_LENGTH, fdn_crash_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_crash_constructor);

  napi_set_named_property (env, exports, "Crash", constructor);
}

static gboolean
fdn_crash_from_value (napi_env env,
                      napi_value value,
                      FridaCrash ** result)
{
  napi_status status;
  bool is_instance;
  FridaCrash * handle;

  status = napi_check_object_type_tag (env, value, &fdn_crash_type_tag, &is_instance);
  if (status != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of Crash");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) &handle);

  g_object_ref (handle);
  *result = handle;

  return TRUE;
}

static napi_value
fdn_crash_to_value (napi_env env,
                    FridaCrash * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_crash_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_crash_construct (napi_env env,
                     napi_callback_info info)
{
  napi_throw_error (env, NULL, "class Crash cannot be constructed because it lacks a default constructor");
  return NULL;
}

static napi_value
fdn_crash_get_pid (napi_env env,
                   napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaCrash * handle;
  guint return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_crash_get_pid (handle);

  result = fdn_uint_to_value (env, return_value);

  return result;
}

static napi_value
fdn_crash_get_process_name (napi_env env,
                            napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaCrash * handle;
  gchar * return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_crash_get_process_name (handle);

  result = fdn_utf8_to_value (env, return_value);

  return result;
}

static napi_value
fdn_crash_get_summary (napi_env env,
                       napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaCrash * handle;
  gchar * return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_crash_get_summary (handle);

  result = fdn_utf8_to_value (env, return_value);

  return result;
}

static napi_value
fdn_crash_get_report (napi_env env,
                      napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaCrash * handle;
  gchar * return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_crash_get_report (handle);

  result = fdn_utf8_to_value (env, return_value);

  return result;
}

static napi_value
fdn_crash_get_parameters (napi_env env,
                          napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaCrash * handle;
  GHashTable * return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_crash_get_parameters (handle);

  result = fdn_hash_table_to_value (env, return_value);

  return result;
}

static void
fdn_bus_register (napi_env env,
                  napi_value exports)
{
  napi_property_descriptor properties[] =
  {
    { "isDetached", NULL, fdn_bus_is_detached, NULL, NULL, NULL, napi_default, NULL },
    { "attach", NULL, fdn_bus_attach, NULL, NULL, NULL, napi_default, NULL },
    { "post", NULL, fdn_bus_post, NULL, NULL, NULL, napi_default, NULL },
    { "getDevice", NULL, fdn_bus_get_device, NULL, NULL, NULL, napi_default, NULL },
  };

  napi_value constructor;
  napi_define_class (env, "Bus", NAPI_AUTO_LENGTH, fdn_bus_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_bus_constructor);

  napi_set_named_property (env, exports, "Bus", constructor);

  napi_value resource_name;

  napi_create_string_utf8 (env, "attach", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_bus_attach_deliver, &fdn_bus_attach_tsfn);
}

static gboolean
fdn_bus_from_value (napi_env env,
                    napi_value value,
                    FridaBus ** result)
{
  napi_status status;
  bool is_instance;
  FridaBus * handle;

  status = napi_check_object_type_tag (env, value, &fdn_bus_type_tag, &is_instance);
  if (status != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of Bus");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) &handle);

  g_object_ref (handle);
  *result = handle;

  return TRUE;
}

static napi_value
fdn_bus_to_value (napi_env env,
                  FridaBus * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_bus_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_bus_construct (napi_env env,
                   napi_callback_info info)
{
  napi_throw_error (env, NULL, "class Bus cannot be constructed because it lacks a default constructor");
  return NULL;
}

static napi_value
fdn_bus_is_detached (napi_env env,
                     napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaBus * handle;
  gboolean return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_bus_is_detached (handle);

  result = fdn_boolean_to_value (env, return_value);

  return result;
}

static napi_value
fdn_bus_attach (napi_env env,
                napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaBus * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnBusAttachOperation * operation;
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

  operation = g_slice_new0 (FdnBusAttachOperation);
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
  g_source_set_callback (source, fdn_bus_attach_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, fdn_bus_attach_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    fdn_bus_attach_operation_free (operation);
    return NULL;
  }
}

static gboolean
fdn_bus_attach_begin (gpointer user_data)
{
  FdnBusAttachOperation * operation = user_data;

  frida_bus_attach (operation->handle,
      operation->cancellable,
      fdn_bus_attach_end, operation);

  return G_SOURCE_REMOVE;
}

static void
fdn_bus_attach_end (GObject * source_object,
                    GAsyncResult * res,
                    gpointer user_data)
{
  FdnBusAttachOperation * operation = user_data;

  frida_bus_attach_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (fdn_bus_attach_tsfn, operation, napi_tsfn_blocking);
}

static void
fdn_bus_attach_deliver (napi_env env,
                        napi_value js_cb,
                        void * context,
                        void * data)
{
  FdnBusAttachOperation * operation = data;

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

  fdn_bus_attach_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_bus_attach_tsfn);
}

static void
fdn_bus_attach_operation_free (FdnBusAttachOperation * operation)
{
  g_slice_free (FdnBusAttachOperation, operation);
}

static napi_value
fdn_bus_post (napi_env env,
              napi_callback_info info)
{
  napi_value result;
  size_t argc = 2;
  napi_value args[2];
  napi_status status;
  napi_value jsthis;
  FridaBus * handle;
  gchar * json;
  GBytes * data;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  if (argc > 0)
  {
    if (!fdn_utf8_from_value (env, args[0], &json))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: json");
    goto invalid_argument;
  }
  if (argc > 1)
  {
    if (!fdn_bytes_from_value (env, args[1], &data))
      goto invalid_argument;
  }
  else
  {
    data = NULL;
  }

  frida_bus_post (handle, json, data);

  
  g_free (operation->json);napi_get_undefined (env, &result);

  return result;

invalid_argument:
  {
    
  g_free (operation->json);return NULL;
  }
}

static napi_value
fdn_bus_get_device (napi_env env,
                    napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaBus * handle;
  FridaDevice * return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_bus_get_device (handle);

  result = fdn_device_to_value (env, return_value);

  return result;
}

static void
fdn_session_register (napi_env env,
                      napi_value exports)
{
  napi_property_descriptor properties[] =
  {
    { "isDetached", NULL, fdn_session_is_detached, NULL, NULL, NULL, napi_default, NULL },
    { "detach", NULL, fdn_session_detach, NULL, NULL, NULL, napi_default, NULL },
    { "resume", NULL, fdn_session_resume, NULL, NULL, NULL, napi_default, NULL },
    { "enableChildGating", NULL, fdn_session_enable_child_gating, NULL, NULL, NULL, napi_default, NULL },
    { "disableChildGating", NULL, fdn_session_disable_child_gating, NULL, NULL, NULL, napi_default, NULL },
    { "createScript", NULL, fdn_session_create_script, NULL, NULL, NULL, napi_default, NULL },
    { "createScriptFromBytes", NULL, fdn_session_create_script_from_bytes, NULL, NULL, NULL, napi_default, NULL },
    { "compileScript", NULL, fdn_session_compile_script, NULL, NULL, NULL, napi_default, NULL },
    { "snapshotScript", NULL, fdn_session_snapshot_script, NULL, NULL, NULL, napi_default, NULL },
    { "setupPeerConnection", NULL, fdn_session_setup_peer_connection, NULL, NULL, NULL, napi_default, NULL },
    { "joinPortal", NULL, fdn_session_join_portal, NULL, NULL, NULL, napi_default, NULL },
    { "getPid", NULL, fdn_session_get_pid, NULL, NULL, NULL, napi_default, NULL },
    { "getSession", NULL, fdn_session_get_session, NULL, NULL, NULL, napi_default, NULL },
    { "getPersistTimeout", NULL, fdn_session_get_persist_timeout, NULL, NULL, NULL, napi_default, NULL },
    { "getDevice", NULL, fdn_session_get_device, NULL, NULL, NULL, napi_default, NULL },
  };

  napi_value constructor;
  napi_define_class (env, "Session", NAPI_AUTO_LENGTH, fdn_session_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_session_constructor);

  napi_set_named_property (env, exports, "Session", constructor);

  napi_value resource_name;

  napi_create_string_utf8 (env, "detach", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_session_detach_deliver, &fdn_session_detach_tsfn);

  napi_create_string_utf8 (env, "resume", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_session_resume_deliver, &fdn_session_resume_tsfn);

  napi_create_string_utf8 (env, "enableChildGating", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_session_enable_child_gating_deliver, &fdn_session_enable_child_gating_tsfn);

  napi_create_string_utf8 (env, "disableChildGating", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_session_disable_child_gating_deliver, &fdn_session_disable_child_gating_tsfn);

  napi_create_string_utf8 (env, "createScript", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_session_create_script_deliver, &fdn_session_create_script_tsfn);

  napi_create_string_utf8 (env, "createScriptFromBytes", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_session_create_script_from_bytes_deliver, &fdn_session_create_script_from_bytes_tsfn);

  napi_create_string_utf8 (env, "compileScript", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_session_compile_script_deliver, &fdn_session_compile_script_tsfn);

  napi_create_string_utf8 (env, "snapshotScript", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_session_snapshot_script_deliver, &fdn_session_snapshot_script_tsfn);

  napi_create_string_utf8 (env, "setupPeerConnection", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_session_setup_peer_connection_deliver, &fdn_session_setup_peer_connection_tsfn);

  napi_create_string_utf8 (env, "joinPortal", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_session_join_portal_deliver, &fdn_session_join_portal_tsfn);
}

static gboolean
fdn_session_from_value (napi_env env,
                        napi_value value,
                        FridaSession ** result)
{
  napi_status status;
  bool is_instance;
  FridaSession * handle;

  status = napi_check_object_type_tag (env, value, &fdn_session_type_tag, &is_instance);
  if (status != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of Session");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) &handle);

  g_object_ref (handle);
  *result = handle;

  return TRUE;
}

static napi_value
fdn_session_to_value (napi_env env,
                      FridaSession * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_session_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_session_construct (napi_env env,
                       napi_callback_info info)
{
  napi_throw_error (env, NULL, "class Session cannot be constructed because it lacks a default constructor");
  return NULL;
}

static napi_value
fdn_session_is_detached (napi_env env,
                         napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaSession * handle;
  gboolean return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_session_is_detached (handle);

  result = fdn_boolean_to_value (env, return_value);

  return result;
}

static napi_value
fdn_session_detach (napi_env env,
                    napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaSession * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnSessionDetachOperation * operation;
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

  operation = g_slice_new0 (FdnSessionDetachOperation);
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
  g_source_set_callback (source, fdn_session_detach_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, fdn_session_detach_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    fdn_session_detach_operation_free (operation);
    return NULL;
  }
}

static gboolean
fdn_session_detach_begin (gpointer user_data)
{
  FdnSessionDetachOperation * operation = user_data;

  frida_session_detach (operation->handle,
      operation->cancellable,
      fdn_session_detach_end, operation);

  return G_SOURCE_REMOVE;
}

static void
fdn_session_detach_end (GObject * source_object,
                        GAsyncResult * res,
                        gpointer user_data)
{
  FdnSessionDetachOperation * operation = user_data;

  frida_session_detach_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (fdn_session_detach_tsfn, operation, napi_tsfn_blocking);
}

static void
fdn_session_detach_deliver (napi_env env,
                            napi_value js_cb,
                            void * context,
                            void * data)
{
  FdnSessionDetachOperation * operation = data;

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

  fdn_session_detach_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_session_detach_tsfn);
}

static void
fdn_session_detach_operation_free (FdnSessionDetachOperation * operation)
{
  g_slice_free (FdnSessionDetachOperation, operation);
}

static napi_value
fdn_session_resume (napi_env env,
                    napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaSession * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnSessionResumeOperation * operation;
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

  operation = g_slice_new0 (FdnSessionResumeOperation);
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
  g_source_set_callback (source, fdn_session_resume_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, fdn_session_resume_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    fdn_session_resume_operation_free (operation);
    return NULL;
  }
}

static gboolean
fdn_session_resume_begin (gpointer user_data)
{
  FdnSessionResumeOperation * operation = user_data;

  frida_session_resume (operation->handle,
      operation->cancellable,
      fdn_session_resume_end, operation);

  return G_SOURCE_REMOVE;
}

static void
fdn_session_resume_end (GObject * source_object,
                        GAsyncResult * res,
                        gpointer user_data)
{
  FdnSessionResumeOperation * operation = user_data;

  frida_session_resume_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (fdn_session_resume_tsfn, operation, napi_tsfn_blocking);
}

static void
fdn_session_resume_deliver (napi_env env,
                            napi_value js_cb,
                            void * context,
                            void * data)
{
  FdnSessionResumeOperation * operation = data;

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

  fdn_session_resume_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_session_resume_tsfn);
}

static void
fdn_session_resume_operation_free (FdnSessionResumeOperation * operation)
{
  g_slice_free (FdnSessionResumeOperation, operation);
}

static napi_value
fdn_session_enable_child_gating (napi_env env,
                                 napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaSession * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnSessionEnableChildGatingOperation * operation;
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

  operation = g_slice_new0 (FdnSessionEnableChildGatingOperation);
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
  g_source_set_callback (source, fdn_session_enable_child_gating_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, fdn_session_enable_child_gating_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    fdn_session_enable_child_gating_operation_free (operation);
    return NULL;
  }
}

static gboolean
fdn_session_enable_child_gating_begin (gpointer user_data)
{
  FdnSessionEnableChildGatingOperation * operation = user_data;

  frida_session_enable_child_gating (operation->handle,
      operation->cancellable,
      fdn_session_enable_child_gating_end, operation);

  return G_SOURCE_REMOVE;
}

static void
fdn_session_enable_child_gating_end (GObject * source_object,
                                     GAsyncResult * res,
                                     gpointer user_data)
{
  FdnSessionEnableChildGatingOperation * operation = user_data;

  frida_session_enable_child_gating_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (fdn_session_enable_child_gating_tsfn, operation, napi_tsfn_blocking);
}

static void
fdn_session_enable_child_gating_deliver (napi_env env,
                                         napi_value js_cb,
                                         void * context,
                                         void * data)
{
  FdnSessionEnableChildGatingOperation * operation = data;

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

  fdn_session_enable_child_gating_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_session_enable_child_gating_tsfn);
}

static void
fdn_session_enable_child_gating_operation_free (FdnSessionEnableChildGatingOperation * operation)
{
  g_slice_free (FdnSessionEnableChildGatingOperation, operation);
}

static napi_value
fdn_session_disable_child_gating (napi_env env,
                                  napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaSession * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnSessionDisableChildGatingOperation * operation;
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

  operation = g_slice_new0 (FdnSessionDisableChildGatingOperation);
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
  g_source_set_callback (source, fdn_session_disable_child_gating_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, fdn_session_disable_child_gating_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    fdn_session_disable_child_gating_operation_free (operation);
    return NULL;
  }
}

static gboolean
fdn_session_disable_child_gating_begin (gpointer user_data)
{
  FdnSessionDisableChildGatingOperation * operation = user_data;

  frida_session_disable_child_gating (operation->handle,
      operation->cancellable,
      fdn_session_disable_child_gating_end, operation);

  return G_SOURCE_REMOVE;
}

static void
fdn_session_disable_child_gating_end (GObject * source_object,
                                      GAsyncResult * res,
                                      gpointer user_data)
{
  FdnSessionDisableChildGatingOperation * operation = user_data;

  frida_session_disable_child_gating_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (fdn_session_disable_child_gating_tsfn, operation, napi_tsfn_blocking);
}

static void
fdn_session_disable_child_gating_deliver (napi_env env,
                                          napi_value js_cb,
                                          void * context,
                                          void * data)
{
  FdnSessionDisableChildGatingOperation * operation = data;

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

  fdn_session_disable_child_gating_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_session_disable_child_gating_tsfn);
}

static void
fdn_session_disable_child_gating_operation_free (FdnSessionDisableChildGatingOperation * operation)
{
  g_slice_free (FdnSessionDisableChildGatingOperation, operation);
}

static napi_value
fdn_session_create_script (napi_env env,
                           napi_callback_info info)
{
  size_t argc = 3;
  napi_value args[3];
  napi_status status;
  napi_value jsthis;
  FridaSession * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnSessionCreateScriptOperation * operation;
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

  operation = g_slice_new0 (FdnSessionCreateScriptOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0)
  {
    if (!fdn_utf8_from_value (env, args[0], &operation->source))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: source");
    goto invalid_argument;
  }

  if (argc > 1)
  {
    if (!fdn_script_options_from_value (env, args[1], &operation->options))
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
  g_source_set_callback (source, fdn_session_create_script_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, fdn_session_create_script_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    fdn_session_create_script_operation_free (operation);
    return NULL;
  }
}

static gboolean
fdn_session_create_script_begin (gpointer user_data)
{
  FdnSessionCreateScriptOperation * operation = user_data;

  frida_session_create_script (operation->handle,
      operation->source, operation->options, operation->cancellable,
      fdn_session_create_script_end, operation);

  return G_SOURCE_REMOVE;
}

static void
fdn_session_create_script_end (GObject * source_object,
                               GAsyncResult * res,
                               gpointer user_data)
{
  FdnSessionCreateScriptOperation * operation = user_data;

  

  operation->return_value = frida_session_create_script_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (fdn_session_create_script_tsfn, operation, napi_tsfn_blocking);
}

static void
fdn_session_create_script_deliver (napi_env env,
                                   napi_value js_cb,
                                   void * context,
                                   void * data)
{
  FdnSessionCreateScriptOperation * operation = data;

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
    result = fdn_script_to_value (env, operation->return_value);
    napi_resolve_deferred (env, operation->deferred, result);
  }

  fdn_session_create_script_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_session_create_script_tsfn);
}

static void
fdn_session_create_script_operation_free (FdnSessionCreateScriptOperation * operation)
{
  g_free (operation->source);
  g_slice_free (FdnSessionCreateScriptOperation, operation);
}

static napi_value
fdn_session_create_script_from_bytes (napi_env env,
                                      napi_callback_info info)
{
  size_t argc = 3;
  napi_value args[3];
  napi_status status;
  napi_value jsthis;
  FridaSession * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnSessionCreateScriptFromBytesOperation * operation;
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

  operation = g_slice_new0 (FdnSessionCreateScriptFromBytesOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0)
  {
    if (!fdn_bytes_from_value (env, args[0], &operation->bytes))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: bytes");
    goto invalid_argument;
  }

  if (argc > 1)
  {
    if (!fdn_script_options_from_value (env, args[1], &operation->options))
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
  g_source_set_callback (source, fdn_session_create_script_from_bytes_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, fdn_session_create_script_from_bytes_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    fdn_session_create_script_from_bytes_operation_free (operation);
    return NULL;
  }
}

static gboolean
fdn_session_create_script_from_bytes_begin (gpointer user_data)
{
  FdnSessionCreateScriptFromBytesOperation * operation = user_data;

  frida_session_create_script_from_bytes (operation->handle,
      operation->bytes, operation->options, operation->cancellable,
      fdn_session_create_script_from_bytes_end, operation);

  return G_SOURCE_REMOVE;
}

static void
fdn_session_create_script_from_bytes_end (GObject * source_object,
                                          GAsyncResult * res,
                                          gpointer user_data)
{
  FdnSessionCreateScriptFromBytesOperation * operation = user_data;

  

  operation->return_value = frida_session_create_script_from_bytes_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (fdn_session_create_script_from_bytes_tsfn, operation, napi_tsfn_blocking);
}

static void
fdn_session_create_script_from_bytes_deliver (napi_env env,
                                              napi_value js_cb,
                                              void * context,
                                              void * data)
{
  FdnSessionCreateScriptFromBytesOperation * operation = data;

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
    result = fdn_script_to_value (env, operation->return_value);
    napi_resolve_deferred (env, operation->deferred, result);
  }

  fdn_session_create_script_from_bytes_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_session_create_script_from_bytes_tsfn);
}

static void
fdn_session_create_script_from_bytes_operation_free (FdnSessionCreateScriptFromBytesOperation * operation)
{
  g_slice_free (FdnSessionCreateScriptFromBytesOperation, operation);
}

static napi_value
fdn_session_compile_script (napi_env env,
                            napi_callback_info info)
{
  size_t argc = 3;
  napi_value args[3];
  napi_status status;
  napi_value jsthis;
  FridaSession * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnSessionCompileScriptOperation * operation;
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

  operation = g_slice_new0 (FdnSessionCompileScriptOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0)
  {
    if (!fdn_utf8_from_value (env, args[0], &operation->source))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: source");
    goto invalid_argument;
  }

  if (argc > 1)
  {
    if (!fdn_script_options_from_value (env, args[1], &operation->options))
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
  g_source_set_callback (source, fdn_session_compile_script_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, fdn_session_compile_script_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    fdn_session_compile_script_operation_free (operation);
    return NULL;
  }
}

static gboolean
fdn_session_compile_script_begin (gpointer user_data)
{
  FdnSessionCompileScriptOperation * operation = user_data;

  frida_session_compile_script (operation->handle,
      operation->source, operation->options, operation->cancellable,
      fdn_session_compile_script_end, operation);

  return G_SOURCE_REMOVE;
}

static void
fdn_session_compile_script_end (GObject * source_object,
                                GAsyncResult * res,
                                gpointer user_data)
{
  FdnSessionCompileScriptOperation * operation = user_data;

  

  operation->return_value = frida_session_compile_script_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (fdn_session_compile_script_tsfn, operation, napi_tsfn_blocking);
}

static void
fdn_session_compile_script_deliver (napi_env env,
                                    napi_value js_cb,
                                    void * context,
                                    void * data)
{
  FdnSessionCompileScriptOperation * operation = data;

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
    result = fdn_bytes_to_value (env, operation->return_value);
    napi_resolve_deferred (env, operation->deferred, result);
  }

  fdn_session_compile_script_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_session_compile_script_tsfn);
}

static void
fdn_session_compile_script_operation_free (FdnSessionCompileScriptOperation * operation)
{
  g_free (operation->source);
  g_slice_free (FdnSessionCompileScriptOperation, operation);
}

static napi_value
fdn_session_snapshot_script (napi_env env,
                             napi_callback_info info)
{
  size_t argc = 3;
  napi_value args[3];
  napi_status status;
  napi_value jsthis;
  FridaSession * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnSessionSnapshotScriptOperation * operation;
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

  operation = g_slice_new0 (FdnSessionSnapshotScriptOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0)
  {
    if (!fdn_utf8_from_value (env, args[0], &operation->embed_script))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: embedScript");
    goto invalid_argument;
  }

  if (argc > 1)
  {
    if (!fdn_snapshot_options_from_value (env, args[1], &operation->options))
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
  g_source_set_callback (source, fdn_session_snapshot_script_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, fdn_session_snapshot_script_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    fdn_session_snapshot_script_operation_free (operation);
    return NULL;
  }
}

static gboolean
fdn_session_snapshot_script_begin (gpointer user_data)
{
  FdnSessionSnapshotScriptOperation * operation = user_data;

  frida_session_snapshot_script (operation->handle,
      operation->embed_script, operation->options, operation->cancellable,
      fdn_session_snapshot_script_end, operation);

  return G_SOURCE_REMOVE;
}

static void
fdn_session_snapshot_script_end (GObject * source_object,
                                 GAsyncResult * res,
                                 gpointer user_data)
{
  FdnSessionSnapshotScriptOperation * operation = user_data;

  

  operation->return_value = frida_session_snapshot_script_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (fdn_session_snapshot_script_tsfn, operation, napi_tsfn_blocking);
}

static void
fdn_session_snapshot_script_deliver (napi_env env,
                                     napi_value js_cb,
                                     void * context,
                                     void * data)
{
  FdnSessionSnapshotScriptOperation * operation = data;

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
    result = fdn_bytes_to_value (env, operation->return_value);
    napi_resolve_deferred (env, operation->deferred, result);
  }

  fdn_session_snapshot_script_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_session_snapshot_script_tsfn);
}

static void
fdn_session_snapshot_script_operation_free (FdnSessionSnapshotScriptOperation * operation)
{
  g_free (operation->embed_script);
  g_slice_free (FdnSessionSnapshotScriptOperation, operation);
}

static napi_value
fdn_session_setup_peer_connection (napi_env env,
                                   napi_callback_info info)
{
  size_t argc = 2;
  napi_value args[2];
  napi_status status;
  napi_value jsthis;
  FridaSession * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnSessionSetupPeerConnectionOperation * operation;
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

  operation = g_slice_new0 (FdnSessionSetupPeerConnectionOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0)
  {
    if (!fdn_peer_options_from_value (env, args[0], &operation->options))
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
  g_source_set_callback (source, fdn_session_setup_peer_connection_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, fdn_session_setup_peer_connection_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    fdn_session_setup_peer_connection_operation_free (operation);
    return NULL;
  }
}

static gboolean
fdn_session_setup_peer_connection_begin (gpointer user_data)
{
  FdnSessionSetupPeerConnectionOperation * operation = user_data;

  frida_session_setup_peer_connection (operation->handle,
      operation->options, operation->cancellable,
      fdn_session_setup_peer_connection_end, operation);

  return G_SOURCE_REMOVE;
}

static void
fdn_session_setup_peer_connection_end (GObject * source_object,
                                       GAsyncResult * res,
                                       gpointer user_data)
{
  FdnSessionSetupPeerConnectionOperation * operation = user_data;

  frida_session_setup_peer_connection_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (fdn_session_setup_peer_connection_tsfn, operation, napi_tsfn_blocking);
}

static void
fdn_session_setup_peer_connection_deliver (napi_env env,
                                           napi_value js_cb,
                                           void * context,
                                           void * data)
{
  FdnSessionSetupPeerConnectionOperation * operation = data;

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

  fdn_session_setup_peer_connection_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_session_setup_peer_connection_tsfn);
}

static void
fdn_session_setup_peer_connection_operation_free (FdnSessionSetupPeerConnectionOperation * operation)
{
  g_slice_free (FdnSessionSetupPeerConnectionOperation, operation);
}

static napi_value
fdn_session_join_portal (napi_env env,
                         napi_callback_info info)
{
  size_t argc = 3;
  napi_value args[3];
  napi_status status;
  napi_value jsthis;
  FridaSession * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnSessionJoinPortalOperation * operation;
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

  operation = g_slice_new0 (FdnSessionJoinPortalOperation);
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
    if (!fdn_portal_options_from_value (env, args[1], &operation->options))
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
  g_source_set_callback (source, fdn_session_join_portal_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, fdn_session_join_portal_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    fdn_session_join_portal_operation_free (operation);
    return NULL;
  }
}

static gboolean
fdn_session_join_portal_begin (gpointer user_data)
{
  FdnSessionJoinPortalOperation * operation = user_data;

  frida_session_join_portal (operation->handle,
      operation->address, operation->options, operation->cancellable,
      fdn_session_join_portal_end, operation);

  return G_SOURCE_REMOVE;
}

static void
fdn_session_join_portal_end (GObject * source_object,
                             GAsyncResult * res,
                             gpointer user_data)
{
  FdnSessionJoinPortalOperation * operation = user_data;

  

  operation->return_value = frida_session_join_portal_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (fdn_session_join_portal_tsfn, operation, napi_tsfn_blocking);
}

static void
fdn_session_join_portal_deliver (napi_env env,
                                 napi_value js_cb,
                                 void * context,
                                 void * data)
{
  FdnSessionJoinPortalOperation * operation = data;

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
    result = fdn_portal_membership_to_value (env, operation->return_value);
    napi_resolve_deferred (env, operation->deferred, result);
  }

  fdn_session_join_portal_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_session_join_portal_tsfn);
}

static void
fdn_session_join_portal_operation_free (FdnSessionJoinPortalOperation * operation)
{
  g_free (operation->address);
  g_slice_free (FdnSessionJoinPortalOperation, operation);
}

static napi_value
fdn_session_get_pid (napi_env env,
                     napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaSession * handle;
  guint return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_session_get_pid (handle);

  result = fdn_uint_to_value (env, return_value);

  return result;
}

static napi_value
fdn_session_get_session (napi_env env,
                         napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaSession * handle;
  FridaAgentSession * return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_session_get_session (handle);

  result = fdn_agent_session_to_value (env, return_value);

  return result;
}

static napi_value
fdn_session_get_persist_timeout (napi_env env,
                                 napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaSession * handle;
  guint return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_session_get_persist_timeout (handle);

  result = fdn_uint_to_value (env, return_value);

  return result;
}

static napi_value
fdn_session_get_device (napi_env env,
                        napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaSession * handle;
  FridaDevice * return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_session_get_device (handle);

  result = fdn_device_to_value (env, return_value);

  return result;
}

static void
fdn_script_register (napi_env env,
                     napi_value exports)
{
  napi_property_descriptor properties[] =
  {
    { "isDestroyed", NULL, fdn_script_is_destroyed, NULL, NULL, NULL, napi_default, NULL },
    { "load", NULL, fdn_script_load, NULL, NULL, NULL, napi_default, NULL },
    { "unload", NULL, fdn_script_unload, NULL, NULL, NULL, napi_default, NULL },
    { "eternalize", NULL, fdn_script_eternalize, NULL, NULL, NULL, napi_default, NULL },
    { "post", NULL, fdn_script_post, NULL, NULL, NULL, napi_default, NULL },
    { "enableDebugger", NULL, fdn_script_enable_debugger, NULL, NULL, NULL, napi_default, NULL },
    { "disableDebugger", NULL, fdn_script_disable_debugger, NULL, NULL, NULL, napi_default, NULL },
    { "getId", NULL, fdn_script_get_id, NULL, NULL, NULL, napi_default, NULL },
    { "getSession", NULL, fdn_script_get_session, NULL, NULL, NULL, napi_default, NULL },
  };

  napi_value constructor;
  napi_define_class (env, "Script", NAPI_AUTO_LENGTH, fdn_script_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_script_constructor);

  napi_set_named_property (env, exports, "Script", constructor);

  napi_value resource_name;

  napi_create_string_utf8 (env, "load", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_script_load_deliver, &fdn_script_load_tsfn);

  napi_create_string_utf8 (env, "unload", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_script_unload_deliver, &fdn_script_unload_tsfn);

  napi_create_string_utf8 (env, "eternalize", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_script_eternalize_deliver, &fdn_script_eternalize_tsfn);

  napi_create_string_utf8 (env, "enableDebugger", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_script_enable_debugger_deliver, &fdn_script_enable_debugger_tsfn);

  napi_create_string_utf8 (env, "disableDebugger", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_script_disable_debugger_deliver, &fdn_script_disable_debugger_tsfn);
}

static gboolean
fdn_script_from_value (napi_env env,
                       napi_value value,
                       FridaScript ** result)
{
  napi_status status;
  bool is_instance;
  FridaScript * handle;

  status = napi_check_object_type_tag (env, value, &fdn_script_type_tag, &is_instance);
  if (status != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of Script");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) &handle);

  g_object_ref (handle);
  *result = handle;

  return TRUE;
}

static napi_value
fdn_script_to_value (napi_env env,
                     FridaScript * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_script_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_script_construct (napi_env env,
                      napi_callback_info info)
{
  napi_throw_error (env, NULL, "class Script cannot be constructed because it lacks a default constructor");
  return NULL;
}

static napi_value
fdn_script_is_destroyed (napi_env env,
                         napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaScript * handle;
  gboolean return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_script_is_destroyed (handle);

  result = fdn_boolean_to_value (env, return_value);

  return result;
}

static napi_value
fdn_script_load (napi_env env,
                 napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaScript * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnScriptLoadOperation * operation;
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

  operation = g_slice_new0 (FdnScriptLoadOperation);
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
  g_source_set_callback (source, fdn_script_load_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, fdn_script_load_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    fdn_script_load_operation_free (operation);
    return NULL;
  }
}

static gboolean
fdn_script_load_begin (gpointer user_data)
{
  FdnScriptLoadOperation * operation = user_data;

  frida_script_load (operation->handle,
      operation->cancellable,
      fdn_script_load_end, operation);

  return G_SOURCE_REMOVE;
}

static void
fdn_script_load_end (GObject * source_object,
                     GAsyncResult * res,
                     gpointer user_data)
{
  FdnScriptLoadOperation * operation = user_data;

  frida_script_load_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (fdn_script_load_tsfn, operation, napi_tsfn_blocking);
}

static void
fdn_script_load_deliver (napi_env env,
                         napi_value js_cb,
                         void * context,
                         void * data)
{
  FdnScriptLoadOperation * operation = data;

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

  fdn_script_load_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_script_load_tsfn);
}

static void
fdn_script_load_operation_free (FdnScriptLoadOperation * operation)
{
  g_slice_free (FdnScriptLoadOperation, operation);
}

static napi_value
fdn_script_unload (napi_env env,
                   napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaScript * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnScriptUnloadOperation * operation;
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

  operation = g_slice_new0 (FdnScriptUnloadOperation);
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
  g_source_set_callback (source, fdn_script_unload_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, fdn_script_unload_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    fdn_script_unload_operation_free (operation);
    return NULL;
  }
}

static gboolean
fdn_script_unload_begin (gpointer user_data)
{
  FdnScriptUnloadOperation * operation = user_data;

  frida_script_unload (operation->handle,
      operation->cancellable,
      fdn_script_unload_end, operation);

  return G_SOURCE_REMOVE;
}

static void
fdn_script_unload_end (GObject * source_object,
                       GAsyncResult * res,
                       gpointer user_data)
{
  FdnScriptUnloadOperation * operation = user_data;

  frida_script_unload_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (fdn_script_unload_tsfn, operation, napi_tsfn_blocking);
}

static void
fdn_script_unload_deliver (napi_env env,
                           napi_value js_cb,
                           void * context,
                           void * data)
{
  FdnScriptUnloadOperation * operation = data;

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

  fdn_script_unload_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_script_unload_tsfn);
}

static void
fdn_script_unload_operation_free (FdnScriptUnloadOperation * operation)
{
  g_slice_free (FdnScriptUnloadOperation, operation);
}

static napi_value
fdn_script_eternalize (napi_env env,
                       napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaScript * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnScriptEternalizeOperation * operation;
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

  operation = g_slice_new0 (FdnScriptEternalizeOperation);
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
  g_source_set_callback (source, fdn_script_eternalize_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, fdn_script_eternalize_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    fdn_script_eternalize_operation_free (operation);
    return NULL;
  }
}

static gboolean
fdn_script_eternalize_begin (gpointer user_data)
{
  FdnScriptEternalizeOperation * operation = user_data;

  frida_script_eternalize (operation->handle,
      operation->cancellable,
      fdn_script_eternalize_end, operation);

  return G_SOURCE_REMOVE;
}

static void
fdn_script_eternalize_end (GObject * source_object,
                           GAsyncResult * res,
                           gpointer user_data)
{
  FdnScriptEternalizeOperation * operation = user_data;

  frida_script_eternalize_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (fdn_script_eternalize_tsfn, operation, napi_tsfn_blocking);
}

static void
fdn_script_eternalize_deliver (napi_env env,
                               napi_value js_cb,
                               void * context,
                               void * data)
{
  FdnScriptEternalizeOperation * operation = data;

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

  fdn_script_eternalize_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_script_eternalize_tsfn);
}

static void
fdn_script_eternalize_operation_free (FdnScriptEternalizeOperation * operation)
{
  g_slice_free (FdnScriptEternalizeOperation, operation);
}

static napi_value
fdn_script_post (napi_env env,
                 napi_callback_info info)
{
  napi_value result;
  size_t argc = 2;
  napi_value args[2];
  napi_status status;
  napi_value jsthis;
  FridaScript * handle;
  gchar * json;
  GBytes * data;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  if (argc > 0)
  {
    if (!fdn_utf8_from_value (env, args[0], &json))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: json");
    goto invalid_argument;
  }
  if (argc > 1)
  {
    if (!fdn_bytes_from_value (env, args[1], &data))
      goto invalid_argument;
  }
  else
  {
    data = NULL;
  }

  frida_script_post (handle, json, data);

  
  g_free (operation->json);napi_get_undefined (env, &result);

  return result;

invalid_argument:
  {
    
  g_free (operation->json);return NULL;
  }
}

static napi_value
fdn_script_enable_debugger (napi_env env,
                            napi_callback_info info)
{
  size_t argc = 2;
  napi_value args[2];
  napi_status status;
  napi_value jsthis;
  FridaScript * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnScriptEnableDebuggerOperation * operation;
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

  operation = g_slice_new0 (FdnScriptEnableDebuggerOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0)
  {
    if (!fdn_uint16_from_value (env, args[0], &operation->port))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: port");
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
  g_source_set_callback (source, fdn_script_enable_debugger_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, fdn_script_enable_debugger_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    fdn_script_enable_debugger_operation_free (operation);
    return NULL;
  }
}

static gboolean
fdn_script_enable_debugger_begin (gpointer user_data)
{
  FdnScriptEnableDebuggerOperation * operation = user_data;

  frida_script_enable_debugger (operation->handle,
      operation->port, operation->cancellable,
      fdn_script_enable_debugger_end, operation);

  return G_SOURCE_REMOVE;
}

static void
fdn_script_enable_debugger_end (GObject * source_object,
                                GAsyncResult * res,
                                gpointer user_data)
{
  FdnScriptEnableDebuggerOperation * operation = user_data;

  frida_script_enable_debugger_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (fdn_script_enable_debugger_tsfn, operation, napi_tsfn_blocking);
}

static void
fdn_script_enable_debugger_deliver (napi_env env,
                                    napi_value js_cb,
                                    void * context,
                                    void * data)
{
  FdnScriptEnableDebuggerOperation * operation = data;

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

  fdn_script_enable_debugger_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_script_enable_debugger_tsfn);
}

static void
fdn_script_enable_debugger_operation_free (FdnScriptEnableDebuggerOperation * operation)
{
  g_slice_free (FdnScriptEnableDebuggerOperation, operation);
}

static napi_value
fdn_script_disable_debugger (napi_env env,
                             napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaScript * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnScriptDisableDebuggerOperation * operation;
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

  operation = g_slice_new0 (FdnScriptDisableDebuggerOperation);
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
  g_source_set_callback (source, fdn_script_disable_debugger_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, fdn_script_disable_debugger_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    fdn_script_disable_debugger_operation_free (operation);
    return NULL;
  }
}

static gboolean
fdn_script_disable_debugger_begin (gpointer user_data)
{
  FdnScriptDisableDebuggerOperation * operation = user_data;

  frida_script_disable_debugger (operation->handle,
      operation->cancellable,
      fdn_script_disable_debugger_end, operation);

  return G_SOURCE_REMOVE;
}

static void
fdn_script_disable_debugger_end (GObject * source_object,
                                 GAsyncResult * res,
                                 gpointer user_data)
{
  FdnScriptDisableDebuggerOperation * operation = user_data;

  frida_script_disable_debugger_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (fdn_script_disable_debugger_tsfn, operation, napi_tsfn_blocking);
}

static void
fdn_script_disable_debugger_deliver (napi_env env,
                                     napi_value js_cb,
                                     void * context,
                                     void * data)
{
  FdnScriptDisableDebuggerOperation * operation = data;

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

  fdn_script_disable_debugger_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_script_disable_debugger_tsfn);
}

static void
fdn_script_disable_debugger_operation_free (FdnScriptDisableDebuggerOperation * operation)
{
  g_slice_free (FdnScriptDisableDebuggerOperation, operation);
}

static napi_value
fdn_script_get_id (napi_env env,
                   napi_callback_info info)
{
  napi_value result;
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaScript * handle;
  FridaAgentScriptId * result;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  if (argc > 0)
  {
    if (!fdn_agent_script_id_from_value (env, args[0], &result))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: result");
    goto invalid_argument;
  }

  frida_script_get_id (handle, result);

  napi_get_undefined (env, &result);

  return result;

invalid_argument:
  {
    return NULL;
  }
}

static napi_value
fdn_script_get_session (napi_env env,
                        napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaScript * handle;
  FridaSession * return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_script_get_session (handle);

  result = fdn_session_to_value (env, return_value);

  return result;
}

static void
fdn_portal_membership_register (napi_env env,
                                napi_value exports)
{
  napi_property_descriptor properties[] =
  {
    { "terminate", NULL, fdn_portal_membership_terminate, NULL, NULL, NULL, napi_default, NULL },
    { "getId", NULL, fdn_portal_membership_get_id, NULL, NULL, NULL, napi_default, NULL },
    { "getSession", NULL, fdn_portal_membership_get_session, NULL, NULL, NULL, napi_default, NULL },
  };

  napi_value constructor;
  napi_define_class (env, "PortalMembership", NAPI_AUTO_LENGTH, fdn_portal_membership_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_portal_membership_constructor);

  napi_set_named_property (env, exports, "PortalMembership", constructor);

  napi_value resource_name;

  napi_create_string_utf8 (env, "terminate", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_portal_membership_terminate_deliver, &fdn_portal_membership_terminate_tsfn);
}

static gboolean
fdn_portal_membership_from_value (napi_env env,
                                  napi_value value,
                                  FridaPortalMembership ** result)
{
  napi_status status;
  bool is_instance;
  FridaPortalMembership * handle;

  status = napi_check_object_type_tag (env, value, &fdn_portal_membership_type_tag, &is_instance);
  if (status != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of PortalMembership");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) &handle);

  g_object_ref (handle);
  *result = handle;

  return TRUE;
}

static napi_value
fdn_portal_membership_to_value (napi_env env,
                                FridaPortalMembership * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_portal_membership_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_portal_membership_construct (napi_env env,
                                 napi_callback_info info)
{
  napi_throw_error (env, NULL, "class PortalMembership cannot be constructed because it lacks a default constructor");
  return NULL;
}

static napi_value
fdn_portal_membership_terminate (napi_env env,
                                 napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaPortalMembership * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnPortalMembershipTerminateOperation * operation;
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

  operation = g_slice_new0 (FdnPortalMembershipTerminateOperation);
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
  g_source_set_callback (source, fdn_portal_membership_terminate_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, fdn_portal_membership_terminate_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    fdn_portal_membership_terminate_operation_free (operation);
    return NULL;
  }
}

static gboolean
fdn_portal_membership_terminate_begin (gpointer user_data)
{
  FdnPortalMembershipTerminateOperation * operation = user_data;

  frida_portal_membership_terminate (operation->handle,
      operation->cancellable,
      fdn_portal_membership_terminate_end, operation);

  return G_SOURCE_REMOVE;
}

static void
fdn_portal_membership_terminate_end (GObject * source_object,
                                     GAsyncResult * res,
                                     gpointer user_data)
{
  FdnPortalMembershipTerminateOperation * operation = user_data;

  frida_portal_membership_terminate_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (fdn_portal_membership_terminate_tsfn, operation, napi_tsfn_blocking);
}

static void
fdn_portal_membership_terminate_deliver (napi_env env,
                                         napi_value js_cb,
                                         void * context,
                                         void * data)
{
  FdnPortalMembershipTerminateOperation * operation = data;

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

  fdn_portal_membership_terminate_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_portal_membership_terminate_tsfn);
}

static void
fdn_portal_membership_terminate_operation_free (FdnPortalMembershipTerminateOperation * operation)
{
  g_slice_free (FdnPortalMembershipTerminateOperation, operation);
}

static napi_value
fdn_portal_membership_get_id (napi_env env,
                              napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaPortalMembership * handle;
  guint return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_portal_membership_get_id (handle);

  result = fdn_uint_to_value (env, return_value);

  return result;
}

static napi_value
fdn_portal_membership_get_session (napi_env env,
                                   napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaPortalMembership * handle;
  FridaSession * return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_portal_membership_get_session (handle);

  result = fdn_session_to_value (env, return_value);

  return result;
}

static void
fdn_control_service_options_register (napi_env env,
                                      napi_value exports)
{
  napi_property_descriptor properties[] =
  {
    { "getSysroot", NULL, fdn_control_service_options_get_sysroot, NULL, NULL, NULL, napi_default, NULL },
    { "setSysroot", NULL, fdn_control_service_options_set_sysroot, NULL, NULL, NULL, napi_default, NULL },
    { "getEnablePreload", NULL, fdn_control_service_options_get_enable_preload, NULL, NULL, NULL, napi_default, NULL },
    { "setEnablePreload", NULL, fdn_control_service_options_set_enable_preload, NULL, NULL, NULL, napi_default, NULL },
    { "getReportCrashes", NULL, fdn_control_service_options_get_report_crashes, NULL, NULL, NULL, napi_default, NULL },
    { "setReportCrashes", NULL, fdn_control_service_options_set_report_crashes, NULL, NULL, NULL, napi_default, NULL },
  };

  napi_value constructor;
  napi_define_class (env, "ControlServiceOptions", NAPI_AUTO_LENGTH, fdn_control_service_options_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_control_service_options_constructor);

  napi_set_named_property (env, exports, "ControlServiceOptions", constructor);
}

static gboolean
fdn_control_service_options_from_value (napi_env env,
                                        napi_value value,
                                        FridaControlServiceOptions ** result)
{
  napi_status status;
  bool is_instance;
  FridaControlServiceOptions * handle;

  status = napi_check_object_type_tag (env, value, &fdn_control_service_options_type_tag, &is_instance);
  if (status != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of ControlServiceOptions");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) &handle);

  g_object_ref (handle);
  *result = handle;

  return TRUE;
}

static napi_value
fdn_control_service_options_to_value (napi_env env,
                                      FridaControlServiceOptions * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_control_service_options_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_control_service_options_construct (napi_env env,
                                       napi_callback_info info)
{
  size_t argc = 0;
  napi_value jsthis;
  napi_status status;
  FridaControlServiceOptions * handle;

  status = napi_get_cb_info (env, info, &argc, NULL, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  handle = frida_control_service_options_new ();

  status = napi_type_tag_object (env, jsthis, &fdn_control_service_options_type_tag);
  if (status != napi_ok)
    return NULL;

  status = napi_wrap (env, jsthis, handle, NULL, NULL, NULL);
  if (status != napi_ok)
    return NULL;

  return jsthis;
}

static napi_value
fdn_control_service_options_get_sysroot (napi_env env,
                                         napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaControlServiceOptions * handle;
  gchar * return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_control_service_options_get_sysroot (handle);

  result = fdn_utf8_to_value (env, return_value);

  return result;
}

static napi_value
fdn_control_service_options_set_sysroot (napi_env env,
                                         napi_callback_info info)
{
  napi_value result;
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaControlServiceOptions * handle;
  gchar * value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  if (argc > 0)
  {
    if (!fdn_utf8_from_value (env, args[0], &value))
      goto invalid_argument;
  }
  else
  {
    value = NULL;
  }

  frida_control_service_options_set_sysroot (handle, value);

  
  g_free (operation->value);napi_get_undefined (env, &result);

  return result;

invalid_argument:
  {
    
  g_free (operation->value);return NULL;
  }
}

static napi_value
fdn_control_service_options_get_enable_preload (napi_env env,
                                                napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaControlServiceOptions * handle;
  gboolean return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_control_service_options_get_enable_preload (handle);

  result = fdn_boolean_to_value (env, return_value);

  return result;
}

static napi_value
fdn_control_service_options_set_enable_preload (napi_env env,
                                                napi_callback_info info)
{
  napi_value result;
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaControlServiceOptions * handle;
  gboolean value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  if (argc > 0)
  {
    if (!fdn_boolean_from_value (env, args[0], &value))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: value");
    goto invalid_argument;
  }

  frida_control_service_options_set_enable_preload (handle, value);

  napi_get_undefined (env, &result);

  return result;

invalid_argument:
  {
    return NULL;
  }
}

static napi_value
fdn_control_service_options_get_report_crashes (napi_env env,
                                                napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaControlServiceOptions * handle;
  gboolean return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_control_service_options_get_report_crashes (handle);

  result = fdn_boolean_to_value (env, return_value);

  return result;
}

static napi_value
fdn_control_service_options_set_report_crashes (napi_env env,
                                                napi_callback_info info)
{
  napi_value result;
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaControlServiceOptions * handle;
  gboolean value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  if (argc > 0)
  {
    if (!fdn_boolean_from_value (env, args[0], &value))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: value");
    goto invalid_argument;
  }

  frida_control_service_options_set_report_crashes (handle, value);

  napi_get_undefined (env, &result);

  return result;

invalid_argument:
  {
    return NULL;
  }
}

static void
fdn_portal_service_register (napi_env env,
                             napi_value exports)
{
  napi_property_descriptor properties[] =
  {
    { "start", NULL, fdn_portal_service_start, NULL, NULL, NULL, napi_default, NULL },
    { "stop", NULL, fdn_portal_service_stop, NULL, NULL, NULL, napi_default, NULL },
    { "kick", NULL, fdn_portal_service_kick, NULL, NULL, NULL, napi_default, NULL },
    { "post", NULL, fdn_portal_service_post, NULL, NULL, NULL, napi_default, NULL },
    { "narrowcast", NULL, fdn_portal_service_narrowcast, NULL, NULL, NULL, napi_default, NULL },
    { "broadcast", NULL, fdn_portal_service_broadcast, NULL, NULL, NULL, napi_default, NULL },
    { "enumerateTags", NULL, fdn_portal_service_enumerate_tags, NULL, NULL, NULL, napi_default, NULL },
    { "tag", NULL, fdn_portal_service_tag, NULL, NULL, NULL, napi_default, NULL },
    { "untag", NULL, fdn_portal_service_untag, NULL, NULL, NULL, napi_default, NULL },
    { "getDevice", NULL, fdn_portal_service_get_device, NULL, NULL, NULL, napi_default, NULL },
    { "getClusterParams", NULL, fdn_portal_service_get_cluster_params, NULL, NULL, NULL, napi_default, NULL },
    { "getControlParams", NULL, fdn_portal_service_get_control_params, NULL, NULL, NULL, napi_default, NULL },
  };

  napi_value constructor;
  napi_define_class (env, "PortalService", NAPI_AUTO_LENGTH, fdn_portal_service_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_portal_service_constructor);

  napi_set_named_property (env, exports, "PortalService", constructor);

  napi_value resource_name;

  napi_create_string_utf8 (env, "start", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_portal_service_start_deliver, &fdn_portal_service_start_tsfn);

  napi_create_string_utf8 (env, "stop", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_portal_service_stop_deliver, &fdn_portal_service_stop_tsfn);
}

static gboolean
fdn_portal_service_from_value (napi_env env,
                               napi_value value,
                               FridaPortalService ** result)
{
  napi_status status;
  bool is_instance;
  FridaPortalService * handle;

  status = napi_check_object_type_tag (env, value, &fdn_portal_service_type_tag, &is_instance);
  if (status != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of PortalService");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) &handle);

  g_object_ref (handle);
  *result = handle;

  return TRUE;
}

static napi_value
fdn_portal_service_to_value (napi_env env,
                             FridaPortalService * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_portal_service_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_portal_service_construct (napi_env env,
                              napi_callback_info info)
{
  napi_throw_error (env, NULL, "class PortalService cannot be constructed because it lacks a default constructor");
  return NULL;
}

static napi_value
fdn_portal_service_start (napi_env env,
                          napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaPortalService * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnPortalServiceStartOperation * operation;
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

  operation = g_slice_new0 (FdnPortalServiceStartOperation);
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
  g_source_set_callback (source, fdn_portal_service_start_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, fdn_portal_service_start_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    fdn_portal_service_start_operation_free (operation);
    return NULL;
  }
}

static gboolean
fdn_portal_service_start_begin (gpointer user_data)
{
  FdnPortalServiceStartOperation * operation = user_data;

  frida_portal_service_start (operation->handle,
      operation->cancellable,
      fdn_portal_service_start_end, operation);

  return G_SOURCE_REMOVE;
}

static void
fdn_portal_service_start_end (GObject * source_object,
                              GAsyncResult * res,
                              gpointer user_data)
{
  FdnPortalServiceStartOperation * operation = user_data;

  frida_portal_service_start_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (fdn_portal_service_start_tsfn, operation, napi_tsfn_blocking);
}

static void
fdn_portal_service_start_deliver (napi_env env,
                                  napi_value js_cb,
                                  void * context,
                                  void * data)
{
  FdnPortalServiceStartOperation * operation = data;

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

  fdn_portal_service_start_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_portal_service_start_tsfn);
}

static void
fdn_portal_service_start_operation_free (FdnPortalServiceStartOperation * operation)
{
  g_slice_free (FdnPortalServiceStartOperation, operation);
}

static napi_value
fdn_portal_service_stop (napi_env env,
                         napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaPortalService * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnPortalServiceStopOperation * operation;
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

  operation = g_slice_new0 (FdnPortalServiceStopOperation);
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
  g_source_set_callback (source, fdn_portal_service_stop_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, fdn_portal_service_stop_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    fdn_portal_service_stop_operation_free (operation);
    return NULL;
  }
}

static gboolean
fdn_portal_service_stop_begin (gpointer user_data)
{
  FdnPortalServiceStopOperation * operation = user_data;

  frida_portal_service_stop (operation->handle,
      operation->cancellable,
      fdn_portal_service_stop_end, operation);

  return G_SOURCE_REMOVE;
}

static void
fdn_portal_service_stop_end (GObject * source_object,
                             GAsyncResult * res,
                             gpointer user_data)
{
  FdnPortalServiceStopOperation * operation = user_data;

  frida_portal_service_stop_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (fdn_portal_service_stop_tsfn, operation, napi_tsfn_blocking);
}

static void
fdn_portal_service_stop_deliver (napi_env env,
                                 napi_value js_cb,
                                 void * context,
                                 void * data)
{
  FdnPortalServiceStopOperation * operation = data;

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

  fdn_portal_service_stop_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_portal_service_stop_tsfn);
}

static void
fdn_portal_service_stop_operation_free (FdnPortalServiceStopOperation * operation)
{
  g_slice_free (FdnPortalServiceStopOperation, operation);
}

static napi_value
fdn_portal_service_kick (napi_env env,
                         napi_callback_info info)
{
  napi_value result;
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaPortalService * handle;
  guint connection_id;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  if (argc > 0)
  {
    if (!fdn_uint_from_value (env, args[0], &connection_id))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: connectionId");
    goto invalid_argument;
  }

  frida_portal_service_kick (handle, connection_id);

  napi_get_undefined (env, &result);

  return result;

invalid_argument:
  {
    return NULL;
  }
}

static napi_value
fdn_portal_service_post (napi_env env,
                         napi_callback_info info)
{
  napi_value result;
  size_t argc = 3;
  napi_value args[3];
  napi_status status;
  napi_value jsthis;
  FridaPortalService * handle;
  guint connection_id;
  gchar * json;
  GBytes * data;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  if (argc > 0)
  {
    if (!fdn_uint_from_value (env, args[0], &connection_id))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: connectionId");
    goto invalid_argument;
  }
  if (argc > 1)
  {
    if (!fdn_utf8_from_value (env, args[1], &json))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: json");
    goto invalid_argument;
  }
  if (argc > 2)
  {
    if (!fdn_bytes_from_value (env, args[2], &data))
      goto invalid_argument;
  }
  else
  {
    data = NULL;
  }

  frida_portal_service_post (handle, connection_id, json, data);

  
  g_free (operation->json);napi_get_undefined (env, &result);

  return result;

invalid_argument:
  {
    
  g_free (operation->json);return NULL;
  }
}

static napi_value
fdn_portal_service_narrowcast (napi_env env,
                               napi_callback_info info)
{
  napi_value result;
  size_t argc = 3;
  napi_value args[3];
  napi_status status;
  napi_value jsthis;
  FridaPortalService * handle;
  gchar * tag;
  gchar * json;
  GBytes * data;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  if (argc > 0)
  {
    if (!fdn_utf8_from_value (env, args[0], &tag))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: tag");
    goto invalid_argument;
  }
  if (argc > 1)
  {
    if (!fdn_utf8_from_value (env, args[1], &json))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: json");
    goto invalid_argument;
  }
  if (argc > 2)
  {
    if (!fdn_bytes_from_value (env, args[2], &data))
      goto invalid_argument;
  }
  else
  {
    data = NULL;
  }

  frida_portal_service_narrowcast (handle, tag, json, data);

  
  g_free (operation->tag);
  g_free (operation->json);napi_get_undefined (env, &result);

  return result;

invalid_argument:
  {
    
  g_free (operation->tag);
  g_free (operation->json);return NULL;
  }
}

static napi_value
fdn_portal_service_broadcast (napi_env env,
                              napi_callback_info info)
{
  napi_value result;
  size_t argc = 2;
  napi_value args[2];
  napi_status status;
  napi_value jsthis;
  FridaPortalService * handle;
  gchar * json;
  GBytes * data;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  if (argc > 0)
  {
    if (!fdn_utf8_from_value (env, args[0], &json))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: json");
    goto invalid_argument;
  }
  if (argc > 1)
  {
    if (!fdn_bytes_from_value (env, args[1], &data))
      goto invalid_argument;
  }
  else
  {
    data = NULL;
  }

  frida_portal_service_broadcast (handle, json, data);

  
  g_free (operation->json);napi_get_undefined (env, &result);

  return result;

invalid_argument:
  {
    
  g_free (operation->json);return NULL;
  }
}

static napi_value
fdn_portal_service_enumerate_tags (napi_env env,
                                   napi_callback_info info)
{
  napi_value result;
  size_t argc = 2;
  napi_value args[2];
  napi_status status;
  napi_value jsthis;
  FridaPortalService * handle;
  guint connection_id;
  gint * result_length1;
  gchar ** return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  if (argc > 0)
  {
    if (!fdn_uint_from_value (env, args[0], &connection_id))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: connectionId");
    goto invalid_argument;
  }
  if (argc > 1)
  {
    if (!fdn_int_from_value (env, args[1], &result_length1))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: resultLength1");
    goto invalid_argument;
  }

  return_value = frida_portal_service_enumerate_tags (handle, connection_id, result_length1);

  result = fdn_strv_to_value (env, return_value);

  return result;

invalid_argument:
  {
    return NULL;
  }
}

static napi_value
fdn_portal_service_tag (napi_env env,
                        napi_callback_info info)
{
  napi_value result;
  size_t argc = 2;
  napi_value args[2];
  napi_status status;
  napi_value jsthis;
  FridaPortalService * handle;
  guint connection_id;
  gchar * tag;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  if (argc > 0)
  {
    if (!fdn_uint_from_value (env, args[0], &connection_id))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: connectionId");
    goto invalid_argument;
  }
  if (argc > 1)
  {
    if (!fdn_utf8_from_value (env, args[1], &tag))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: tag");
    goto invalid_argument;
  }

  frida_portal_service_tag (handle, connection_id, tag);

  
  g_free (operation->tag);napi_get_undefined (env, &result);

  return result;

invalid_argument:
  {
    
  g_free (operation->tag);return NULL;
  }
}

static napi_value
fdn_portal_service_untag (napi_env env,
                          napi_callback_info info)
{
  napi_value result;
  size_t argc = 2;
  napi_value args[2];
  napi_status status;
  napi_value jsthis;
  FridaPortalService * handle;
  guint connection_id;
  gchar * tag;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  if (argc > 0)
  {
    if (!fdn_uint_from_value (env, args[0], &connection_id))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: connectionId");
    goto invalid_argument;
  }
  if (argc > 1)
  {
    if (!fdn_utf8_from_value (env, args[1], &tag))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: tag");
    goto invalid_argument;
  }

  frida_portal_service_untag (handle, connection_id, tag);

  
  g_free (operation->tag);napi_get_undefined (env, &result);

  return result;

invalid_argument:
  {
    
  g_free (operation->tag);return NULL;
  }
}

static napi_value
fdn_portal_service_get_device (napi_env env,
                               napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaPortalService * handle;
  FridaDevice * return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_portal_service_get_device (handle);

  result = fdn_device_to_value (env, return_value);

  return result;
}

static napi_value
fdn_portal_service_get_cluster_params (napi_env env,
                                       napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaPortalService * handle;
  FridaEndpointParameters * return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_portal_service_get_cluster_params (handle);

  result = fdn_endpoint_parameters_to_value (env, return_value);

  return result;
}

static napi_value
fdn_portal_service_get_control_params (napi_env env,
                                       napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaPortalService * handle;
  FridaEndpointParameters * return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_portal_service_get_control_params (handle);

  result = fdn_endpoint_parameters_to_value (env, return_value);

  return result;
}

static void
fdn_file_monitor_register (napi_env env,
                           napi_value exports)
{
  napi_property_descriptor properties[] =
  {
    { "enable", NULL, fdn_file_monitor_enable, NULL, NULL, NULL, napi_default, NULL },
    { "disable", NULL, fdn_file_monitor_disable, NULL, NULL, NULL, napi_default, NULL },
    { "getPath", NULL, fdn_file_monitor_get_path, NULL, NULL, NULL, napi_default, NULL },
  };

  napi_value constructor;
  napi_define_class (env, "FileMonitor", NAPI_AUTO_LENGTH, fdn_file_monitor_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_file_monitor_constructor);

  napi_set_named_property (env, exports, "FileMonitor", constructor);

  napi_value resource_name;

  napi_create_string_utf8 (env, "enable", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_file_monitor_enable_deliver, &fdn_file_monitor_enable_tsfn);

  napi_create_string_utf8 (env, "disable", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_file_monitor_disable_deliver, &fdn_file_monitor_disable_tsfn);
}

static gboolean
fdn_file_monitor_from_value (napi_env env,
                             napi_value value,
                             FridaFileMonitor ** result)
{
  napi_status status;
  bool is_instance;
  FridaFileMonitor * handle;

  status = napi_check_object_type_tag (env, value, &fdn_file_monitor_type_tag, &is_instance);
  if (status != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of FileMonitor");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) &handle);

  g_object_ref (handle);
  *result = handle;

  return TRUE;
}

static napi_value
fdn_file_monitor_to_value (napi_env env,
                           FridaFileMonitor * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_file_monitor_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_file_monitor_construct (napi_env env,
                            napi_callback_info info)
{
  napi_throw_error (env, NULL, "class FileMonitor cannot be constructed because it lacks a default constructor");
  return NULL;
}

static napi_value
fdn_file_monitor_enable (napi_env env,
                         napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaFileMonitor * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnFileMonitorEnableOperation * operation;
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

  operation = g_slice_new0 (FdnFileMonitorEnableOperation);
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
  g_source_set_callback (source, fdn_file_monitor_enable_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, fdn_file_monitor_enable_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    fdn_file_monitor_enable_operation_free (operation);
    return NULL;
  }
}

static gboolean
fdn_file_monitor_enable_begin (gpointer user_data)
{
  FdnFileMonitorEnableOperation * operation = user_data;

  frida_file_monitor_enable (operation->handle,
      operation->cancellable,
      fdn_file_monitor_enable_end, operation);

  return G_SOURCE_REMOVE;
}

static void
fdn_file_monitor_enable_end (GObject * source_object,
                             GAsyncResult * res,
                             gpointer user_data)
{
  FdnFileMonitorEnableOperation * operation = user_data;

  frida_file_monitor_enable_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (fdn_file_monitor_enable_tsfn, operation, napi_tsfn_blocking);
}

static void
fdn_file_monitor_enable_deliver (napi_env env,
                                 napi_value js_cb,
                                 void * context,
                                 void * data)
{
  FdnFileMonitorEnableOperation * operation = data;

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

  fdn_file_monitor_enable_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_file_monitor_enable_tsfn);
}

static void
fdn_file_monitor_enable_operation_free (FdnFileMonitorEnableOperation * operation)
{
  g_slice_free (FdnFileMonitorEnableOperation, operation);
}

static napi_value
fdn_file_monitor_disable (napi_env env,
                          napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaFileMonitor * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnFileMonitorDisableOperation * operation;
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

  operation = g_slice_new0 (FdnFileMonitorDisableOperation);
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
  g_source_set_callback (source, fdn_file_monitor_disable_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, fdn_file_monitor_disable_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    fdn_file_monitor_disable_operation_free (operation);
    return NULL;
  }
}

static gboolean
fdn_file_monitor_disable_begin (gpointer user_data)
{
  FdnFileMonitorDisableOperation * operation = user_data;

  frida_file_monitor_disable (operation->handle,
      operation->cancellable,
      fdn_file_monitor_disable_end, operation);

  return G_SOURCE_REMOVE;
}

static void
fdn_file_monitor_disable_end (GObject * source_object,
                              GAsyncResult * res,
                              gpointer user_data)
{
  FdnFileMonitorDisableOperation * operation = user_data;

  frida_file_monitor_disable_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (fdn_file_monitor_disable_tsfn, operation, napi_tsfn_blocking);
}

static void
fdn_file_monitor_disable_deliver (napi_env env,
                                  napi_value js_cb,
                                  void * context,
                                  void * data)
{
  FdnFileMonitorDisableOperation * operation = data;

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

  fdn_file_monitor_disable_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_file_monitor_disable_tsfn);
}

static void
fdn_file_monitor_disable_operation_free (FdnFileMonitorDisableOperation * operation)
{
  g_slice_free (FdnFileMonitorDisableOperation, operation);
}

static napi_value
fdn_file_monitor_get_path (napi_env env,
                           napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaFileMonitor * handle;
  gchar * return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_file_monitor_get_path (handle);

  result = fdn_utf8_to_value (env, return_value);

  return result;
}

static void
fdn_compiler_register (napi_env env,
                       napi_value exports)
{
  napi_property_descriptor properties[] =
  {
    { "build", NULL, fdn_compiler_build, NULL, NULL, NULL, napi_default, NULL },
    { "watch", NULL, fdn_compiler_watch, NULL, NULL, NULL, napi_default, NULL },
    { "getManager", NULL, fdn_compiler_get_manager, NULL, NULL, NULL, napi_default, NULL },
  };

  napi_value constructor;
  napi_define_class (env, "Compiler", NAPI_AUTO_LENGTH, fdn_compiler_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_compiler_constructor);

  napi_set_named_property (env, exports, "Compiler", constructor);

  napi_value resource_name;

  napi_create_string_utf8 (env, "build", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_compiler_build_deliver, &fdn_compiler_build_tsfn);

  napi_create_string_utf8 (env, "watch", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_compiler_watch_deliver, &fdn_compiler_watch_tsfn);
}

static gboolean
fdn_compiler_from_value (napi_env env,
                         napi_value value,
                         FridaCompiler ** result)
{
  napi_status status;
  bool is_instance;
  FridaCompiler * handle;

  status = napi_check_object_type_tag (env, value, &fdn_compiler_type_tag, &is_instance);
  if (status != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of Compiler");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) &handle);

  g_object_ref (handle);
  *result = handle;

  return TRUE;
}

static napi_value
fdn_compiler_to_value (napi_env env,
                       FridaCompiler * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_compiler_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_compiler_construct (napi_env env,
                        napi_callback_info info)
{
  napi_throw_error (env, NULL, "class Compiler cannot be constructed because it lacks a default constructor");
  return NULL;
}

static napi_value
fdn_compiler_build (napi_env env,
                    napi_callback_info info)
{
  size_t argc = 3;
  napi_value args[3];
  napi_status status;
  napi_value jsthis;
  FridaCompiler * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnCompilerBuildOperation * operation;
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

  operation = g_slice_new0 (FdnCompilerBuildOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0)
  {
    if (!fdn_utf8_from_value (env, args[0], &operation->entrypoint))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: entrypoint");
    goto invalid_argument;
  }

  if (argc > 1)
  {
    if (!fdn_build_options_from_value (env, args[1], &operation->options))
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
  g_source_set_callback (source, fdn_compiler_build_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, fdn_compiler_build_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    fdn_compiler_build_operation_free (operation);
    return NULL;
  }
}

static gboolean
fdn_compiler_build_begin (gpointer user_data)
{
  FdnCompilerBuildOperation * operation = user_data;

  frida_compiler_build (operation->handle,
      operation->entrypoint, operation->options, operation->cancellable,
      fdn_compiler_build_end, operation);

  return G_SOURCE_REMOVE;
}

static void
fdn_compiler_build_end (GObject * source_object,
                        GAsyncResult * res,
                        gpointer user_data)
{
  FdnCompilerBuildOperation * operation = user_data;

  

  operation->return_value = frida_compiler_build_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (fdn_compiler_build_tsfn, operation, napi_tsfn_blocking);
}

static void
fdn_compiler_build_deliver (napi_env env,
                            napi_value js_cb,
                            void * context,
                            void * data)
{
  FdnCompilerBuildOperation * operation = data;

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
    result = fdn_utf8_to_value (env, operation->return_value);
    napi_resolve_deferred (env, operation->deferred, result);
  }

  fdn_compiler_build_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_compiler_build_tsfn);
}

static void
fdn_compiler_build_operation_free (FdnCompilerBuildOperation * operation)
{
  g_free (operation->entrypoint);
  g_free (operation->return_value);
  g_slice_free (FdnCompilerBuildOperation, operation);
}

static napi_value
fdn_compiler_watch (napi_env env,
                    napi_callback_info info)
{
  size_t argc = 3;
  napi_value args[3];
  napi_status status;
  napi_value jsthis;
  FridaCompiler * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnCompilerWatchOperation * operation;
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

  operation = g_slice_new0 (FdnCompilerWatchOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0)
  {
    if (!fdn_utf8_from_value (env, args[0], &operation->entrypoint))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: entrypoint");
    goto invalid_argument;
  }

  if (argc > 1)
  {
    if (!fdn_watch_options_from_value (env, args[1], &operation->options))
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
  g_source_set_callback (source, fdn_compiler_watch_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, fdn_compiler_watch_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    fdn_compiler_watch_operation_free (operation);
    return NULL;
  }
}

static gboolean
fdn_compiler_watch_begin (gpointer user_data)
{
  FdnCompilerWatchOperation * operation = user_data;

  frida_compiler_watch (operation->handle,
      operation->entrypoint, operation->options, operation->cancellable,
      fdn_compiler_watch_end, operation);

  return G_SOURCE_REMOVE;
}

static void
fdn_compiler_watch_end (GObject * source_object,
                        GAsyncResult * res,
                        gpointer user_data)
{
  FdnCompilerWatchOperation * operation = user_data;

  frida_compiler_watch_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (fdn_compiler_watch_tsfn, operation, napi_tsfn_blocking);
}

static void
fdn_compiler_watch_deliver (napi_env env,
                            napi_value js_cb,
                            void * context,
                            void * data)
{
  FdnCompilerWatchOperation * operation = data;

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

  fdn_compiler_watch_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_compiler_watch_tsfn);
}

static void
fdn_compiler_watch_operation_free (FdnCompilerWatchOperation * operation)
{
  g_free (operation->entrypoint);
  g_slice_free (FdnCompilerWatchOperation, operation);
}

static napi_value
fdn_compiler_get_manager (napi_env env,
                          napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaCompiler * handle;
  FridaDeviceManager * return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_compiler_get_manager (handle);

  result = fdn_device_manager_to_value (env, return_value);

  return result;
}

static void
fdn_compiler_options_register (napi_env env,
                               napi_value exports)
{
  napi_property_descriptor properties[] =
  {
    { "getProjectRoot", NULL, fdn_compiler_options_get_project_root, NULL, NULL, NULL, napi_default, NULL },
    { "setProjectRoot", NULL, fdn_compiler_options_set_project_root, NULL, NULL, NULL, napi_default, NULL },
    { "getSourceMaps", NULL, fdn_compiler_options_get_source_maps, NULL, NULL, NULL, napi_default, NULL },
    { "setSourceMaps", NULL, fdn_compiler_options_set_source_maps, NULL, NULL, NULL, napi_default, NULL },
    { "getCompression", NULL, fdn_compiler_options_get_compression, NULL, NULL, NULL, napi_default, NULL },
    { "setCompression", NULL, fdn_compiler_options_set_compression, NULL, NULL, NULL, napi_default, NULL },
  };

  napi_value constructor;
  napi_define_class (env, "CompilerOptions", NAPI_AUTO_LENGTH, fdn_compiler_options_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_compiler_options_constructor);

  napi_set_named_property (env, exports, "CompilerOptions", constructor);
}

static gboolean
fdn_compiler_options_from_value (napi_env env,
                                 napi_value value,
                                 FridaCompilerOptions ** result)
{
  napi_status status;
  bool is_instance;
  FridaCompilerOptions * handle;

  status = napi_check_object_type_tag (env, value, &fdn_compiler_options_type_tag, &is_instance);
  if (status != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of CompilerOptions");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) &handle);

  g_object_ref (handle);
  *result = handle;

  return TRUE;
}

static napi_value
fdn_compiler_options_to_value (napi_env env,
                               FridaCompilerOptions * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_compiler_options_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_compiler_options_construct (napi_env env,
                                napi_callback_info info)
{
  size_t argc = 0;
  napi_value jsthis;
  napi_status status;
  FridaCompilerOptions * handle;

  status = napi_get_cb_info (env, info, &argc, NULL, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  handle = frida_compiler_options_new ();

  status = napi_type_tag_object (env, jsthis, &fdn_compiler_options_type_tag);
  if (status != napi_ok)
    return NULL;

  status = napi_wrap (env, jsthis, handle, NULL, NULL, NULL);
  if (status != napi_ok)
    return NULL;

  return jsthis;
}

static napi_value
fdn_compiler_options_get_project_root (napi_env env,
                                       napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaCompilerOptions * handle;
  gchar * return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_compiler_options_get_project_root (handle);

  result = fdn_utf8_to_value (env, return_value);

  return result;
}

static napi_value
fdn_compiler_options_set_project_root (napi_env env,
                                       napi_callback_info info)
{
  napi_value result;
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaCompilerOptions * handle;
  gchar * value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  if (argc > 0)
  {
    if (!fdn_utf8_from_value (env, args[0], &value))
      goto invalid_argument;
  }
  else
  {
    value = NULL;
  }

  frida_compiler_options_set_project_root (handle, value);

  
  g_free (operation->value);napi_get_undefined (env, &result);

  return result;

invalid_argument:
  {
    
  g_free (operation->value);return NULL;
  }
}

static napi_value
fdn_compiler_options_get_source_maps (napi_env env,
                                      napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaCompilerOptions * handle;
  FridaSourceMaps return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_compiler_options_get_source_maps (handle);

  result = fdn_source_maps_to_value (env, return_value);

  return result;
}

static napi_value
fdn_compiler_options_set_source_maps (napi_env env,
                                      napi_callback_info info)
{
  napi_value result;
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaCompilerOptions * handle;
  FridaSourceMaps value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  if (argc > 0)
  {
    if (!fdn_source_maps_from_value (env, args[0], &value))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: value");
    goto invalid_argument;
  }

  frida_compiler_options_set_source_maps (handle, value);

  napi_get_undefined (env, &result);

  return result;

invalid_argument:
  {
    return NULL;
  }
}

static napi_value
fdn_compiler_options_get_compression (napi_env env,
                                      napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaCompilerOptions * handle;
  FridaJsCompression return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_compiler_options_get_compression (handle);

  result = fdn_js_compression_to_value (env, return_value);

  return result;
}

static napi_value
fdn_compiler_options_set_compression (napi_env env,
                                      napi_callback_info info)
{
  napi_value result;
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaCompilerOptions * handle;
  FridaJsCompression value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  if (argc > 0)
  {
    if (!fdn_js_compression_from_value (env, args[0], &value))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: value");
    goto invalid_argument;
  }

  frida_compiler_options_set_compression (handle, value);

  napi_get_undefined (env, &result);

  return result;

invalid_argument:
  {
    return NULL;
  }
}

static void
fdn_build_options_register (napi_env env,
                            napi_value exports)
{
  napi_property_descriptor properties[] =
  {
    
  };

  napi_value constructor;
  napi_define_class (env, "BuildOptions", NAPI_AUTO_LENGTH, fdn_build_options_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_build_options_constructor);

  napi_set_named_property (env, exports, "BuildOptions", constructor);
}

static gboolean
fdn_build_options_from_value (napi_env env,
                              napi_value value,
                              FridaBuildOptions ** result)
{
  napi_status status;
  bool is_instance;
  FridaBuildOptions * handle;

  status = napi_check_object_type_tag (env, value, &fdn_build_options_type_tag, &is_instance);
  if (status != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of BuildOptions");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) &handle);

  g_object_ref (handle);
  *result = handle;

  return TRUE;
}

static napi_value
fdn_build_options_to_value (napi_env env,
                            FridaBuildOptions * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_build_options_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_build_options_construct (napi_env env,
                             napi_callback_info info)
{
  size_t argc = 0;
  napi_value jsthis;
  napi_status status;
  FridaBuildOptions * handle;

  status = napi_get_cb_info (env, info, &argc, NULL, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  handle = frida_build_options_new ();

  status = napi_type_tag_object (env, jsthis, &fdn_build_options_type_tag);
  if (status != napi_ok)
    return NULL;

  status = napi_wrap (env, jsthis, handle, NULL, NULL, NULL);
  if (status != napi_ok)
    return NULL;

  return jsthis;
}

static void
fdn_watch_options_register (napi_env env,
                            napi_value exports)
{
  napi_property_descriptor properties[] =
  {
    
  };

  napi_value constructor;
  napi_define_class (env, "WatchOptions", NAPI_AUTO_LENGTH, fdn_watch_options_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_watch_options_constructor);

  napi_set_named_property (env, exports, "WatchOptions", constructor);
}

static gboolean
fdn_watch_options_from_value (napi_env env,
                              napi_value value,
                              FridaWatchOptions ** result)
{
  napi_status status;
  bool is_instance;
  FridaWatchOptions * handle;

  status = napi_check_object_type_tag (env, value, &fdn_watch_options_type_tag, &is_instance);
  if (status != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of WatchOptions");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) &handle);

  g_object_ref (handle);
  *result = handle;

  return TRUE;
}

static napi_value
fdn_watch_options_to_value (napi_env env,
                            FridaWatchOptions * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_watch_options_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_watch_options_construct (napi_env env,
                             napi_callback_info info)
{
  size_t argc = 0;
  napi_value jsthis;
  napi_status status;
  FridaWatchOptions * handle;

  status = napi_get_cb_info (env, info, &argc, NULL, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  handle = frida_watch_options_new ();

  status = napi_type_tag_object (env, jsthis, &fdn_watch_options_type_tag);
  if (status != napi_ok)
    return NULL;

  status = napi_wrap (env, jsthis, handle, NULL, NULL, NULL);
  if (status != napi_ok)
    return NULL;

  return jsthis;
}

static void
fdn_static_authentication_service_register (napi_env env,
                                            napi_value exports)
{
  napi_property_descriptor properties[] =
  {
    { "getTokenHash", NULL, fdn_static_authentication_service_get_token_hash, NULL, NULL, NULL, napi_default, NULL },
  };

  napi_value constructor;
  napi_define_class (env, "StaticAuthenticationService", NAPI_AUTO_LENGTH, fdn_static_authentication_service_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_static_authentication_service_constructor);

  napi_set_named_property (env, exports, "StaticAuthenticationService", constructor);
}

static gboolean
fdn_static_authentication_service_from_value (napi_env env,
                                              napi_value value,
                                              FridaStaticAuthenticationService ** result)
{
  napi_status status;
  bool is_instance;
  FridaStaticAuthenticationService * handle;

  status = napi_check_object_type_tag (env, value, &fdn_static_authentication_service_type_tag, &is_instance);
  if (status != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of StaticAuthenticationService");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) &handle);

  g_object_ref (handle);
  *result = handle;

  return TRUE;
}

static napi_value
fdn_static_authentication_service_to_value (napi_env env,
                                            FridaStaticAuthenticationService * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_static_authentication_service_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_static_authentication_service_construct (napi_env env,
                                             napi_callback_info info)
{
  napi_throw_error (env, NULL, "class StaticAuthenticationService cannot be constructed because it lacks a default constructor");
  return NULL;
}

static napi_value
fdn_static_authentication_service_get_token_hash (napi_env env,
                                                  napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaStaticAuthenticationService * handle;
  gchar * return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_static_authentication_service_get_token_hash (handle);

  result = fdn_utf8_to_value (env, return_value);

  return result;
}

static void
fdn_frontmost_query_options_register (napi_env env,
                                      napi_value exports)
{
  napi_property_descriptor properties[] =
  {
    { "getScope", NULL, fdn_frontmost_query_options_get_scope, NULL, NULL, NULL, napi_default, NULL },
    { "setScope", NULL, fdn_frontmost_query_options_set_scope, NULL, NULL, NULL, napi_default, NULL },
  };

  napi_value constructor;
  napi_define_class (env, "FrontmostQueryOptions", NAPI_AUTO_LENGTH, fdn_frontmost_query_options_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_frontmost_query_options_constructor);

  napi_set_named_property (env, exports, "FrontmostQueryOptions", constructor);
}

static gboolean
fdn_frontmost_query_options_from_value (napi_env env,
                                        napi_value value,
                                        FridaFrontmostQueryOptions ** result)
{
  napi_status status;
  bool is_instance;
  FridaFrontmostQueryOptions * handle;

  status = napi_check_object_type_tag (env, value, &fdn_frontmost_query_options_type_tag, &is_instance);
  if (status != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of FrontmostQueryOptions");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) &handle);

  g_object_ref (handle);
  *result = handle;

  return TRUE;
}

static napi_value
fdn_frontmost_query_options_to_value (napi_env env,
                                      FridaFrontmostQueryOptions * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_frontmost_query_options_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_frontmost_query_options_construct (napi_env env,
                                       napi_callback_info info)
{
  size_t argc = 0;
  napi_value jsthis;
  napi_status status;
  FridaFrontmostQueryOptions * handle;

  status = napi_get_cb_info (env, info, &argc, NULL, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  handle = frida_frontmost_query_options_new ();

  status = napi_type_tag_object (env, jsthis, &fdn_frontmost_query_options_type_tag);
  if (status != napi_ok)
    return NULL;

  status = napi_wrap (env, jsthis, handle, NULL, NULL, NULL);
  if (status != napi_ok)
    return NULL;

  return jsthis;
}

static napi_value
fdn_frontmost_query_options_get_scope (napi_env env,
                                       napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaFrontmostQueryOptions * handle;
  FridaScope return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_frontmost_query_options_get_scope (handle);

  result = fdn_scope_to_value (env, return_value);

  return result;
}

static napi_value
fdn_frontmost_query_options_set_scope (napi_env env,
                                       napi_callback_info info)
{
  napi_value result;
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaFrontmostQueryOptions * handle;
  FridaScope value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  if (argc > 0)
  {
    if (!fdn_scope_from_value (env, args[0], &value))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: value");
    goto invalid_argument;
  }

  frida_frontmost_query_options_set_scope (handle, value);

  napi_get_undefined (env, &result);

  return result;

invalid_argument:
  {
    return NULL;
  }
}

static void
fdn_application_query_options_register (napi_env env,
                                        napi_value exports)
{
  napi_property_descriptor properties[] =
  {
    { "selectIdentifier", NULL, fdn_application_query_options_select_identifier, NULL, NULL, NULL, napi_default, NULL },
    { "hasSelectedIdentifiers", NULL, fdn_application_query_options_has_selected_identifiers, NULL, NULL, NULL, napi_default, NULL },
    { "getScope", NULL, fdn_application_query_options_get_scope, NULL, NULL, NULL, napi_default, NULL },
    { "setScope", NULL, fdn_application_query_options_set_scope, NULL, NULL, NULL, napi_default, NULL },
  };

  napi_value constructor;
  napi_define_class (env, "ApplicationQueryOptions", NAPI_AUTO_LENGTH, fdn_application_query_options_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_application_query_options_constructor);

  napi_set_named_property (env, exports, "ApplicationQueryOptions", constructor);
}

static gboolean
fdn_application_query_options_from_value (napi_env env,
                                          napi_value value,
                                          FridaApplicationQueryOptions ** result)
{
  napi_status status;
  bool is_instance;
  FridaApplicationQueryOptions * handle;

  status = napi_check_object_type_tag (env, value, &fdn_application_query_options_type_tag, &is_instance);
  if (status != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of ApplicationQueryOptions");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) &handle);

  g_object_ref (handle);
  *result = handle;

  return TRUE;
}

static napi_value
fdn_application_query_options_to_value (napi_env env,
                                        FridaApplicationQueryOptions * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_application_query_options_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_application_query_options_construct (napi_env env,
                                         napi_callback_info info)
{
  size_t argc = 0;
  napi_value jsthis;
  napi_status status;
  FridaApplicationQueryOptions * handle;

  status = napi_get_cb_info (env, info, &argc, NULL, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  handle = frida_application_query_options_new ();

  status = napi_type_tag_object (env, jsthis, &fdn_application_query_options_type_tag);
  if (status != napi_ok)
    return NULL;

  status = napi_wrap (env, jsthis, handle, NULL, NULL, NULL);
  if (status != napi_ok)
    return NULL;

  return jsthis;
}

static napi_value
fdn_application_query_options_select_identifier (napi_env env,
                                                 napi_callback_info info)
{
  napi_value result;
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaApplicationQueryOptions * handle;
  gchar * identifier;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  if (argc > 0)
  {
    if (!fdn_utf8_from_value (env, args[0], &identifier))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: identifier");
    goto invalid_argument;
  }

  frida_application_query_options_select_identifier (handle, identifier);

  
  g_free (operation->identifier);napi_get_undefined (env, &result);

  return result;

invalid_argument:
  {
    
  g_free (operation->identifier);return NULL;
  }
}

static napi_value
fdn_application_query_options_has_selected_identifiers (napi_env env,
                                                        napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaApplicationQueryOptions * handle;
  gboolean return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_application_query_options_has_selected_identifiers (handle);

  result = fdn_boolean_to_value (env, return_value);

  return result;
}

static napi_value
fdn_application_query_options_get_scope (napi_env env,
                                         napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaApplicationQueryOptions * handle;
  FridaScope return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_application_query_options_get_scope (handle);

  result = fdn_scope_to_value (env, return_value);

  return result;
}

static napi_value
fdn_application_query_options_set_scope (napi_env env,
                                         napi_callback_info info)
{
  napi_value result;
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaApplicationQueryOptions * handle;
  FridaScope value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  if (argc > 0)
  {
    if (!fdn_scope_from_value (env, args[0], &value))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: value");
    goto invalid_argument;
  }

  frida_application_query_options_set_scope (handle, value);

  napi_get_undefined (env, &result);

  return result;

invalid_argument:
  {
    return NULL;
  }
}

static void
fdn_process_query_options_register (napi_env env,
                                    napi_value exports)
{
  napi_property_descriptor properties[] =
  {
    { "selectPid", NULL, fdn_process_query_options_select_pid, NULL, NULL, NULL, napi_default, NULL },
    { "hasSelectedPids", NULL, fdn_process_query_options_has_selected_pids, NULL, NULL, NULL, napi_default, NULL },
    { "getScope", NULL, fdn_process_query_options_get_scope, NULL, NULL, NULL, napi_default, NULL },
    { "setScope", NULL, fdn_process_query_options_set_scope, NULL, NULL, NULL, napi_default, NULL },
  };

  napi_value constructor;
  napi_define_class (env, "ProcessQueryOptions", NAPI_AUTO_LENGTH, fdn_process_query_options_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_process_query_options_constructor);

  napi_set_named_property (env, exports, "ProcessQueryOptions", constructor);
}

static gboolean
fdn_process_query_options_from_value (napi_env env,
                                      napi_value value,
                                      FridaProcessQueryOptions ** result)
{
  napi_status status;
  bool is_instance;
  FridaProcessQueryOptions * handle;

  status = napi_check_object_type_tag (env, value, &fdn_process_query_options_type_tag, &is_instance);
  if (status != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of ProcessQueryOptions");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) &handle);

  g_object_ref (handle);
  *result = handle;

  return TRUE;
}

static napi_value
fdn_process_query_options_to_value (napi_env env,
                                    FridaProcessQueryOptions * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_process_query_options_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_process_query_options_construct (napi_env env,
                                     napi_callback_info info)
{
  size_t argc = 0;
  napi_value jsthis;
  napi_status status;
  FridaProcessQueryOptions * handle;

  status = napi_get_cb_info (env, info, &argc, NULL, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  handle = frida_process_query_options_new ();

  status = napi_type_tag_object (env, jsthis, &fdn_process_query_options_type_tag);
  if (status != napi_ok)
    return NULL;

  status = napi_wrap (env, jsthis, handle, NULL, NULL, NULL);
  if (status != napi_ok)
    return NULL;

  return jsthis;
}

static napi_value
fdn_process_query_options_select_pid (napi_env env,
                                      napi_callback_info info)
{
  napi_value result;
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaProcessQueryOptions * handle;
  guint pid;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  if (argc > 0)
  {
    if (!fdn_uint_from_value (env, args[0], &pid))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: pid");
    goto invalid_argument;
  }

  frida_process_query_options_select_pid (handle, pid);

  napi_get_undefined (env, &result);

  return result;

invalid_argument:
  {
    return NULL;
  }
}

static napi_value
fdn_process_query_options_has_selected_pids (napi_env env,
                                             napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaProcessQueryOptions * handle;
  gboolean return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_process_query_options_has_selected_pids (handle);

  result = fdn_boolean_to_value (env, return_value);

  return result;
}

static napi_value
fdn_process_query_options_get_scope (napi_env env,
                                     napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaProcessQueryOptions * handle;
  FridaScope return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_process_query_options_get_scope (handle);

  result = fdn_scope_to_value (env, return_value);

  return result;
}

static napi_value
fdn_process_query_options_set_scope (napi_env env,
                                     napi_callback_info info)
{
  napi_value result;
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaProcessQueryOptions * handle;
  FridaScope value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  if (argc > 0)
  {
    if (!fdn_scope_from_value (env, args[0], &value))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: value");
    goto invalid_argument;
  }

  frida_process_query_options_set_scope (handle, value);

  napi_get_undefined (env, &result);

  return result;

invalid_argument:
  {
    return NULL;
  }
}

static void
fdn_session_options_register (napi_env env,
                              napi_value exports)
{
  napi_property_descriptor properties[] =
  {
    { "getRealm", NULL, fdn_session_options_get_realm, NULL, NULL, NULL, napi_default, NULL },
    { "setRealm", NULL, fdn_session_options_set_realm, NULL, NULL, NULL, napi_default, NULL },
    { "getPersistTimeout", NULL, fdn_session_options_get_persist_timeout, NULL, NULL, NULL, napi_default, NULL },
    { "setPersistTimeout", NULL, fdn_session_options_set_persist_timeout, NULL, NULL, NULL, napi_default, NULL },
    { "getEmulatedAgentPath", NULL, fdn_session_options_get_emulated_agent_path, NULL, NULL, NULL, napi_default, NULL },
    { "setEmulatedAgentPath", NULL, fdn_session_options_set_emulated_agent_path, NULL, NULL, NULL, napi_default, NULL },
  };

  napi_value constructor;
  napi_define_class (env, "SessionOptions", NAPI_AUTO_LENGTH, fdn_session_options_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_session_options_constructor);

  napi_set_named_property (env, exports, "SessionOptions", constructor);
}

static gboolean
fdn_session_options_from_value (napi_env env,
                                napi_value value,
                                FridaSessionOptions ** result)
{
  napi_status status;
  bool is_instance;
  FridaSessionOptions * handle;

  status = napi_check_object_type_tag (env, value, &fdn_session_options_type_tag, &is_instance);
  if (status != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of SessionOptions");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) &handle);

  g_object_ref (handle);
  *result = handle;

  return TRUE;
}

static napi_value
fdn_session_options_to_value (napi_env env,
                              FridaSessionOptions * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_session_options_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_session_options_construct (napi_env env,
                               napi_callback_info info)
{
  size_t argc = 0;
  napi_value jsthis;
  napi_status status;
  FridaSessionOptions * handle;

  status = napi_get_cb_info (env, info, &argc, NULL, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  handle = frida_session_options_new ();

  status = napi_type_tag_object (env, jsthis, &fdn_session_options_type_tag);
  if (status != napi_ok)
    return NULL;

  status = napi_wrap (env, jsthis, handle, NULL, NULL, NULL);
  if (status != napi_ok)
    return NULL;

  return jsthis;
}

static napi_value
fdn_session_options_get_realm (napi_env env,
                               napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaSessionOptions * handle;
  FridaRealm return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_session_options_get_realm (handle);

  result = fdn_realm_to_value (env, return_value);

  return result;
}

static napi_value
fdn_session_options_set_realm (napi_env env,
                               napi_callback_info info)
{
  napi_value result;
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaSessionOptions * handle;
  FridaRealm value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  if (argc > 0)
  {
    if (!fdn_realm_from_value (env, args[0], &value))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: value");
    goto invalid_argument;
  }

  frida_session_options_set_realm (handle, value);

  napi_get_undefined (env, &result);

  return result;

invalid_argument:
  {
    return NULL;
  }
}

static napi_value
fdn_session_options_get_persist_timeout (napi_env env,
                                         napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaSessionOptions * handle;
  guint return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_session_options_get_persist_timeout (handle);

  result = fdn_uint_to_value (env, return_value);

  return result;
}

static napi_value
fdn_session_options_set_persist_timeout (napi_env env,
                                         napi_callback_info info)
{
  napi_value result;
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaSessionOptions * handle;
  guint value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  if (argc > 0)
  {
    if (!fdn_uint_from_value (env, args[0], &value))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: value");
    goto invalid_argument;
  }

  frida_session_options_set_persist_timeout (handle, value);

  napi_get_undefined (env, &result);

  return result;

invalid_argument:
  {
    return NULL;
  }
}

static napi_value
fdn_session_options_get_emulated_agent_path (napi_env env,
                                             napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaSessionOptions * handle;
  gchar * return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_session_options_get_emulated_agent_path (handle);

  result = fdn_utf8_to_value (env, return_value);

  return result;
}

static napi_value
fdn_session_options_set_emulated_agent_path (napi_env env,
                                             napi_callback_info info)
{
  napi_value result;
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaSessionOptions * handle;
  gchar * value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  if (argc > 0)
  {
    if (!fdn_utf8_from_value (env, args[0], &value))
      goto invalid_argument;
  }
  else
  {
    value = NULL;
  }

  frida_session_options_set_emulated_agent_path (handle, value);

  
  g_free (operation->value);napi_get_undefined (env, &result);

  return result;

invalid_argument:
  {
    
  g_free (operation->value);return NULL;
  }
}

static void
fdn_script_options_register (napi_env env,
                             napi_value exports)
{
  napi_property_descriptor properties[] =
  {
    { "getName", NULL, fdn_script_options_get_name, NULL, NULL, NULL, napi_default, NULL },
    { "setName", NULL, fdn_script_options_set_name, NULL, NULL, NULL, napi_default, NULL },
    { "getSnapshot", NULL, fdn_script_options_get_snapshot, NULL, NULL, NULL, napi_default, NULL },
    { "setSnapshot", NULL, fdn_script_options_set_snapshot, NULL, NULL, NULL, napi_default, NULL },
    { "getSnapshotTransport", NULL, fdn_script_options_get_snapshot_transport, NULL, NULL, NULL, napi_default, NULL },
    { "setSnapshotTransport", NULL, fdn_script_options_set_snapshot_transport, NULL, NULL, NULL, napi_default, NULL },
    { "getRuntime", NULL, fdn_script_options_get_runtime, NULL, NULL, NULL, napi_default, NULL },
    { "setRuntime", NULL, fdn_script_options_set_runtime, NULL, NULL, NULL, napi_default, NULL },
  };

  napi_value constructor;
  napi_define_class (env, "ScriptOptions", NAPI_AUTO_LENGTH, fdn_script_options_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_script_options_constructor);

  napi_set_named_property (env, exports, "ScriptOptions", constructor);
}

static gboolean
fdn_script_options_from_value (napi_env env,
                               napi_value value,
                               FridaScriptOptions ** result)
{
  napi_status status;
  bool is_instance;
  FridaScriptOptions * handle;

  status = napi_check_object_type_tag (env, value, &fdn_script_options_type_tag, &is_instance);
  if (status != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of ScriptOptions");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) &handle);

  g_object_ref (handle);
  *result = handle;

  return TRUE;
}

static napi_value
fdn_script_options_to_value (napi_env env,
                             FridaScriptOptions * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_script_options_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_script_options_construct (napi_env env,
                              napi_callback_info info)
{
  size_t argc = 0;
  napi_value jsthis;
  napi_status status;
  FridaScriptOptions * handle;

  status = napi_get_cb_info (env, info, &argc, NULL, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  handle = frida_script_options_new ();

  status = napi_type_tag_object (env, jsthis, &fdn_script_options_type_tag);
  if (status != napi_ok)
    return NULL;

  status = napi_wrap (env, jsthis, handle, NULL, NULL, NULL);
  if (status != napi_ok)
    return NULL;

  return jsthis;
}

static napi_value
fdn_script_options_get_name (napi_env env,
                             napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaScriptOptions * handle;
  gchar * return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_script_options_get_name (handle);

  result = fdn_utf8_to_value (env, return_value);

  return result;
}

static napi_value
fdn_script_options_set_name (napi_env env,
                             napi_callback_info info)
{
  napi_value result;
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaScriptOptions * handle;
  gchar * value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  if (argc > 0)
  {
    if (!fdn_utf8_from_value (env, args[0], &value))
      goto invalid_argument;
  }
  else
  {
    value = NULL;
  }

  frida_script_options_set_name (handle, value);

  
  g_free (operation->value);napi_get_undefined (env, &result);

  return result;

invalid_argument:
  {
    
  g_free (operation->value);return NULL;
  }
}

static napi_value
fdn_script_options_get_snapshot (napi_env env,
                                 napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaScriptOptions * handle;
  GBytes * return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_script_options_get_snapshot (handle);

  result = fdn_bytes_to_value (env, return_value);

  return result;
}

static napi_value
fdn_script_options_set_snapshot (napi_env env,
                                 napi_callback_info info)
{
  napi_value result;
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaScriptOptions * handle;
  GBytes * value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  if (argc > 0)
  {
    if (!fdn_bytes_from_value (env, args[0], &value))
      goto invalid_argument;
  }
  else
  {
    value = NULL;
  }

  frida_script_options_set_snapshot (handle, value);

  napi_get_undefined (env, &result);

  return result;

invalid_argument:
  {
    return NULL;
  }
}

static napi_value
fdn_script_options_get_snapshot_transport (napi_env env,
                                           napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaScriptOptions * handle;
  FridaSnapshotTransport return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_script_options_get_snapshot_transport (handle);

  result = fdn_snapshot_transport_to_value (env, return_value);

  return result;
}

static napi_value
fdn_script_options_set_snapshot_transport (napi_env env,
                                           napi_callback_info info)
{
  napi_value result;
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaScriptOptions * handle;
  FridaSnapshotTransport value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  if (argc > 0)
  {
    if (!fdn_snapshot_transport_from_value (env, args[0], &value))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: value");
    goto invalid_argument;
  }

  frida_script_options_set_snapshot_transport (handle, value);

  napi_get_undefined (env, &result);

  return result;

invalid_argument:
  {
    return NULL;
  }
}

static napi_value
fdn_script_options_get_runtime (napi_env env,
                                napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaScriptOptions * handle;
  FridaScriptRuntime return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_script_options_get_runtime (handle);

  result = fdn_script_runtime_to_value (env, return_value);

  return result;
}

static napi_value
fdn_script_options_set_runtime (napi_env env,
                                napi_callback_info info)
{
  napi_value result;
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaScriptOptions * handle;
  FridaScriptRuntime value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  if (argc > 0)
  {
    if (!fdn_script_runtime_from_value (env, args[0], &value))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: value");
    goto invalid_argument;
  }

  frida_script_options_set_runtime (handle, value);

  napi_get_undefined (env, &result);

  return result;

invalid_argument:
  {
    return NULL;
  }
}

static void
fdn_snapshot_options_register (napi_env env,
                               napi_value exports)
{
  napi_property_descriptor properties[] =
  {
    { "getWarmupScript", NULL, fdn_snapshot_options_get_warmup_script, NULL, NULL, NULL, napi_default, NULL },
    { "setWarmupScript", NULL, fdn_snapshot_options_set_warmup_script, NULL, NULL, NULL, napi_default, NULL },
    { "getRuntime", NULL, fdn_snapshot_options_get_runtime, NULL, NULL, NULL, napi_default, NULL },
    { "setRuntime", NULL, fdn_snapshot_options_set_runtime, NULL, NULL, NULL, napi_default, NULL },
  };

  napi_value constructor;
  napi_define_class (env, "SnapshotOptions", NAPI_AUTO_LENGTH, fdn_snapshot_options_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_snapshot_options_constructor);

  napi_set_named_property (env, exports, "SnapshotOptions", constructor);
}

static gboolean
fdn_snapshot_options_from_value (napi_env env,
                                 napi_value value,
                                 FridaSnapshotOptions ** result)
{
  napi_status status;
  bool is_instance;
  FridaSnapshotOptions * handle;

  status = napi_check_object_type_tag (env, value, &fdn_snapshot_options_type_tag, &is_instance);
  if (status != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of SnapshotOptions");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) &handle);

  g_object_ref (handle);
  *result = handle;

  return TRUE;
}

static napi_value
fdn_snapshot_options_to_value (napi_env env,
                               FridaSnapshotOptions * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_snapshot_options_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_snapshot_options_construct (napi_env env,
                                napi_callback_info info)
{
  size_t argc = 0;
  napi_value jsthis;
  napi_status status;
  FridaSnapshotOptions * handle;

  status = napi_get_cb_info (env, info, &argc, NULL, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  handle = frida_snapshot_options_new ();

  status = napi_type_tag_object (env, jsthis, &fdn_snapshot_options_type_tag);
  if (status != napi_ok)
    return NULL;

  status = napi_wrap (env, jsthis, handle, NULL, NULL, NULL);
  if (status != napi_ok)
    return NULL;

  return jsthis;
}

static napi_value
fdn_snapshot_options_get_warmup_script (napi_env env,
                                        napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaSnapshotOptions * handle;
  gchar * return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_snapshot_options_get_warmup_script (handle);

  result = fdn_utf8_to_value (env, return_value);

  return result;
}

static napi_value
fdn_snapshot_options_set_warmup_script (napi_env env,
                                        napi_callback_info info)
{
  napi_value result;
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaSnapshotOptions * handle;
  gchar * value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  if (argc > 0)
  {
    if (!fdn_utf8_from_value (env, args[0], &value))
      goto invalid_argument;
  }
  else
  {
    value = NULL;
  }

  frida_snapshot_options_set_warmup_script (handle, value);

  
  g_free (operation->value);napi_get_undefined (env, &result);

  return result;

invalid_argument:
  {
    
  g_free (operation->value);return NULL;
  }
}

static napi_value
fdn_snapshot_options_get_runtime (napi_env env,
                                  napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaSnapshotOptions * handle;
  FridaScriptRuntime return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_snapshot_options_get_runtime (handle);

  result = fdn_script_runtime_to_value (env, return_value);

  return result;
}

static napi_value
fdn_snapshot_options_set_runtime (napi_env env,
                                  napi_callback_info info)
{
  napi_value result;
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaSnapshotOptions * handle;
  FridaScriptRuntime value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  if (argc > 0)
  {
    if (!fdn_script_runtime_from_value (env, args[0], &value))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: value");
    goto invalid_argument;
  }

  frida_snapshot_options_set_runtime (handle, value);

  napi_get_undefined (env, &result);

  return result;

invalid_argument:
  {
    return NULL;
  }
}

static void
fdn_portal_options_register (napi_env env,
                             napi_value exports)
{
  napi_property_descriptor properties[] =
  {
    { "getCertificate", NULL, fdn_portal_options_get_certificate, NULL, NULL, NULL, napi_default, NULL },
    { "setCertificate", NULL, fdn_portal_options_set_certificate, NULL, NULL, NULL, napi_default, NULL },
    { "getToken", NULL, fdn_portal_options_get_token, NULL, NULL, NULL, napi_default, NULL },
    { "setToken", NULL, fdn_portal_options_set_token, NULL, NULL, NULL, napi_default, NULL },
    { "getAcl", NULL, fdn_portal_options_get_acl, NULL, NULL, NULL, napi_default, NULL },
    { "setAcl", NULL, fdn_portal_options_set_acl, NULL, NULL, NULL, napi_default, NULL },
  };

  napi_value constructor;
  napi_define_class (env, "PortalOptions", NAPI_AUTO_LENGTH, fdn_portal_options_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_portal_options_constructor);

  napi_set_named_property (env, exports, "PortalOptions", constructor);
}

static gboolean
fdn_portal_options_from_value (napi_env env,
                               napi_value value,
                               FridaPortalOptions ** result)
{
  napi_status status;
  bool is_instance;
  FridaPortalOptions * handle;

  status = napi_check_object_type_tag (env, value, &fdn_portal_options_type_tag, &is_instance);
  if (status != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of PortalOptions");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) &handle);

  g_object_ref (handle);
  *result = handle;

  return TRUE;
}

static napi_value
fdn_portal_options_to_value (napi_env env,
                             FridaPortalOptions * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_portal_options_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_portal_options_construct (napi_env env,
                              napi_callback_info info)
{
  size_t argc = 0;
  napi_value jsthis;
  napi_status status;
  FridaPortalOptions * handle;

  status = napi_get_cb_info (env, info, &argc, NULL, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  handle = frida_portal_options_new ();

  status = napi_type_tag_object (env, jsthis, &fdn_portal_options_type_tag);
  if (status != napi_ok)
    return NULL;

  status = napi_wrap (env, jsthis, handle, NULL, NULL, NULL);
  if (status != napi_ok)
    return NULL;

  return jsthis;
}

static napi_value
fdn_portal_options_get_certificate (napi_env env,
                                    napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaPortalOptions * handle;
  GTlsCertificate * return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_portal_options_get_certificate (handle);

  result = fdn_tls_certificate_to_value (env, return_value);

  return result;
}

static napi_value
fdn_portal_options_set_certificate (napi_env env,
                                    napi_callback_info info)
{
  napi_value result;
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaPortalOptions * handle;
  GTlsCertificate * value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  if (argc > 0)
  {
    if (!fdn_tls_certificate_from_value (env, args[0], &value))
      goto invalid_argument;
  }
  else
  {
    value = NULL;
  }

  frida_portal_options_set_certificate (handle, value);

  napi_get_undefined (env, &result);

  return result;

invalid_argument:
  {
    return NULL;
  }
}

static napi_value
fdn_portal_options_get_token (napi_env env,
                              napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaPortalOptions * handle;
  gchar * return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_portal_options_get_token (handle);

  result = fdn_utf8_to_value (env, return_value);

  return result;
}

static napi_value
fdn_portal_options_set_token (napi_env env,
                              napi_callback_info info)
{
  napi_value result;
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaPortalOptions * handle;
  gchar * value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  if (argc > 0)
  {
    if (!fdn_utf8_from_value (env, args[0], &value))
      goto invalid_argument;
  }
  else
  {
    value = NULL;
  }

  frida_portal_options_set_token (handle, value);

  
  g_free (operation->value);napi_get_undefined (env, &result);

  return result;

invalid_argument:
  {
    
  g_free (operation->value);return NULL;
  }
}

static napi_value
fdn_portal_options_get_acl (napi_env env,
                            napi_callback_info info)
{
  napi_value result;
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaPortalOptions * handle;
  gint * result_length1;
  gchar ** return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  if (argc > 0)
  {
    if (!fdn_int_from_value (env, args[0], &result_length1))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: resultLength1");
    goto invalid_argument;
  }

  return_value = frida_portal_options_get_acl (handle, result_length1);

  result = fdn_strv_to_value (env, return_value);

  return result;

invalid_argument:
  {
    return NULL;
  }
}

static napi_value
fdn_portal_options_set_acl (napi_env env,
                            napi_callback_info info)
{
  napi_value result;
  size_t argc = 2;
  napi_value args[2];
  napi_status status;
  napi_value jsthis;
  FridaPortalOptions * handle;
  gchar ** value;
  gint value_length1;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  if (argc > 0)
  {
    if (!fdn_strv_from_value (env, args[0], &value))
      goto invalid_argument;
  }
  else
  {
    value = NULL;
  }
  if (argc > 1)
  {
    if (!fdn_int_from_value (env, args[1], &value_length1))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: valueLength1");
    goto invalid_argument;
  }

  frida_portal_options_set_acl (handle, value, value_length1);

  napi_get_undefined (env, &result);

  return result;

invalid_argument:
  {
    return NULL;
  }
}

static void
fdn_peer_options_register (napi_env env,
                           napi_value exports)
{
  napi_property_descriptor properties[] =
  {
    { "clearRelays", NULL, fdn_peer_options_clear_relays, NULL, NULL, NULL, napi_default, NULL },
    { "addRelay", NULL, fdn_peer_options_add_relay, NULL, NULL, NULL, napi_default, NULL },
    { "getStunServer", NULL, fdn_peer_options_get_stun_server, NULL, NULL, NULL, napi_default, NULL },
    { "setStunServer", NULL, fdn_peer_options_set_stun_server, NULL, NULL, NULL, napi_default, NULL },
  };

  napi_value constructor;
  napi_define_class (env, "PeerOptions", NAPI_AUTO_LENGTH, fdn_peer_options_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_peer_options_constructor);

  napi_set_named_property (env, exports, "PeerOptions", constructor);
}

static gboolean
fdn_peer_options_from_value (napi_env env,
                             napi_value value,
                             FridaPeerOptions ** result)
{
  napi_status status;
  bool is_instance;
  FridaPeerOptions * handle;

  status = napi_check_object_type_tag (env, value, &fdn_peer_options_type_tag, &is_instance);
  if (status != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of PeerOptions");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) &handle);

  g_object_ref (handle);
  *result = handle;

  return TRUE;
}

static napi_value
fdn_peer_options_to_value (napi_env env,
                           FridaPeerOptions * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_peer_options_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_peer_options_construct (napi_env env,
                            napi_callback_info info)
{
  size_t argc = 0;
  napi_value jsthis;
  napi_status status;
  FridaPeerOptions * handle;

  status = napi_get_cb_info (env, info, &argc, NULL, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  handle = frida_peer_options_new ();

  status = napi_type_tag_object (env, jsthis, &fdn_peer_options_type_tag);
  if (status != napi_ok)
    return NULL;

  status = napi_wrap (env, jsthis, handle, NULL, NULL, NULL);
  if (status != napi_ok)
    return NULL;

  return jsthis;
}

static napi_value
fdn_peer_options_clear_relays (napi_env env,
                               napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaPeerOptions * handle;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  frida_peer_options_clear_relays (handle);

  napi_get_undefined (env, &result);

  return result;
}

static napi_value
fdn_peer_options_add_relay (napi_env env,
                            napi_callback_info info)
{
  napi_value result;
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaPeerOptions * handle;
  FridaRelay * relay;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  if (argc > 0)
  {
    if (!fdn_relay_from_value (env, args[0], &relay))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: relay");
    goto invalid_argument;
  }

  frida_peer_options_add_relay (handle, relay);

  napi_get_undefined (env, &result);

  return result;

invalid_argument:
  {
    return NULL;
  }
}

static napi_value
fdn_peer_options_get_stun_server (napi_env env,
                                  napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaPeerOptions * handle;
  gchar * return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_peer_options_get_stun_server (handle);

  result = fdn_utf8_to_value (env, return_value);

  return result;
}

static napi_value
fdn_peer_options_set_stun_server (napi_env env,
                                  napi_callback_info info)
{
  napi_value result;
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaPeerOptions * handle;
  gchar * value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  if (argc > 0)
  {
    if (!fdn_utf8_from_value (env, args[0], &value))
      goto invalid_argument;
  }
  else
  {
    value = NULL;
  }

  frida_peer_options_set_stun_server (handle, value);

  
  g_free (operation->value);napi_get_undefined (env, &result);

  return result;

invalid_argument:
  {
    
  g_free (operation->value);return NULL;
  }
}

static void
fdn_relay_register (napi_env env,
                    napi_value exports)
{
  napi_property_descriptor properties[] =
  {
    { "getAddress", NULL, fdn_relay_get_address, NULL, NULL, NULL, napi_default, NULL },
    { "getUsername", NULL, fdn_relay_get_username, NULL, NULL, NULL, napi_default, NULL },
    { "getPassword", NULL, fdn_relay_get_password, NULL, NULL, NULL, napi_default, NULL },
    { "getKind", NULL, fdn_relay_get_kind, NULL, NULL, NULL, napi_default, NULL },
  };

  napi_value constructor;
  napi_define_class (env, "Relay", NAPI_AUTO_LENGTH, fdn_relay_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_relay_constructor);

  napi_set_named_property (env, exports, "Relay", constructor);
}

static gboolean
fdn_relay_from_value (napi_env env,
                      napi_value value,
                      FridaRelay ** result)
{
  napi_status status;
  bool is_instance;
  FridaRelay * handle;

  status = napi_check_object_type_tag (env, value, &fdn_relay_type_tag, &is_instance);
  if (status != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of Relay");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) &handle);

  g_object_ref (handle);
  *result = handle;

  return TRUE;
}

static napi_value
fdn_relay_to_value (napi_env env,
                    FridaRelay * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_relay_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_relay_construct (napi_env env,
                     napi_callback_info info)
{
  napi_throw_error (env, NULL, "class Relay cannot be constructed because it lacks a default constructor");
  return NULL;
}

static napi_value
fdn_relay_get_address (napi_env env,
                       napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaRelay * handle;
  gchar * return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_relay_get_address (handle);

  result = fdn_utf8_to_value (env, return_value);

  return result;
}

static napi_value
fdn_relay_get_username (napi_env env,
                        napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaRelay * handle;
  gchar * return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_relay_get_username (handle);

  result = fdn_utf8_to_value (env, return_value);

  return result;
}

static napi_value
fdn_relay_get_password (napi_env env,
                        napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaRelay * handle;
  gchar * return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_relay_get_password (handle);

  result = fdn_utf8_to_value (env, return_value);

  return result;
}

static napi_value
fdn_relay_get_kind (napi_env env,
                    napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaRelay * handle;
  FridaRelayKind return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_relay_get_kind (handle);

  result = fdn_relay_kind_to_value (env, return_value);

  return result;
}

static void
fdn_endpoint_parameters_register (napi_env env,
                                  napi_value exports)
{
  napi_property_descriptor properties[] =
  {
    { "getAddress", NULL, fdn_endpoint_parameters_get_address, NULL, NULL, NULL, napi_default, NULL },
    { "getPort", NULL, fdn_endpoint_parameters_get_port, NULL, NULL, NULL, napi_default, NULL },
    { "getCertificate", NULL, fdn_endpoint_parameters_get_certificate, NULL, NULL, NULL, napi_default, NULL },
    { "getOrigin", NULL, fdn_endpoint_parameters_get_origin, NULL, NULL, NULL, napi_default, NULL },
    { "getAuthService", NULL, fdn_endpoint_parameters_get_auth_service, NULL, NULL, NULL, napi_default, NULL },
    { "getAssetRoot", NULL, fdn_endpoint_parameters_get_asset_root, NULL, NULL, NULL, napi_default, NULL },
    { "setAssetRoot", NULL, fdn_endpoint_parameters_set_asset_root, NULL, NULL, NULL, napi_default, NULL },
  };

  napi_value constructor;
  napi_define_class (env, "EndpointParameters", NAPI_AUTO_LENGTH, fdn_endpoint_parameters_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_endpoint_parameters_constructor);

  napi_set_named_property (env, exports, "EndpointParameters", constructor);
}

static gboolean
fdn_endpoint_parameters_from_value (napi_env env,
                                    napi_value value,
                                    FridaEndpointParameters ** result)
{
  napi_status status;
  bool is_instance;
  FridaEndpointParameters * handle;

  status = napi_check_object_type_tag (env, value, &fdn_endpoint_parameters_type_tag, &is_instance);
  if (status != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of EndpointParameters");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) &handle);

  g_object_ref (handle);
  *result = handle;

  return TRUE;
}

static napi_value
fdn_endpoint_parameters_to_value (napi_env env,
                                  FridaEndpointParameters * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_endpoint_parameters_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_endpoint_parameters_construct (napi_env env,
                                   napi_callback_info info)
{
  napi_throw_error (env, NULL, "class EndpointParameters cannot be constructed because it lacks a default constructor");
  return NULL;
}

static napi_value
fdn_endpoint_parameters_get_address (napi_env env,
                                     napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaEndpointParameters * handle;
  gchar * return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_endpoint_parameters_get_address (handle);

  result = fdn_utf8_to_value (env, return_value);

  return result;
}

static napi_value
fdn_endpoint_parameters_get_port (napi_env env,
                                  napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaEndpointParameters * handle;
  guint16 return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_endpoint_parameters_get_port (handle);

  result = fdn_uint16_to_value (env, return_value);

  return result;
}

static napi_value
fdn_endpoint_parameters_get_certificate (napi_env env,
                                         napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaEndpointParameters * handle;
  GTlsCertificate * return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_endpoint_parameters_get_certificate (handle);

  result = fdn_tls_certificate_to_value (env, return_value);

  return result;
}

static napi_value
fdn_endpoint_parameters_get_origin (napi_env env,
                                    napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaEndpointParameters * handle;
  gchar * return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_endpoint_parameters_get_origin (handle);

  result = fdn_utf8_to_value (env, return_value);

  return result;
}

static napi_value
fdn_endpoint_parameters_get_auth_service (napi_env env,
                                          napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaEndpointParameters * handle;
  FridaAuthenticationService * return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_endpoint_parameters_get_auth_service (handle);

  result = fdn_authentication_service_to_value (env, return_value);

  return result;
}

static napi_value
fdn_endpoint_parameters_get_asset_root (napi_env env,
                                        napi_callback_info info)
{
  napi_value result;
  size_t argc = 0;
  napi_value args[0];
  napi_status status;
  napi_value jsthis;
  FridaEndpointParameters * handle;
  GFile * return_value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  return_value = frida_endpoint_parameters_get_asset_root (handle);

  result = fdn_file_to_value (env, return_value);

  return result;
}

static napi_value
fdn_endpoint_parameters_set_asset_root (napi_env env,
                                        napi_callback_info info)
{
  napi_value result;
  size_t argc = 1;
  napi_value args[1];
  napi_status status;
  napi_value jsthis;
  FridaEndpointParameters * handle;
  GFile * value;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  if (argc > 0)
  {
    if (!fdn_file_from_value (env, args[0], &value))
      goto invalid_argument;
  }
  else
  {
    value = NULL;
  }

  frida_endpoint_parameters_set_asset_root (handle, value);

  napi_get_undefined (env, &result);

  return result;

invalid_argument:
  {
    return NULL;
  }
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

static gboolean
fdn_runtime_from_value (napi_env env,
                        napi_value value,
                        FridaRuntime * result)
{
  return fdn_enum_from_value (env, frida_runtime_get_type (), value, (gint *) result);
}

static napi_value
fdn_runtime_to_value (napi_env env,
                      FridaRuntime value)
{
  return fdn_enum_to_value (env, frida_runtime_get_type (), value);
}

static gboolean
fdn_device_type_from_value (napi_env env,
                            napi_value value,
                            FridaDeviceType * result)
{
  return fdn_enum_from_value (env, frida_device_type_get_type (), value, (gint *) result);
}

static napi_value
fdn_device_type_to_value (napi_env env,
                          FridaDeviceType value)
{
  return fdn_enum_to_value (env, frida_device_type_get_type (), value);
}

static gboolean
fdn_source_maps_from_value (napi_env env,
                            napi_value value,
                            FridaSourceMaps * result)
{
  return fdn_enum_from_value (env, frida_source_maps_get_type (), value, (gint *) result);
}

static napi_value
fdn_source_maps_to_value (napi_env env,
                          FridaSourceMaps value)
{
  return fdn_enum_to_value (env, frida_source_maps_get_type (), value);
}

static gboolean
fdn_js_compression_from_value (napi_env env,
                               napi_value value,
                               FridaJsCompression * result)
{
  return fdn_enum_from_value (env, frida_js_compression_get_type (), value, (gint *) result);
}

static napi_value
fdn_js_compression_to_value (napi_env env,
                             FridaJsCompression value)
{
  return fdn_enum_to_value (env, frida_js_compression_get_type (), value);
}

static gboolean
fdn_agent_message_kind_from_value (napi_env env,
                                   napi_value value,
                                   FridaAgentMessageKind * result)
{
  return fdn_enum_from_value (env, frida_agent_message_kind_get_type (), value, (gint *) result);
}

static napi_value
fdn_agent_message_kind_to_value (napi_env env,
                                 FridaAgentMessageKind value)
{
  return fdn_enum_to_value (env, frida_agent_message_kind_get_type (), value);
}

static gboolean
fdn_realm_from_value (napi_env env,
                      napi_value value,
                      FridaRealm * result)
{
  return fdn_enum_from_value (env, frida_realm_get_type (), value, (gint *) result);
}

static napi_value
fdn_realm_to_value (napi_env env,
                    FridaRealm value)
{
  return fdn_enum_to_value (env, frida_realm_get_type (), value);
}

static gboolean
fdn_unload_policy_from_value (napi_env env,
                              napi_value value,
                              FridaUnloadPolicy * result)
{
  return fdn_enum_from_value (env, frida_unload_policy_get_type (), value, (gint *) result);
}

static napi_value
fdn_unload_policy_to_value (napi_env env,
                            FridaUnloadPolicy value)
{
  return fdn_enum_to_value (env, frida_unload_policy_get_type (), value);
}

static gboolean
fdn_session_detach_reason_from_value (napi_env env,
                                      napi_value value,
                                      FridaSessionDetachReason * result)
{
  return fdn_enum_from_value (env, frida_session_detach_reason_get_type (), value, (gint *) result);
}

static napi_value
fdn_session_detach_reason_to_value (napi_env env,
                                    FridaSessionDetachReason value)
{
  return fdn_enum_to_value (env, frida_session_detach_reason_get_type (), value);
}

static gboolean
fdn_scope_from_value (napi_env env,
                      napi_value value,
                      FridaScope * result)
{
  return fdn_enum_from_value (env, frida_scope_get_type (), value, (gint *) result);
}

static napi_value
fdn_scope_to_value (napi_env env,
                    FridaScope value)
{
  return fdn_enum_to_value (env, frida_scope_get_type (), value);
}

static gboolean
fdn_stdio_from_value (napi_env env,
                      napi_value value,
                      FridaStdio * result)
{
  return fdn_enum_from_value (env, frida_stdio_get_type (), value, (gint *) result);
}

static napi_value
fdn_stdio_to_value (napi_env env,
                    FridaStdio value)
{
  return fdn_enum_to_value (env, frida_stdio_get_type (), value);
}

static gboolean
fdn_child_origin_from_value (napi_env env,
                             napi_value value,
                             FridaChildOrigin * result)
{
  return fdn_enum_from_value (env, frida_child_origin_get_type (), value, (gint *) result);
}

static napi_value
fdn_child_origin_to_value (napi_env env,
                           FridaChildOrigin value)
{
  return fdn_enum_to_value (env, frida_child_origin_get_type (), value);
}

static gboolean
fdn_snapshot_transport_from_value (napi_env env,
                                   napi_value value,
                                   FridaSnapshotTransport * result)
{
  return fdn_enum_from_value (env, frida_snapshot_transport_get_type (), value, (gint *) result);
}

static napi_value
fdn_snapshot_transport_to_value (napi_env env,
                                 FridaSnapshotTransport value)
{
  return fdn_enum_to_value (env, frida_snapshot_transport_get_type (), value);
}

static gboolean
fdn_script_runtime_from_value (napi_env env,
                               napi_value value,
                               FridaScriptRuntime * result)
{
  return fdn_enum_from_value (env, frida_script_runtime_get_type (), value, (gint *) result);
}

static napi_value
fdn_script_runtime_to_value (napi_env env,
                             FridaScriptRuntime value)
{
  return fdn_enum_to_value (env, frida_script_runtime_get_type (), value);
}

static gboolean
fdn_relay_kind_from_value (napi_env env,
                           napi_value value,
                           FridaRelayKind * result)
{
  return fdn_enum_from_value (env, frida_relay_kind_get_type (), value, (gint *) result);
}

static napi_value
fdn_relay_kind_to_value (napi_env env,
                         FridaRelayKind value)
{
  return fdn_enum_to_value (env, frida_relay_kind_get_type (), value);
}

static gboolean
fdn_peer_setup_from_value (napi_env env,
                           napi_value value,
                           FridaPeerSetup * result)
{
  return fdn_enum_from_value (env, frida_peer_setup_get_type (), value, (gint *) result);
}

static napi_value
fdn_peer_setup_to_value (napi_env env,
                         FridaPeerSetup value)
{
  return fdn_enum_to_value (env, frida_peer_setup_get_type (), value);
}

static gboolean
fdn_web_service_transport_from_value (napi_env env,
                                      napi_value value,
                                      FridaWebServiceTransport * result)
{
  return fdn_enum_from_value (env, frida_web_service_transport_get_type (), value, (gint *) result);
}

static napi_value
fdn_web_service_transport_to_value (napi_env env,
                                    FridaWebServiceTransport value)
{
  return fdn_enum_to_value (env, frida_web_service_transport_get_type (), value);
}

static gboolean
fdn_web_service_flavor_from_value (napi_env env,
                                   napi_value value,
                                   FridaWebServiceFlavor * result)
{
  return fdn_enum_from_value (env, frida_web_service_flavor_get_type (), value, (gint *) result);
}

static napi_value
fdn_web_service_flavor_to_value (napi_env env,
                                 FridaWebServiceFlavor value)
{
  return fdn_enum_to_value (env, frida_web_service_flavor_get_type (), value);
}

static gboolean
fdn_port_conflict_behavior_from_value (napi_env env,
                                       napi_value value,
                                       FridaPortConflictBehavior * result)
{
  return fdn_enum_from_value (env, frida_port_conflict_behavior_get_type (), value, (gint *) result);
}

static napi_value
fdn_port_conflict_behavior_to_value (napi_env env,
                                     FridaPortConflictBehavior value)
{
  return fdn_enum_to_value (env, frida_port_conflict_behavior_get_type (), value);
}

static gboolean
fdn_string_terminator_from_value (napi_env env,
                                  napi_value value,
                                  FridaStringTerminator * result)
{
  return fdn_enum_from_value (env, frida_string_terminator_get_type (), value, (gint *) result);
}

static napi_value
fdn_string_terminator_to_value (napi_env env,
                                FridaStringTerminator value)
{
  return fdn_enum_to_value (env, frida_string_terminator_get_type (), value);
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
fdn_uint_from_value (napi_env env,
                     napi_value value,
                     guint * result)
{
  uint32_t number;

  if (napi_get_value_uint32 (env, value, &number) != napi_ok)
    goto invalid_argument;

  *result = number;
  return TRUE;

invalid_argument:
  {
    napi_throw_error (env, NULL, "expected an unsigned integer");
    return FALSE;
  }
}

static napi_value
fdn_uint_to_value (napi_env env,
                   guint value)
{
  napi_value result;
  napi_create_uint32 (env, value, &result);
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

static napi_value
fdn_utf8_to_value (napi_env env,
                   const gchar * str)
{
  napi_value result;
  napi_create_string_utf8 (env, str, NAPI_AUTO_LENGTH, &result);
  return result;
}

static gboolean
fdn_enum_from_value (napi_env env,
                     GType enum_type,
                     napi_value value,
                     gint * result)
{
  gboolean success = FALSE;
  gchar * nick;
  GEnumClass * enum_class;
  guint i;

  if (!fdn_utf8_from_value (env, value, &nick))
    return FALSE;

  enum_class = G_ENUM_CLASS (g_type_class_ref (enum_type));

  for (i = 0; i != enum_class->n_values; i++)
  {
    GEnumValue * enum_value = &enum_class->values[i];
    if (strcmp (enum_value->value_nick, nick) == 0)
    {
      *result = enum_value->value;
      success = TRUE;
      break;
    }
  }

  g_type_class_unref (enum_class);

  g_free (nick);

  if (!success)
    napi_throw_error (env, NULL, "invalid enumeration value");

  return success;
}

static napi_value
fdn_enum_to_value (napi_env env,
                   GType enum_type,
                   gint value)
{
  napi_value result;
  GEnumClass * enum_class;
  GEnumValue * enum_value;

  enum_class = G_ENUM_CLASS (g_type_class_ref (enum_type));

  enum_value = g_enum_get_value (enum_class, value);
  g_assert (enum_value != NULL);

  napi_create_string_utf8 (env, enum_value->value_nick, NAPI_AUTO_LENGTH, &result);

  g_type_class_unref (enum_class);

  return result;
}
