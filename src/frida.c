#include <frida-core.h>
#include <node_api.h>
#include <string.h>

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
  FridaDevice * retval;
} FdnDeviceManagerGetDeviceByIdOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaDeviceManager * handle;
  GError * error;
  FridaDeviceType type;
  gint timeout;
  GCancellable * cancellable;
  FridaDevice * retval;
} FdnDeviceManagerGetDeviceByTypeOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaDeviceManager * handle;
  GError * error;
  gchar * id;
  gint timeout;
  GCancellable * cancellable;
  FridaDevice * retval;
} FdnDeviceManagerFindDeviceByIdOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaDeviceManager * handle;
  GError * error;
  FridaDeviceType type;
  gint timeout;
  GCancellable * cancellable;
  FridaDevice * retval;
} FdnDeviceManagerFindDeviceByTypeOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaDeviceManager * handle;
  GError * error;
  GCancellable * cancellable;
  FridaDeviceList * retval;
} FdnDeviceManagerEnumerateDevicesOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaDeviceManager * handle;
  GError * error;
  gchar * address;
  FridaRemoteDeviceOptions * options;
  GCancellable * cancellable;
  FridaDevice * retval;
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
  GHashTable * retval;
} FdnDeviceQuerySystemParametersOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaDevice * handle;
  GError * error;
  FridaFrontmostQueryOptions * options;
  GCancellable * cancellable;
  FridaApplication * retval;
} FdnDeviceGetFrontmostApplicationOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaDevice * handle;
  GError * error;
  FridaApplicationQueryOptions * options;
  GCancellable * cancellable;
  FridaApplicationList * retval;
} FdnDeviceEnumerateApplicationsOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaDevice * handle;
  GError * error;
  guint pid;
  FridaProcessMatchOptions * options;
  GCancellable * cancellable;
  FridaProcess * retval;
} FdnDeviceGetProcessByPidOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaDevice * handle;
  GError * error;
  gchar * name;
  FridaProcessMatchOptions * options;
  GCancellable * cancellable;
  FridaProcess * retval;
} FdnDeviceGetProcessByNameOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaDevice * handle;
  GError * error;
  guint pid;
  FridaProcessMatchOptions * options;
  GCancellable * cancellable;
  FridaProcess * retval;
} FdnDeviceFindProcessByPidOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaDevice * handle;
  GError * error;
  gchar * name;
  FridaProcessMatchOptions * options;
  GCancellable * cancellable;
  FridaProcess * retval;
} FdnDeviceFindProcessByNameOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaDevice * handle;
  GError * error;
  FridaProcessQueryOptions * options;
  GCancellable * cancellable;
  FridaProcessList * retval;
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
  FridaSpawnList * retval;
} FdnDeviceEnumeratePendingSpawnOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaDevice * handle;
  GError * error;
  GCancellable * cancellable;
  FridaChildList * retval;
} FdnDeviceEnumeratePendingChildrenOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaDevice * handle;
  GError * error;
  gchar * program;
  FridaSpawnOptions * options;
  GCancellable * cancellable;
  guint retval;
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
  FridaSession * retval;
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
  guint retval;
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
  guint retval;
} FdnDeviceInjectLibraryBlobOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaDevice * handle;
  GError * error;
  gchar * address;
  GCancellable * cancellable;
  GIOStream * retval;
} FdnDeviceOpenChannelOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaDevice * handle;
  GError * error;
  gchar * address;
  GCancellable * cancellable;
  FridaService * retval;
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
  FridaScript * retval;
} FdnSessionCreateScriptOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaSession * handle;
  GError * error;
  GBytes * bytes;
  FridaScriptOptions * options;
  GCancellable * cancellable;
  FridaScript * retval;
} FdnSessionCreateScriptFromBytesOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaSession * handle;
  GError * error;
  gchar * source;
  FridaScriptOptions * options;
  GCancellable * cancellable;
  GBytes * retval;
} FdnSessionCompileScriptOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaSession * handle;
  GError * error;
  gchar * embed_script;
  FridaSnapshotOptions * options;
  GCancellable * cancellable;
  GBytes * retval;
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
  FridaPortalMembership * retval;
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
  gchar * retval;
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

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaService * handle;
  GError * error;
  GCancellable * cancellable;
} FdnServiceActivateOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaService * handle;
  GError * error;
  GCancellable * cancellable;
} FdnServiceCancelOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaService * handle;
  GError * error;
  GVariant * parameters;
  GCancellable * cancellable;
  GVariant * retval;
} FdnServiceRequestOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaInjector * handle;
  GError * error;
  GCancellable * cancellable;
} FdnInjectorCloseOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaInjector * handle;
  GError * error;
  guint pid;
  gchar * path;
  gchar * entrypoint;
  gchar * data;
  GCancellable * cancellable;
  guint retval;
} FdnInjectorInjectLibraryFileOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaInjector * handle;
  GError * error;
  guint pid;
  GBytes * blob;
  gchar * entrypoint;
  gchar * data;
  GCancellable * cancellable;
  guint retval;
} FdnInjectorInjectLibraryBlobOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaInjector * handle;
  GError * error;
  guint id;
  GCancellable * cancellable;
} FdnInjectorDemonitorOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaInjector * handle;
  GError * error;
  guint id;
  GCancellable * cancellable;
  guint retval;
} FdnInjectorDemonitorAndCloneStateOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaInjector * handle;
  GError * error;
  guint pid;
  guint id;
  GCancellable * cancellable;
} FdnInjectorRecreateThreadOperation;

typedef struct {
  napi_env env;
  napi_deferred deferred;
  FridaAuthenticationService * handle;
  GError * error;
  gchar * token;
  GCancellable * cancellable;
  gchar * retval;
} FdnAuthenticationServiceAuthenticateOperation;


static void fdn_device_manager_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_device_manager_from_value (napi_env env, napi_value value, FridaDeviceManager ** handle);
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

static napi_value fdn_device_manager_get_added_signal (napi_env env, napi_callback_info info);
static napi_value fdn_device_manager_get_removed_signal (napi_env env, napi_callback_info info);
static napi_value fdn_device_manager_get_changed_signal (napi_env env, napi_callback_info info);

G_GNUC_UNUSED static napi_value fdn_device_list_to_value (napi_env env, FridaDeviceList * handle);

static void fdn_device_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_device_from_value (napi_env env, napi_value value, FridaDevice ** handle);
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

static napi_value fdn_device_get_spawn_added_signal (napi_env env, napi_callback_info info);
static napi_value fdn_device_get_spawn_removed_signal (napi_env env, napi_callback_info info);
static napi_value fdn_device_get_child_added_signal (napi_env env, napi_callback_info info);
static napi_value fdn_device_get_child_removed_signal (napi_env env, napi_callback_info info);
static napi_value fdn_device_get_process_crashed_signal (napi_env env, napi_callback_info info);
static napi_value fdn_device_get_output_signal (napi_env env, napi_callback_info info);
static napi_value fdn_device_get_uninjected_signal (napi_env env, napi_callback_info info);
static napi_value fdn_device_get_lost_signal (napi_env env, napi_callback_info info);

static void fdn_remote_device_options_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_remote_device_options_from_value (napi_env env, napi_value value, FridaRemoteDeviceOptions ** handle);
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

G_GNUC_UNUSED static napi_value fdn_application_list_to_value (napi_env env, FridaApplicationList * handle);

static void fdn_application_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_application_from_value (napi_env env, napi_value value, FridaApplication ** handle);
G_GNUC_UNUSED static napi_value fdn_application_to_value (napi_env env, FridaApplication * handle);
static napi_value fdn_application_construct (napi_env env, napi_callback_info info);

static napi_value fdn_application_get_identifier (napi_env env, napi_callback_info info);

static napi_value fdn_application_get_name (napi_env env, napi_callback_info info);

static napi_value fdn_application_get_pid (napi_env env, napi_callback_info info);

static napi_value fdn_application_get_parameters (napi_env env, napi_callback_info info);

G_GNUC_UNUSED static napi_value fdn_process_list_to_value (napi_env env, FridaProcessList * handle);

static void fdn_process_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_process_from_value (napi_env env, napi_value value, FridaProcess ** handle);
G_GNUC_UNUSED static napi_value fdn_process_to_value (napi_env env, FridaProcess * handle);
static napi_value fdn_process_construct (napi_env env, napi_callback_info info);

static napi_value fdn_process_get_pid (napi_env env, napi_callback_info info);

static napi_value fdn_process_get_name (napi_env env, napi_callback_info info);

static napi_value fdn_process_get_parameters (napi_env env, napi_callback_info info);

static void fdn_process_match_options_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_process_match_options_from_value (napi_env env, napi_value value, FridaProcessMatchOptions ** handle);
G_GNUC_UNUSED static napi_value fdn_process_match_options_to_value (napi_env env, FridaProcessMatchOptions * handle);
static napi_value fdn_process_match_options_construct (napi_env env, napi_callback_info info);

static napi_value fdn_process_match_options_get_timeout (napi_env env, napi_callback_info info);

static napi_value fdn_process_match_options_set_timeout (napi_env env, napi_callback_info info);

static napi_value fdn_process_match_options_get_scope (napi_env env, napi_callback_info info);

static napi_value fdn_process_match_options_set_scope (napi_env env, napi_callback_info info);

static void fdn_spawn_options_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_spawn_options_from_value (napi_env env, napi_value value, FridaSpawnOptions ** handle);
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

G_GNUC_UNUSED static napi_value fdn_spawn_list_to_value (napi_env env, FridaSpawnList * handle);

static void fdn_spawn_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_spawn_from_value (napi_env env, napi_value value, FridaSpawn ** handle);
G_GNUC_UNUSED static napi_value fdn_spawn_to_value (napi_env env, FridaSpawn * handle);
static napi_value fdn_spawn_construct (napi_env env, napi_callback_info info);

static napi_value fdn_spawn_get_pid (napi_env env, napi_callback_info info);

static napi_value fdn_spawn_get_identifier (napi_env env, napi_callback_info info);

G_GNUC_UNUSED static napi_value fdn_child_list_to_value (napi_env env, FridaChildList * handle);

static void fdn_child_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_child_from_value (napi_env env, napi_value value, FridaChild ** handle);
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
G_GNUC_UNUSED static gboolean fdn_crash_from_value (napi_env env, napi_value value, FridaCrash ** handle);
G_GNUC_UNUSED static napi_value fdn_crash_to_value (napi_env env, FridaCrash * handle);
static napi_value fdn_crash_construct (napi_env env, napi_callback_info info);

static napi_value fdn_crash_get_pid (napi_env env, napi_callback_info info);

static napi_value fdn_crash_get_process_name (napi_env env, napi_callback_info info);

static napi_value fdn_crash_get_summary (napi_env env, napi_callback_info info);

static napi_value fdn_crash_get_report (napi_env env, napi_callback_info info);

static napi_value fdn_crash_get_parameters (napi_env env, napi_callback_info info);

static void fdn_bus_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_bus_from_value (napi_env env, napi_value value, FridaBus ** handle);
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

static napi_value fdn_bus_get_detached_signal (napi_env env, napi_callback_info info);
static napi_value fdn_bus_get_message_signal (napi_env env, napi_callback_info info);

static void fdn_session_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_session_from_value (napi_env env, napi_value value, FridaSession ** handle);
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

static napi_value fdn_session_get_persist_timeout (napi_env env, napi_callback_info info);

static napi_value fdn_session_get_detached_signal (napi_env env, napi_callback_info info);

static void fdn_script_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_script_from_value (napi_env env, napi_value value, FridaScript ** handle);
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

static napi_value fdn_script_get_destroyed_signal (napi_env env, napi_callback_info info);
static napi_value fdn_script_get_message_signal (napi_env env, napi_callback_info info);

static void fdn_portal_membership_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_portal_membership_from_value (napi_env env, napi_value value, FridaPortalMembership ** handle);
G_GNUC_UNUSED static napi_value fdn_portal_membership_to_value (napi_env env, FridaPortalMembership * handle);
static napi_value fdn_portal_membership_construct (napi_env env, napi_callback_info info);

static napi_value fdn_portal_membership_terminate (napi_env env, napi_callback_info info);
static gboolean fdn_portal_membership_terminate_begin (gpointer user_data);
static void fdn_portal_membership_terminate_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void fdn_portal_membership_terminate_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void fdn_portal_membership_terminate_operation_free (FdnPortalMembershipTerminateOperation * operation);

static void fdn_control_service_options_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_control_service_options_from_value (napi_env env, napi_value value, FridaControlServiceOptions ** handle);
G_GNUC_UNUSED static napi_value fdn_control_service_options_to_value (napi_env env, FridaControlServiceOptions * handle);
static napi_value fdn_control_service_options_construct (napi_env env, napi_callback_info info);

static napi_value fdn_control_service_options_get_sysroot (napi_env env, napi_callback_info info);

static napi_value fdn_control_service_options_set_sysroot (napi_env env, napi_callback_info info);

static napi_value fdn_control_service_options_get_enable_preload (napi_env env, napi_callback_info info);

static napi_value fdn_control_service_options_set_enable_preload (napi_env env, napi_callback_info info);

static napi_value fdn_control_service_options_get_report_crashes (napi_env env, napi_callback_info info);

static napi_value fdn_control_service_options_set_report_crashes (napi_env env, napi_callback_info info);

static void fdn_portal_service_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_portal_service_from_value (napi_env env, napi_value value, FridaPortalService ** handle);
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

static napi_value fdn_portal_service_get_node_connected_signal (napi_env env, napi_callback_info info);
static napi_value fdn_portal_service_get_node_joined_signal (napi_env env, napi_callback_info info);
static napi_value fdn_portal_service_get_node_left_signal (napi_env env, napi_callback_info info);
static napi_value fdn_portal_service_get_node_disconnected_signal (napi_env env, napi_callback_info info);
static napi_value fdn_portal_service_get_controller_connected_signal (napi_env env, napi_callback_info info);
static napi_value fdn_portal_service_get_controller_disconnected_signal (napi_env env, napi_callback_info info);
static napi_value fdn_portal_service_get_authenticated_signal (napi_env env, napi_callback_info info);
static napi_value fdn_portal_service_get_subscribe_signal (napi_env env, napi_callback_info info);
static napi_value fdn_portal_service_get_message_signal (napi_env env, napi_callback_info info);

static void fdn_file_monitor_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_file_monitor_from_value (napi_env env, napi_value value, FridaFileMonitor ** handle);
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

static napi_value fdn_file_monitor_get_change_signal (napi_env env, napi_callback_info info);

static void fdn_compiler_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_compiler_from_value (napi_env env, napi_value value, FridaCompiler ** handle);
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

static napi_value fdn_compiler_get_starting_signal (napi_env env, napi_callback_info info);
static napi_value fdn_compiler_get_finished_signal (napi_env env, napi_callback_info info);
static napi_value fdn_compiler_get_output_signal (napi_env env, napi_callback_info info);
static napi_value fdn_compiler_get_diagnostics_signal (napi_env env, napi_callback_info info);

static void fdn_compiler_options_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_compiler_options_from_value (napi_env env, napi_value value, FridaCompilerOptions ** handle);
G_GNUC_UNUSED static napi_value fdn_compiler_options_to_value (napi_env env, FridaCompilerOptions * handle);
static napi_value fdn_compiler_options_construct (napi_env env, napi_callback_info info);

static napi_value fdn_compiler_options_get_project_root (napi_env env, napi_callback_info info);

static napi_value fdn_compiler_options_set_project_root (napi_env env, napi_callback_info info);

static napi_value fdn_compiler_options_get_source_maps (napi_env env, napi_callback_info info);

static napi_value fdn_compiler_options_set_source_maps (napi_env env, napi_callback_info info);

static napi_value fdn_compiler_options_get_compression (napi_env env, napi_callback_info info);

static napi_value fdn_compiler_options_set_compression (napi_env env, napi_callback_info info);

static void fdn_build_options_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_build_options_from_value (napi_env env, napi_value value, FridaBuildOptions ** handle);
G_GNUC_UNUSED static napi_value fdn_build_options_to_value (napi_env env, FridaBuildOptions * handle);
static napi_value fdn_build_options_construct (napi_env env, napi_callback_info info);

static void fdn_watch_options_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_watch_options_from_value (napi_env env, napi_value value, FridaWatchOptions ** handle);
G_GNUC_UNUSED static napi_value fdn_watch_options_to_value (napi_env env, FridaWatchOptions * handle);
static napi_value fdn_watch_options_construct (napi_env env, napi_callback_info info);

static void fdn_static_authentication_service_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_static_authentication_service_from_value (napi_env env, napi_value value, FridaStaticAuthenticationService ** handle);
G_GNUC_UNUSED static napi_value fdn_static_authentication_service_to_value (napi_env env, FridaStaticAuthenticationService * handle);
static napi_value fdn_static_authentication_service_construct (napi_env env, napi_callback_info info);

static napi_value fdn_static_authentication_service_get_token_hash (napi_env env, napi_callback_info info);

static void fdn_frontmost_query_options_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_frontmost_query_options_from_value (napi_env env, napi_value value, FridaFrontmostQueryOptions ** handle);
G_GNUC_UNUSED static napi_value fdn_frontmost_query_options_to_value (napi_env env, FridaFrontmostQueryOptions * handle);
static napi_value fdn_frontmost_query_options_construct (napi_env env, napi_callback_info info);

static napi_value fdn_frontmost_query_options_get_scope (napi_env env, napi_callback_info info);

static napi_value fdn_frontmost_query_options_set_scope (napi_env env, napi_callback_info info);

static void fdn_application_query_options_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_application_query_options_from_value (napi_env env, napi_value value, FridaApplicationQueryOptions ** handle);
G_GNUC_UNUSED static napi_value fdn_application_query_options_to_value (napi_env env, FridaApplicationQueryOptions * handle);
static napi_value fdn_application_query_options_construct (napi_env env, napi_callback_info info);

static napi_value fdn_application_query_options_select_identifier (napi_env env, napi_callback_info info);

static napi_value fdn_application_query_options_has_selected_identifiers (napi_env env, napi_callback_info info);

static napi_value fdn_application_query_options_get_scope (napi_env env, napi_callback_info info);

static napi_value fdn_application_query_options_set_scope (napi_env env, napi_callback_info info);

static void fdn_process_query_options_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_process_query_options_from_value (napi_env env, napi_value value, FridaProcessQueryOptions ** handle);
G_GNUC_UNUSED static napi_value fdn_process_query_options_to_value (napi_env env, FridaProcessQueryOptions * handle);
static napi_value fdn_process_query_options_construct (napi_env env, napi_callback_info info);

static napi_value fdn_process_query_options_select_pid (napi_env env, napi_callback_info info);

static napi_value fdn_process_query_options_has_selected_pids (napi_env env, napi_callback_info info);

static napi_value fdn_process_query_options_get_scope (napi_env env, napi_callback_info info);

static napi_value fdn_process_query_options_set_scope (napi_env env, napi_callback_info info);

static void fdn_session_options_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_session_options_from_value (napi_env env, napi_value value, FridaSessionOptions ** handle);
G_GNUC_UNUSED static napi_value fdn_session_options_to_value (napi_env env, FridaSessionOptions * handle);
static napi_value fdn_session_options_construct (napi_env env, napi_callback_info info);

static napi_value fdn_session_options_get_realm (napi_env env, napi_callback_info info);

static napi_value fdn_session_options_set_realm (napi_env env, napi_callback_info info);

static napi_value fdn_session_options_get_persist_timeout (napi_env env, napi_callback_info info);

static napi_value fdn_session_options_set_persist_timeout (napi_env env, napi_callback_info info);

static napi_value fdn_session_options_get_emulated_agent_path (napi_env env, napi_callback_info info);

static napi_value fdn_session_options_set_emulated_agent_path (napi_env env, napi_callback_info info);

static void fdn_script_options_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_script_options_from_value (napi_env env, napi_value value, FridaScriptOptions ** handle);
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
G_GNUC_UNUSED static gboolean fdn_snapshot_options_from_value (napi_env env, napi_value value, FridaSnapshotOptions ** handle);
G_GNUC_UNUSED static napi_value fdn_snapshot_options_to_value (napi_env env, FridaSnapshotOptions * handle);
static napi_value fdn_snapshot_options_construct (napi_env env, napi_callback_info info);

static napi_value fdn_snapshot_options_get_warmup_script (napi_env env, napi_callback_info info);

static napi_value fdn_snapshot_options_set_warmup_script (napi_env env, napi_callback_info info);

static napi_value fdn_snapshot_options_get_runtime (napi_env env, napi_callback_info info);

static napi_value fdn_snapshot_options_set_runtime (napi_env env, napi_callback_info info);

static void fdn_portal_options_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_portal_options_from_value (napi_env env, napi_value value, FridaPortalOptions ** handle);
G_GNUC_UNUSED static napi_value fdn_portal_options_to_value (napi_env env, FridaPortalOptions * handle);
static napi_value fdn_portal_options_construct (napi_env env, napi_callback_info info);

static napi_value fdn_portal_options_get_certificate (napi_env env, napi_callback_info info);

static napi_value fdn_portal_options_set_certificate (napi_env env, napi_callback_info info);

static napi_value fdn_portal_options_get_token (napi_env env, napi_callback_info info);

static napi_value fdn_portal_options_set_token (napi_env env, napi_callback_info info);

static napi_value fdn_portal_options_get_acl (napi_env env, napi_callback_info info);

static napi_value fdn_portal_options_set_acl (napi_env env, napi_callback_info info);

static void fdn_peer_options_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_peer_options_from_value (napi_env env, napi_value value, FridaPeerOptions ** handle);
G_GNUC_UNUSED static napi_value fdn_peer_options_to_value (napi_env env, FridaPeerOptions * handle);
static napi_value fdn_peer_options_construct (napi_env env, napi_callback_info info);

static napi_value fdn_peer_options_clear_relays (napi_env env, napi_callback_info info);

static napi_value fdn_peer_options_add_relay (napi_env env, napi_callback_info info);

static napi_value fdn_peer_options_get_stun_server (napi_env env, napi_callback_info info);

static napi_value fdn_peer_options_set_stun_server (napi_env env, napi_callback_info info);

static void fdn_relay_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_relay_from_value (napi_env env, napi_value value, FridaRelay ** handle);
G_GNUC_UNUSED static napi_value fdn_relay_to_value (napi_env env, FridaRelay * handle);
static napi_value fdn_relay_construct (napi_env env, napi_callback_info info);

static napi_value fdn_relay_get_address (napi_env env, napi_callback_info info);

static napi_value fdn_relay_get_username (napi_env env, napi_callback_info info);

static napi_value fdn_relay_get_password (napi_env env, napi_callback_info info);

static napi_value fdn_relay_get_kind (napi_env env, napi_callback_info info);

static void fdn_endpoint_parameters_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_endpoint_parameters_from_value (napi_env env, napi_value value, FridaEndpointParameters ** handle);
G_GNUC_UNUSED static napi_value fdn_endpoint_parameters_to_value (napi_env env, FridaEndpointParameters * handle);
static napi_value fdn_endpoint_parameters_construct (napi_env env, napi_callback_info info);

static napi_value fdn_endpoint_parameters_get_address (napi_env env, napi_callback_info info);

static napi_value fdn_endpoint_parameters_get_port (napi_env env, napi_callback_info info);

static napi_value fdn_endpoint_parameters_get_certificate (napi_env env, napi_callback_info info);

static napi_value fdn_endpoint_parameters_get_origin (napi_env env, napi_callback_info info);

static napi_value fdn_endpoint_parameters_get_auth_service (napi_env env, napi_callback_info info);

static napi_value fdn_endpoint_parameters_get_asset_root (napi_env env, napi_callback_info info);

static napi_value fdn_endpoint_parameters_set_asset_root (napi_env env, napi_callback_info info);

static void fdn_service_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_service_from_value (napi_env env, napi_value value, FridaService ** handle);
G_GNUC_UNUSED static napi_value fdn_service_to_value (napi_env env, FridaService * handle);
static napi_value fdn_service_construct (napi_env env, napi_callback_info info);

static napi_value fdn_service_is_closed (napi_env env, napi_callback_info info);

static napi_value fdn_service_activate (napi_env env, napi_callback_info info);
static gboolean fdn_service_activate_begin (gpointer user_data);
static void fdn_service_activate_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void fdn_service_activate_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void fdn_service_activate_operation_free (FdnServiceActivateOperation * operation);

static napi_value fdn_service_cancel (napi_env env, napi_callback_info info);
static gboolean fdn_service_cancel_begin (gpointer user_data);
static void fdn_service_cancel_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void fdn_service_cancel_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void fdn_service_cancel_operation_free (FdnServiceCancelOperation * operation);

static napi_value fdn_service_request (napi_env env, napi_callback_info info);
static gboolean fdn_service_request_begin (gpointer user_data);
static void fdn_service_request_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void fdn_service_request_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void fdn_service_request_operation_free (FdnServiceRequestOperation * operation);

static napi_value fdn_service_get_close_signal (napi_env env, napi_callback_info info);
static napi_value fdn_service_get_message_signal (napi_env env, napi_callback_info info);

static void fdn_injector_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_injector_from_value (napi_env env, napi_value value, FridaInjector ** handle);
G_GNUC_UNUSED static napi_value fdn_injector_to_value (napi_env env, FridaInjector * handle);
static napi_value fdn_injector_construct (napi_env env, napi_callback_info info);

static napi_value fdn_injector_close (napi_env env, napi_callback_info info);
static gboolean fdn_injector_close_begin (gpointer user_data);
static void fdn_injector_close_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void fdn_injector_close_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void fdn_injector_close_operation_free (FdnInjectorCloseOperation * operation);

static napi_value fdn_injector_inject_library_file (napi_env env, napi_callback_info info);
static gboolean fdn_injector_inject_library_file_begin (gpointer user_data);
static void fdn_injector_inject_library_file_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void fdn_injector_inject_library_file_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void fdn_injector_inject_library_file_operation_free (FdnInjectorInjectLibraryFileOperation * operation);

static napi_value fdn_injector_inject_library_blob (napi_env env, napi_callback_info info);
static gboolean fdn_injector_inject_library_blob_begin (gpointer user_data);
static void fdn_injector_inject_library_blob_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void fdn_injector_inject_library_blob_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void fdn_injector_inject_library_blob_operation_free (FdnInjectorInjectLibraryBlobOperation * operation);

static napi_value fdn_injector_demonitor (napi_env env, napi_callback_info info);
static gboolean fdn_injector_demonitor_begin (gpointer user_data);
static void fdn_injector_demonitor_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void fdn_injector_demonitor_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void fdn_injector_demonitor_operation_free (FdnInjectorDemonitorOperation * operation);

static napi_value fdn_injector_demonitor_and_clone_state (napi_env env, napi_callback_info info);
static gboolean fdn_injector_demonitor_and_clone_state_begin (gpointer user_data);
static void fdn_injector_demonitor_and_clone_state_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void fdn_injector_demonitor_and_clone_state_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void fdn_injector_demonitor_and_clone_state_operation_free (FdnInjectorDemonitorAndCloneStateOperation * operation);

static napi_value fdn_injector_recreate_thread (napi_env env, napi_callback_info info);
static gboolean fdn_injector_recreate_thread_begin (gpointer user_data);
static void fdn_injector_recreate_thread_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void fdn_injector_recreate_thread_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void fdn_injector_recreate_thread_operation_free (FdnInjectorRecreateThreadOperation * operation);

static napi_value fdn_injector_get_uninjected_signal (napi_env env, napi_callback_info info);

static void fdn_authentication_service_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_authentication_service_from_value (napi_env env, napi_value value, FridaAuthenticationService ** handle);
G_GNUC_UNUSED static napi_value fdn_authentication_service_to_value (napi_env env, FridaAuthenticationService * handle);
static napi_value fdn_authentication_service_construct (napi_env env, napi_callback_info info);

static napi_value fdn_authentication_service_authenticate (napi_env env, napi_callback_info info);
static gboolean fdn_authentication_service_authenticate_begin (gpointer user_data);
static void fdn_authentication_service_authenticate_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void fdn_authentication_service_authenticate_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void fdn_authentication_service_authenticate_operation_free (FdnAuthenticationServiceAuthenticateOperation * operation);

static void fdn_cancellable_register (napi_env env, napi_value exports);
G_GNUC_UNUSED static gboolean fdn_cancellable_from_value (napi_env env, napi_value value, GCancellable ** handle);
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

static napi_value fdn_cancellable_get_cancelled_signal (napi_env env, napi_callback_info info);

G_GNUC_UNUSED static gboolean fdn_runtime_from_value (napi_env env, napi_value value, FridaRuntime * e);
G_GNUC_UNUSED static napi_value fdn_runtime_to_value (napi_env env, FridaRuntime e);

G_GNUC_UNUSED static gboolean fdn_device_type_from_value (napi_env env, napi_value value, FridaDeviceType * e);
G_GNUC_UNUSED static napi_value fdn_device_type_to_value (napi_env env, FridaDeviceType e);

G_GNUC_UNUSED static gboolean fdn_source_maps_from_value (napi_env env, napi_value value, FridaSourceMaps * e);
G_GNUC_UNUSED static napi_value fdn_source_maps_to_value (napi_env env, FridaSourceMaps e);

G_GNUC_UNUSED static gboolean fdn_js_compression_from_value (napi_env env, napi_value value, FridaJsCompression * e);
G_GNUC_UNUSED static napi_value fdn_js_compression_to_value (napi_env env, FridaJsCompression e);

G_GNUC_UNUSED static gboolean fdn_agent_message_kind_from_value (napi_env env, napi_value value, FridaAgentMessageKind * e);
G_GNUC_UNUSED static napi_value fdn_agent_message_kind_to_value (napi_env env, FridaAgentMessageKind e);

G_GNUC_UNUSED static gboolean fdn_realm_from_value (napi_env env, napi_value value, FridaRealm * e);
G_GNUC_UNUSED static napi_value fdn_realm_to_value (napi_env env, FridaRealm e);

G_GNUC_UNUSED static gboolean fdn_unload_policy_from_value (napi_env env, napi_value value, FridaUnloadPolicy * e);
G_GNUC_UNUSED static napi_value fdn_unload_policy_to_value (napi_env env, FridaUnloadPolicy e);

G_GNUC_UNUSED static gboolean fdn_session_detach_reason_from_value (napi_env env, napi_value value, FridaSessionDetachReason * e);
G_GNUC_UNUSED static napi_value fdn_session_detach_reason_to_value (napi_env env, FridaSessionDetachReason e);

G_GNUC_UNUSED static gboolean fdn_scope_from_value (napi_env env, napi_value value, FridaScope * e);
G_GNUC_UNUSED static napi_value fdn_scope_to_value (napi_env env, FridaScope e);

G_GNUC_UNUSED static gboolean fdn_stdio_from_value (napi_env env, napi_value value, FridaStdio * e);
G_GNUC_UNUSED static napi_value fdn_stdio_to_value (napi_env env, FridaStdio e);

G_GNUC_UNUSED static gboolean fdn_child_origin_from_value (napi_env env, napi_value value, FridaChildOrigin * e);
G_GNUC_UNUSED static napi_value fdn_child_origin_to_value (napi_env env, FridaChildOrigin e);

G_GNUC_UNUSED static gboolean fdn_snapshot_transport_from_value (napi_env env, napi_value value, FridaSnapshotTransport * e);
G_GNUC_UNUSED static napi_value fdn_snapshot_transport_to_value (napi_env env, FridaSnapshotTransport e);

G_GNUC_UNUSED static gboolean fdn_script_runtime_from_value (napi_env env, napi_value value, FridaScriptRuntime * e);
G_GNUC_UNUSED static napi_value fdn_script_runtime_to_value (napi_env env, FridaScriptRuntime e);

G_GNUC_UNUSED static gboolean fdn_relay_kind_from_value (napi_env env, napi_value value, FridaRelayKind * e);
G_GNUC_UNUSED static napi_value fdn_relay_kind_to_value (napi_env env, FridaRelayKind e);

G_GNUC_UNUSED static gboolean fdn_peer_setup_from_value (napi_env env, napi_value value, FridaPeerSetup * e);
G_GNUC_UNUSED static napi_value fdn_peer_setup_to_value (napi_env env, FridaPeerSetup e);

G_GNUC_UNUSED static gboolean fdn_web_service_transport_from_value (napi_env env, napi_value value, FridaWebServiceTransport * e);
G_GNUC_UNUSED static napi_value fdn_web_service_transport_to_value (napi_env env, FridaWebServiceTransport e);

G_GNUC_UNUSED static gboolean fdn_web_service_flavor_from_value (napi_env env, napi_value value, FridaWebServiceFlavor * e);
G_GNUC_UNUSED static napi_value fdn_web_service_flavor_to_value (napi_env env, FridaWebServiceFlavor e);

G_GNUC_UNUSED static gboolean fdn_port_conflict_behavior_from_value (napi_env env, napi_value value, FridaPortConflictBehavior * e);
G_GNUC_UNUSED static napi_value fdn_port_conflict_behavior_to_value (napi_env env, FridaPortConflictBehavior e);

G_GNUC_UNUSED static gboolean fdn_string_terminator_from_value (napi_env env, napi_value value, FridaStringTerminator * e);
G_GNUC_UNUSED static napi_value fdn_string_terminator_to_value (napi_env env, FridaStringTerminator e);
static gboolean fdn_is_undefined_or_null (napi_env env, napi_value value);

static gboolean fdn_boolean_from_value (napi_env env, napi_value value, gboolean * b);
static napi_value fdn_boolean_to_value (napi_env env, gboolean b);
static gboolean fdn_int_from_value (napi_env env, napi_value value, gint * i);
static napi_value fdn_int_to_value (napi_env env, gint i);
static gboolean fdn_uint_from_value (napi_env env, napi_value value, guint * u);
static napi_value fdn_uint_to_value (napi_env env, guint u);
static gboolean fdn_uint16_from_value (napi_env env, napi_value value, guint16 * u);
static napi_value fdn_uint16_to_value (napi_env env, guint16 u);
static gboolean fdn_int64_from_value (napi_env env, napi_value value, gint64 * i);
static napi_value fdn_int64_to_value (napi_env env, gint64 i);
static napi_value fdn_uint64_to_value (napi_env env, guint64 u);
static gboolean fdn_ulong_from_value (napi_env env, napi_value value, gulong * u);
static napi_value fdn_double_to_value (napi_env env, gdouble d);
static gboolean fdn_enum_from_value (napi_env env, GType enum_type, napi_value value, gint * e);
static napi_value fdn_enum_to_value (napi_env env, GType enum_type, gint e);
static gboolean fdn_utf8_from_value (napi_env env, napi_value value, gchar ** str);
static napi_value fdn_utf8_to_value (napi_env env, const gchar * str);
static gboolean fdn_strv_from_value (napi_env env, napi_value value, gchar *** strv);
static napi_value fdn_strv_to_value (napi_env env, gchar ** strv);
static napi_value fdn_buffer_to_value (napi_env env, const guint8 * data, gsize size);
static gboolean fdn_bytes_from_value (napi_env env, napi_value value, GBytes ** bytes);
static napi_value fdn_bytes_to_value (napi_env env, GBytes * bytes);
static gboolean fdn_vardict_from_value (napi_env env, napi_value value, GHashTable ** vardict);
static napi_value fdn_vardict_to_value (napi_env env, GHashTable * vardict);
static gboolean fdn_variant_from_value (napi_env env, napi_value value, GVariant ** variant);
static napi_value fdn_variant_to_value (napi_env env, GVariant * variant);
static gboolean fdn_file_from_value (napi_env env, napi_value value, GFile ** file);
static napi_value fdn_file_to_value (napi_env env, GFile * file);
static gboolean fdn_tls_certificate_from_value (napi_env env, napi_value value, GTlsCertificate ** certificate);
static napi_value fdn_tls_certificate_to_value (napi_env env, GTlsCertificate * certificate);
static napi_value fdn_io_stream_to_value (napi_env env, GIOStream * stream);

static void fdn_object_finalize (napi_env env, void * finalize_data, void * finalize_hint);
static napi_value fdn_object_get_signal (napi_env env, napi_callback_info info, const gchar * name, const gchar * js_storage_name);

static napi_value fdn_signal_new (napi_env env, GObject * handle, const gchar * name);
static void fdn_signal_register (napi_env env, napi_value exports);
static napi_value fdn_signal_construct (napi_env env, napi_callback_info info);
static napi_value fdn_signal_connect (napi_env env, napi_callback_info info);
static napi_value fdn_signal_disconnect (napi_env env, napi_callback_info info);

static napi_type_tag fdn_handle_wrapper_type_tag = { 0xdd596d4f2dad45f9, 0x844585a48e8d05ba };
static napi_type_tag fdn_device_manager_type_tag = { 0xf777907979a649a8, 0x99a72f46b6f35500 };
static napi_type_tag fdn_device_type_tag = { 0x3b0f3f24cb7b4632, 0xb15f019e434eff5a };
static napi_type_tag fdn_remote_device_options_type_tag = { 0xd8e20474d20f4df2, 0xa3148e53e59b413a };
static napi_type_tag fdn_application_type_tag = { 0x1f87a08c73d44bb8, 0xb3455e21e848470c };
static napi_type_tag fdn_process_type_tag = { 0xe6083618972c4150, 0x80b6d2ab5014b7ad };
static napi_type_tag fdn_process_match_options_type_tag = { 0xb9307dc71f0241b1, 0x9354233cb934dc9c };
static napi_type_tag fdn_spawn_options_type_tag = { 0xf91612b6f6b54a7d, 0x8b72a5007152f6f0 };
static napi_type_tag fdn_spawn_type_tag = { 0x1474be4318694256, 0x92194ac5ebe509a7 };
static napi_type_tag fdn_child_type_tag = { 0x062c2866fb0b4ae5, 0x8dc8a9e7ea418331 };
static napi_type_tag fdn_crash_type_tag = { 0x86f33169501c4b41, 0xb5fa3d5c918c0a49 };
static napi_type_tag fdn_bus_type_tag = { 0xc0de5bb481e94c90, 0xbed2b1c0cddc8b5a };
static napi_type_tag fdn_session_type_tag = { 0xcc11a656c37046a7, 0x8ea546d0b69c8772 };
static napi_type_tag fdn_script_type_tag = { 0x3c2ae660317d491f, 0xa4652db2d7633ca5 };
static napi_type_tag fdn_portal_membership_type_tag = { 0xe2a71277e85142fa, 0xa5a69f813f3a621e };
static napi_type_tag fdn_control_service_options_type_tag = { 0x36d224750b6b4df4, 0xbff89872aa3dc577 };
static napi_type_tag fdn_portal_service_type_tag = { 0x457a01791d244816, 0xbd1bdc7115d3105b };
static napi_type_tag fdn_file_monitor_type_tag = { 0x9166826820434d73, 0x8055667c6c29933c };
static napi_type_tag fdn_compiler_type_tag = { 0x4d62694d4ca94b2c, 0xb6709ff714e8d200 };
static napi_type_tag fdn_compiler_options_type_tag = { 0xea7fa5c63d3f4881, 0xa0b4496fa0efde66 };
static napi_type_tag fdn_build_options_type_tag = { 0xffe2cce12cdb4093, 0xa02b3c89e11e65e4 };
static napi_type_tag fdn_watch_options_type_tag = { 0x3864ea12ca9c4b0a, 0xad0a962f2dfb8810 };
static napi_type_tag fdn_static_authentication_service_type_tag = { 0x34ecb77e0eff4f37, 0xa86546fa2d37d4af };
static napi_type_tag fdn_frontmost_query_options_type_tag = { 0x5d150c016f964708, 0x92297f25f67ea2e5 };
static napi_type_tag fdn_application_query_options_type_tag = { 0x4f6ac1f7b4894180, 0xa5da23b25b4bb8f8 };
static napi_type_tag fdn_process_query_options_type_tag = { 0x8f959d3f9d8b4503, 0xaa84fe655025dc68 };
static napi_type_tag fdn_session_options_type_tag = { 0x680ebae3dfa1443c, 0xb06ccbf64d1b4d32 };
static napi_type_tag fdn_script_options_type_tag = { 0xf29155a818f74fee, 0xb9fd7a141dd4eff1 };
static napi_type_tag fdn_snapshot_options_type_tag = { 0xbffeec72b0b64ca5, 0x81d54e89479157bd };
static napi_type_tag fdn_portal_options_type_tag = { 0xccfcd15868dc4351, 0xb608b8952756bb93 };
static napi_type_tag fdn_peer_options_type_tag = { 0x118ad6b51c5d4795, 0xacf1856ecfa3a0fa };
static napi_type_tag fdn_relay_type_tag = { 0x6381b6f0d46e474c, 0x9adfd2d938b59c7c };
static napi_type_tag fdn_endpoint_parameters_type_tag = { 0x643a1730a722465b, 0xa83f3536520318f6 };
static napi_type_tag fdn_service_type_tag = { 0x1cc7fbcd38e7484e, 0x81612eeadf76e9c7 };
static napi_type_tag fdn_injector_type_tag = { 0xfac32c9eb1cf4fbf, 0x944c87e4fc58f9f2 };
static napi_type_tag fdn_authentication_service_type_tag = { 0xc265f2f53f894a59, 0xbf8e9f18244323d0 };
static napi_type_tag fdn_cancellable_type_tag = { 0x3a83224f057f4b00, 0xaaa85f2a4c339221 };

static napi_ref fdn_device_manager_constructor;
static napi_ref fdn_device_constructor;
static napi_ref fdn_remote_device_options_constructor;
static napi_ref fdn_application_constructor;
static napi_ref fdn_process_constructor;
static napi_ref fdn_process_match_options_constructor;
static napi_ref fdn_spawn_options_constructor;
static napi_ref fdn_spawn_constructor;
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
static napi_ref fdn_service_constructor;
static napi_ref fdn_injector_constructor;
static napi_ref fdn_authentication_service_constructor;
static napi_ref fdn_cancellable_constructor;

static napi_ref fdn_signal_constructor;

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

static napi_threadsafe_function fdn_service_activate_tsfn;
static napi_threadsafe_function fdn_service_cancel_tsfn;
static napi_threadsafe_function fdn_service_request_tsfn;

static napi_threadsafe_function fdn_injector_close_tsfn;
static napi_threadsafe_function fdn_injector_inject_library_file_tsfn;
static napi_threadsafe_function fdn_injector_inject_library_blob_tsfn;
static napi_threadsafe_function fdn_injector_demonitor_tsfn;
static napi_threadsafe_function fdn_injector_demonitor_and_clone_state_tsfn;
static napi_threadsafe_function fdn_injector_recreate_thread_tsfn;

static napi_threadsafe_function fdn_authentication_service_authenticate_tsfn;

static napi_value
fdn_init (napi_env env,
          napi_value exports)
{
  frida_init ();

  fdn_device_manager_register (env, exports);
  fdn_device_register (env, exports);
  fdn_remote_device_options_register (env, exports);
  fdn_application_register (env, exports);
  fdn_process_register (env, exports);
  fdn_process_match_options_register (env, exports);
  fdn_spawn_options_register (env, exports);
  fdn_spawn_register (env, exports);
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
  fdn_service_register (env, exports);
  fdn_injector_register (env, exports);
  fdn_authentication_service_register (env, exports);
  fdn_cancellable_register (env, exports);

  fdn_signal_register (env, exports);

  return exports;
}

NAPI_MODULE (NODE_GYP_MODULE_NAME, fdn_init)

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
    { "added", NULL, NULL, fdn_device_manager_get_added_signal, NULL, NULL, napi_default, NULL },
    { "removed", NULL, NULL, fdn_device_manager_get_removed_signal, NULL, NULL, napi_default, NULL },
    { "changed", NULL, NULL, fdn_device_manager_get_changed_signal, NULL, NULL, napi_default, NULL },
  };

  napi_value constructor;
  napi_define_class (env, "DeviceManager", NAPI_AUTO_LENGTH, fdn_device_manager_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_device_manager_constructor);

  napi_set_named_property (env, exports, "DeviceManager", constructor);

  napi_value resource_name;

  napi_create_string_utf8 (env, "close", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_device_manager_close_deliver, &fdn_device_manager_close_tsfn);
  napi_unref_threadsafe_function (env, fdn_device_manager_close_tsfn);

  napi_create_string_utf8 (env, "getDeviceById", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_device_manager_get_device_by_id_deliver, &fdn_device_manager_get_device_by_id_tsfn);
  napi_unref_threadsafe_function (env, fdn_device_manager_get_device_by_id_tsfn);

  napi_create_string_utf8 (env, "getDeviceByType", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_device_manager_get_device_by_type_deliver, &fdn_device_manager_get_device_by_type_tsfn);
  napi_unref_threadsafe_function (env, fdn_device_manager_get_device_by_type_tsfn);

  napi_create_string_utf8 (env, "findDeviceById", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_device_manager_find_device_by_id_deliver, &fdn_device_manager_find_device_by_id_tsfn);
  napi_unref_threadsafe_function (env, fdn_device_manager_find_device_by_id_tsfn);

  napi_create_string_utf8 (env, "findDeviceByType", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_device_manager_find_device_by_type_deliver, &fdn_device_manager_find_device_by_type_tsfn);
  napi_unref_threadsafe_function (env, fdn_device_manager_find_device_by_type_tsfn);

  napi_create_string_utf8 (env, "enumerateDevices", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_device_manager_enumerate_devices_deliver, &fdn_device_manager_enumerate_devices_tsfn);
  napi_unref_threadsafe_function (env, fdn_device_manager_enumerate_devices_tsfn);

  napi_create_string_utf8 (env, "addRemoteDevice", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_device_manager_add_remote_device_deliver, &fdn_device_manager_add_remote_device_tsfn);
  napi_unref_threadsafe_function (env, fdn_device_manager_add_remote_device_tsfn);

  napi_create_string_utf8 (env, "removeRemoteDevice", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_device_manager_remove_remote_device_deliver, &fdn_device_manager_remove_remote_device_tsfn);
  napi_unref_threadsafe_function (env, fdn_device_manager_remove_remote_device_tsfn);
}

static gboolean
fdn_device_manager_from_value (napi_env env,
                               napi_value value,
                               FridaDeviceManager ** handle)
{
  bool is_instance;

  if (napi_check_object_type_tag (env, value, &fdn_device_manager_type_tag, &is_instance) != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of DeviceManager");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) handle);

  g_object_ref (*handle);

  return TRUE;
}

static napi_value
fdn_device_manager_to_value (napi_env env,
                             FridaDeviceManager * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_device_manager_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);
  napi_type_tag_object (env, handle_wrapper, &fdn_handle_wrapper_type_tag);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_device_manager_construct (napi_env env,
                              napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaDeviceManager * handle = NULL;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto propagate_error;

  if (argc == 0)
  {
    handle = frida_device_manager_new ();
  }
  else
  {
    bool is_instance;

    if (napi_check_object_type_tag (env, args[0], &fdn_handle_wrapper_type_tag, &is_instance) != napi_ok || !is_instance)
      goto invalid_handle;

    if (napi_get_value_external (env, args[0], (void **) &handle) != napi_ok)
      goto propagate_error;

    g_object_ref (handle);
  }

  if (napi_type_tag_object (env, jsthis, &fdn_device_manager_type_tag) != napi_ok)
    goto propagate_error;

  if (napi_wrap (env, jsthis, handle, NULL, NULL, NULL) != napi_ok)
    goto propagate_error;

  if (napi_add_finalizer (env, jsthis, handle, fdn_object_finalize, NULL, NULL) != napi_ok)
    goto propagate_error;

  return jsthis;

invalid_handle:
  {
    napi_throw_type_error (env, NULL, "expected a DeviceManager handle");
    goto propagate_error;
  }
propagate_error:
  {
    g_clear_object (&handle);
    return NULL;
  }
}

static napi_value
fdn_device_manager_close (napi_env env,
                          napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaDeviceManager * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnDeviceManagerCloseOperation * operation;
  GSource * source;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    return NULL;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    return NULL;

  napi_create_promise (env, &deferred, &promise);

  operation = g_slice_new0 (FdnDeviceManagerCloseOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
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
    napi_value js_retval;
    napi_get_undefined (env, &js_retval);
    napi_resolve_deferred (env, operation->deferred, js_retval);
  }

  fdn_device_manager_close_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_device_manager_close_tsfn);
}

static void
fdn_device_manager_close_operation_free (FdnDeviceManagerCloseOperation * operation)
{
  g_clear_pointer (&operation->cancellable, g_object_unref);
  g_slice_free (FdnDeviceManagerCloseOperation, operation);
}

static napi_value
fdn_device_manager_get_device_by_id (napi_env env,
                                     napi_callback_info info)
{
  size_t argc = 3;
  napi_value args[3];
  napi_value jsthis;
  FridaDeviceManager * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnDeviceManagerGetDeviceByIdOperation * operation;
  GSource * source;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    return NULL;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    return NULL;

  napi_create_promise (env, &deferred, &promise);

  operation = g_slice_new0 (FdnDeviceManagerGetDeviceByIdOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_utf8_from_value (env, args[0], &operation->id))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: id");
    goto invalid_argument;
  }

  if (argc > 1 && !fdn_is_undefined_or_null (env, args[1]))
  {
    if (!fdn_int_from_value (env, args[1], &operation->timeout))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: timeout");
    goto invalid_argument;
  }

  if (argc > 2 && !fdn_is_undefined_or_null (env, args[2]))
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

  

  operation->retval = frida_device_manager_get_device_by_id_finish (operation->handle, res,
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
    napi_value js_retval;
    js_retval = fdn_device_to_value (env, operation->retval);
    napi_resolve_deferred (env, operation->deferred, js_retval);
  }

  fdn_device_manager_get_device_by_id_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_device_manager_get_device_by_id_tsfn);
}

static void
fdn_device_manager_get_device_by_id_operation_free (FdnDeviceManagerGetDeviceByIdOperation * operation)
{
  g_clear_pointer (&operation->id, g_free);
  g_clear_pointer (&operation->cancellable, g_object_unref);
  g_clear_pointer (&operation->retval, frida_unref);
  g_slice_free (FdnDeviceManagerGetDeviceByIdOperation, operation);
}

static napi_value
fdn_device_manager_get_device_by_type (napi_env env,
                                       napi_callback_info info)
{
  size_t argc = 3;
  napi_value args[3];
  napi_value jsthis;
  FridaDeviceManager * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnDeviceManagerGetDeviceByTypeOperation * operation;
  GSource * source;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    return NULL;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    return NULL;

  napi_create_promise (env, &deferred, &promise);

  operation = g_slice_new0 (FdnDeviceManagerGetDeviceByTypeOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_device_type_from_value (env, args[0], &operation->type))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: type");
    goto invalid_argument;
  }

  if (argc > 1 && !fdn_is_undefined_or_null (env, args[1]))
  {
    if (!fdn_int_from_value (env, args[1], &operation->timeout))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: timeout");
    goto invalid_argument;
  }

  if (argc > 2 && !fdn_is_undefined_or_null (env, args[2]))
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

  

  operation->retval = frida_device_manager_get_device_by_type_finish (operation->handle, res,
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
    napi_value js_retval;
    js_retval = fdn_device_to_value (env, operation->retval);
    napi_resolve_deferred (env, operation->deferred, js_retval);
  }

  fdn_device_manager_get_device_by_type_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_device_manager_get_device_by_type_tsfn);
}

static void
fdn_device_manager_get_device_by_type_operation_free (FdnDeviceManagerGetDeviceByTypeOperation * operation)
{
  g_clear_pointer (&operation->cancellable, g_object_unref);
  g_clear_pointer (&operation->retval, frida_unref);
  g_slice_free (FdnDeviceManagerGetDeviceByTypeOperation, operation);
}

static napi_value
fdn_device_manager_find_device_by_id (napi_env env,
                                      napi_callback_info info)
{
  size_t argc = 3;
  napi_value args[3];
  napi_value jsthis;
  FridaDeviceManager * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnDeviceManagerFindDeviceByIdOperation * operation;
  GSource * source;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    return NULL;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    return NULL;

  napi_create_promise (env, &deferred, &promise);

  operation = g_slice_new0 (FdnDeviceManagerFindDeviceByIdOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_utf8_from_value (env, args[0], &operation->id))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: id");
    goto invalid_argument;
  }

  if (argc > 1 && !fdn_is_undefined_or_null (env, args[1]))
  {
    if (!fdn_int_from_value (env, args[1], &operation->timeout))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: timeout");
    goto invalid_argument;
  }

  if (argc > 2 && !fdn_is_undefined_or_null (env, args[2]))
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

  

  operation->retval = frida_device_manager_find_device_by_id_finish (operation->handle, res,
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
    napi_value js_retval;
    if (operation->retval != NULL)
      js_retval = fdn_device_to_value (env, operation->retval);
    else
      napi_get_null (env, &js_retval);
    napi_resolve_deferred (env, operation->deferred, js_retval);
  }

  fdn_device_manager_find_device_by_id_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_device_manager_find_device_by_id_tsfn);
}

static void
fdn_device_manager_find_device_by_id_operation_free (FdnDeviceManagerFindDeviceByIdOperation * operation)
{
  g_clear_pointer (&operation->id, g_free);
  g_clear_pointer (&operation->cancellable, g_object_unref);
  g_clear_pointer (&operation->retval, frida_unref);
  g_slice_free (FdnDeviceManagerFindDeviceByIdOperation, operation);
}

static napi_value
fdn_device_manager_find_device_by_type (napi_env env,
                                        napi_callback_info info)
{
  size_t argc = 3;
  napi_value args[3];
  napi_value jsthis;
  FridaDeviceManager * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnDeviceManagerFindDeviceByTypeOperation * operation;
  GSource * source;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    return NULL;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    return NULL;

  napi_create_promise (env, &deferred, &promise);

  operation = g_slice_new0 (FdnDeviceManagerFindDeviceByTypeOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_device_type_from_value (env, args[0], &operation->type))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: type");
    goto invalid_argument;
  }

  if (argc > 1 && !fdn_is_undefined_or_null (env, args[1]))
  {
    if (!fdn_int_from_value (env, args[1], &operation->timeout))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: timeout");
    goto invalid_argument;
  }

  if (argc > 2 && !fdn_is_undefined_or_null (env, args[2]))
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

  

  operation->retval = frida_device_manager_find_device_by_type_finish (operation->handle, res,
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
    napi_value js_retval;
    if (operation->retval != NULL)
      js_retval = fdn_device_to_value (env, operation->retval);
    else
      napi_get_null (env, &js_retval);
    napi_resolve_deferred (env, operation->deferred, js_retval);
  }

  fdn_device_manager_find_device_by_type_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_device_manager_find_device_by_type_tsfn);
}

static void
fdn_device_manager_find_device_by_type_operation_free (FdnDeviceManagerFindDeviceByTypeOperation * operation)
{
  g_clear_pointer (&operation->cancellable, g_object_unref);
  g_clear_pointer (&operation->retval, frida_unref);
  g_slice_free (FdnDeviceManagerFindDeviceByTypeOperation, operation);
}

static napi_value
fdn_device_manager_enumerate_devices (napi_env env,
                                      napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaDeviceManager * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnDeviceManagerEnumerateDevicesOperation * operation;
  GSource * source;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    return NULL;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    return NULL;

  napi_create_promise (env, &deferred, &promise);

  operation = g_slice_new0 (FdnDeviceManagerEnumerateDevicesOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
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

  

  operation->retval = frida_device_manager_enumerate_devices_finish (operation->handle, res,
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
    napi_value js_retval;
    js_retval = fdn_device_list_to_value (env, operation->retval);
    napi_resolve_deferred (env, operation->deferred, js_retval);
  }

  fdn_device_manager_enumerate_devices_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_device_manager_enumerate_devices_tsfn);
}

static void
fdn_device_manager_enumerate_devices_operation_free (FdnDeviceManagerEnumerateDevicesOperation * operation)
{
  g_clear_pointer (&operation->cancellable, g_object_unref);
  g_clear_pointer (&operation->retval, frida_unref);
  g_slice_free (FdnDeviceManagerEnumerateDevicesOperation, operation);
}

static napi_value
fdn_device_manager_add_remote_device (napi_env env,
                                      napi_callback_info info)
{
  size_t argc = 3;
  napi_value args[3];
  napi_value jsthis;
  FridaDeviceManager * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnDeviceManagerAddRemoteDeviceOperation * operation;
  GSource * source;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    return NULL;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    return NULL;

  napi_create_promise (env, &deferred, &promise);

  operation = g_slice_new0 (FdnDeviceManagerAddRemoteDeviceOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_utf8_from_value (env, args[0], &operation->address))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: address");
    goto invalid_argument;
  }

  if (argc > 1 && !fdn_is_undefined_or_null (env, args[1]))
  {
    if (!fdn_remote_device_options_from_value (env, args[1], &operation->options))
      goto invalid_argument;
  }
  else
  {
    operation->options = NULL;
  }

  if (argc > 2 && !fdn_is_undefined_or_null (env, args[2]))
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

  

  operation->retval = frida_device_manager_add_remote_device_finish (operation->handle, res,
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
    napi_value js_retval;
    js_retval = fdn_device_to_value (env, operation->retval);
    napi_resolve_deferred (env, operation->deferred, js_retval);
  }

  fdn_device_manager_add_remote_device_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_device_manager_add_remote_device_tsfn);
}

static void
fdn_device_manager_add_remote_device_operation_free (FdnDeviceManagerAddRemoteDeviceOperation * operation)
{
  g_clear_pointer (&operation->address, g_free);
  g_clear_pointer (&operation->options, frida_unref);
  g_clear_pointer (&operation->cancellable, g_object_unref);
  g_clear_pointer (&operation->retval, frida_unref);
  g_slice_free (FdnDeviceManagerAddRemoteDeviceOperation, operation);
}

static napi_value
fdn_device_manager_remove_remote_device (napi_env env,
                                         napi_callback_info info)
{
  size_t argc = 2;
  napi_value args[2];
  napi_value jsthis;
  FridaDeviceManager * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnDeviceManagerRemoveRemoteDeviceOperation * operation;
  GSource * source;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    return NULL;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    return NULL;

  napi_create_promise (env, &deferred, &promise);

  operation = g_slice_new0 (FdnDeviceManagerRemoveRemoteDeviceOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_utf8_from_value (env, args[0], &operation->address))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: address");
    goto invalid_argument;
  }

  if (argc > 1 && !fdn_is_undefined_or_null (env, args[1]))
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
    napi_value js_retval;
    napi_get_undefined (env, &js_retval);
    napi_resolve_deferred (env, operation->deferred, js_retval);
  }

  fdn_device_manager_remove_remote_device_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_device_manager_remove_remote_device_tsfn);
}

static void
fdn_device_manager_remove_remote_device_operation_free (FdnDeviceManagerRemoveRemoteDeviceOperation * operation)
{
  g_clear_pointer (&operation->address, g_free);
  g_clear_pointer (&operation->cancellable, g_object_unref);
  g_slice_free (FdnDeviceManagerRemoveRemoteDeviceOperation, operation);
}

static napi_value
fdn_device_manager_get_added_signal (napi_env env,
                                     napi_callback_info info)
{
  return fdn_object_get_signal (env, info, "added", "_added");
}

static napi_value
fdn_device_manager_get_removed_signal (napi_env env,
                                       napi_callback_info info)
{
  return fdn_object_get_signal (env, info, "removed", "_removed");
}

static napi_value
fdn_device_manager_get_changed_signal (napi_env env,
                                       napi_callback_info info)
{
  return fdn_object_get_signal (env, info, "changed", "_changed");
}

static napi_value
fdn_device_list_to_value (napi_env env,
                          FridaDeviceList * list)
{
  napi_value result;
  gint size, i;

  size = frida_device_list_size (list);
  napi_create_array_with_length (env, size, &result);

  for (i = 0; i != size; i++)
  {
    FridaDevice * handle = frida_device_list_get (list, i);
    napi_set_element (env, result, i, fdn_device_to_value (env, handle));
    g_object_unref (handle);
  }

  return result;
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
    { "id", NULL, NULL, fdn_device_get_id, NULL, NULL, napi_enumerable | napi_configurable, NULL },
    { "name", NULL, NULL, fdn_device_get_name, NULL, NULL, napi_enumerable | napi_configurable, NULL },
    { "icon", NULL, NULL, fdn_device_get_icon, NULL, NULL, napi_enumerable | napi_configurable, NULL },
    { "dtype", NULL, NULL, fdn_device_get_dtype, NULL, NULL, napi_enumerable | napi_configurable, NULL },
    { "bus", NULL, NULL, fdn_device_get_bus, NULL, NULL, napi_enumerable | napi_configurable, NULL },
    { "spawnAdded", NULL, NULL, fdn_device_get_spawn_added_signal, NULL, NULL, napi_default, NULL },
    { "spawnRemoved", NULL, NULL, fdn_device_get_spawn_removed_signal, NULL, NULL, napi_default, NULL },
    { "childAdded", NULL, NULL, fdn_device_get_child_added_signal, NULL, NULL, napi_default, NULL },
    { "childRemoved", NULL, NULL, fdn_device_get_child_removed_signal, NULL, NULL, napi_default, NULL },
    { "processCrashed", NULL, NULL, fdn_device_get_process_crashed_signal, NULL, NULL, napi_default, NULL },
    { "output", NULL, NULL, fdn_device_get_output_signal, NULL, NULL, napi_default, NULL },
    { "uninjected", NULL, NULL, fdn_device_get_uninjected_signal, NULL, NULL, napi_default, NULL },
    { "lost", NULL, NULL, fdn_device_get_lost_signal, NULL, NULL, napi_default, NULL },
  };

  napi_value constructor;
  napi_define_class (env, "Device", NAPI_AUTO_LENGTH, fdn_device_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_device_constructor);

  napi_set_named_property (env, exports, "Device", constructor);

  napi_value resource_name;

  napi_create_string_utf8 (env, "querySystemParameters", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_device_query_system_parameters_deliver, &fdn_device_query_system_parameters_tsfn);
  napi_unref_threadsafe_function (env, fdn_device_query_system_parameters_tsfn);

  napi_create_string_utf8 (env, "getFrontmostApplication", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_device_get_frontmost_application_deliver, &fdn_device_get_frontmost_application_tsfn);
  napi_unref_threadsafe_function (env, fdn_device_get_frontmost_application_tsfn);

  napi_create_string_utf8 (env, "enumerateApplications", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_device_enumerate_applications_deliver, &fdn_device_enumerate_applications_tsfn);
  napi_unref_threadsafe_function (env, fdn_device_enumerate_applications_tsfn);

  napi_create_string_utf8 (env, "getProcessByPid", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_device_get_process_by_pid_deliver, &fdn_device_get_process_by_pid_tsfn);
  napi_unref_threadsafe_function (env, fdn_device_get_process_by_pid_tsfn);

  napi_create_string_utf8 (env, "getProcessByName", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_device_get_process_by_name_deliver, &fdn_device_get_process_by_name_tsfn);
  napi_unref_threadsafe_function (env, fdn_device_get_process_by_name_tsfn);

  napi_create_string_utf8 (env, "findProcessByPid", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_device_find_process_by_pid_deliver, &fdn_device_find_process_by_pid_tsfn);
  napi_unref_threadsafe_function (env, fdn_device_find_process_by_pid_tsfn);

  napi_create_string_utf8 (env, "findProcessByName", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_device_find_process_by_name_deliver, &fdn_device_find_process_by_name_tsfn);
  napi_unref_threadsafe_function (env, fdn_device_find_process_by_name_tsfn);

  napi_create_string_utf8 (env, "enumerateProcesses", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_device_enumerate_processes_deliver, &fdn_device_enumerate_processes_tsfn);
  napi_unref_threadsafe_function (env, fdn_device_enumerate_processes_tsfn);

  napi_create_string_utf8 (env, "enableSpawnGating", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_device_enable_spawn_gating_deliver, &fdn_device_enable_spawn_gating_tsfn);
  napi_unref_threadsafe_function (env, fdn_device_enable_spawn_gating_tsfn);

  napi_create_string_utf8 (env, "disableSpawnGating", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_device_disable_spawn_gating_deliver, &fdn_device_disable_spawn_gating_tsfn);
  napi_unref_threadsafe_function (env, fdn_device_disable_spawn_gating_tsfn);

  napi_create_string_utf8 (env, "enumeratePendingSpawn", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_device_enumerate_pending_spawn_deliver, &fdn_device_enumerate_pending_spawn_tsfn);
  napi_unref_threadsafe_function (env, fdn_device_enumerate_pending_spawn_tsfn);

  napi_create_string_utf8 (env, "enumeratePendingChildren", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_device_enumerate_pending_children_deliver, &fdn_device_enumerate_pending_children_tsfn);
  napi_unref_threadsafe_function (env, fdn_device_enumerate_pending_children_tsfn);

  napi_create_string_utf8 (env, "spawn", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_device_spawn_deliver, &fdn_device_spawn_tsfn);
  napi_unref_threadsafe_function (env, fdn_device_spawn_tsfn);

  napi_create_string_utf8 (env, "input", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_device_input_deliver, &fdn_device_input_tsfn);
  napi_unref_threadsafe_function (env, fdn_device_input_tsfn);

  napi_create_string_utf8 (env, "resume", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_device_resume_deliver, &fdn_device_resume_tsfn);
  napi_unref_threadsafe_function (env, fdn_device_resume_tsfn);

  napi_create_string_utf8 (env, "kill", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_device_kill_deliver, &fdn_device_kill_tsfn);
  napi_unref_threadsafe_function (env, fdn_device_kill_tsfn);

  napi_create_string_utf8 (env, "attach", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_device_attach_deliver, &fdn_device_attach_tsfn);
  napi_unref_threadsafe_function (env, fdn_device_attach_tsfn);

  napi_create_string_utf8 (env, "injectLibraryFile", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_device_inject_library_file_deliver, &fdn_device_inject_library_file_tsfn);
  napi_unref_threadsafe_function (env, fdn_device_inject_library_file_tsfn);

  napi_create_string_utf8 (env, "injectLibraryBlob", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_device_inject_library_blob_deliver, &fdn_device_inject_library_blob_tsfn);
  napi_unref_threadsafe_function (env, fdn_device_inject_library_blob_tsfn);

  napi_create_string_utf8 (env, "openChannel", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_device_open_channel_deliver, &fdn_device_open_channel_tsfn);
  napi_unref_threadsafe_function (env, fdn_device_open_channel_tsfn);

  napi_create_string_utf8 (env, "openService", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_device_open_service_deliver, &fdn_device_open_service_tsfn);
  napi_unref_threadsafe_function (env, fdn_device_open_service_tsfn);

  napi_create_string_utf8 (env, "unpair", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_device_unpair_deliver, &fdn_device_unpair_tsfn);
  napi_unref_threadsafe_function (env, fdn_device_unpair_tsfn);
}

static gboolean
fdn_device_from_value (napi_env env,
                       napi_value value,
                       FridaDevice ** handle)
{
  bool is_instance;

  if (napi_check_object_type_tag (env, value, &fdn_device_type_tag, &is_instance) != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of Device");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) handle);

  g_object_ref (*handle);

  return TRUE;
}

static napi_value
fdn_device_to_value (napi_env env,
                     FridaDevice * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_device_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);
  napi_type_tag_object (env, handle_wrapper, &fdn_handle_wrapper_type_tag);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_device_construct (napi_env env,
                      napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaDevice * handle = NULL;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto propagate_error;

  if (argc == 0)
  {
    napi_throw_error (env, NULL, "type Device cannot be constructed because it lacks a default constructor");
    return NULL;
  }
  else
  {
    bool is_instance;

    if (napi_check_object_type_tag (env, args[0], &fdn_handle_wrapper_type_tag, &is_instance) != napi_ok || !is_instance)
      goto invalid_handle;

    if (napi_get_value_external (env, args[0], (void **) &handle) != napi_ok)
      goto propagate_error;

    g_object_ref (handle);
  }

  if (napi_type_tag_object (env, jsthis, &fdn_device_type_tag) != napi_ok)
    goto propagate_error;

  if (napi_wrap (env, jsthis, handle, NULL, NULL, NULL) != napi_ok)
    goto propagate_error;

  if (napi_add_finalizer (env, jsthis, handle, fdn_object_finalize, NULL, NULL) != napi_ok)
    goto propagate_error;

  return jsthis;

invalid_handle:
  {
    napi_throw_type_error (env, NULL, "expected a Device handle");
    goto propagate_error;
  }
propagate_error:
  {
    g_clear_object (&handle);
    return NULL;
  }
}

static napi_value
fdn_device_is_lost (napi_env env,
                    napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaDevice * handle;
  gboolean retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_device_is_lost (handle);

  js_retval = fdn_boolean_to_value (env, retval);

beach:
  return js_retval;
}

static napi_value
fdn_device_query_system_parameters (napi_env env,
                                    napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaDevice * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnDeviceQuerySystemParametersOperation * operation;
  GSource * source;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    return NULL;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    return NULL;

  napi_create_promise (env, &deferred, &promise);

  operation = g_slice_new0 (FdnDeviceQuerySystemParametersOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
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

  

  operation->retval = frida_device_query_system_parameters_finish (operation->handle, res,
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
    napi_value js_retval;
    js_retval = fdn_vardict_to_value (env, operation->retval);
    napi_resolve_deferred (env, operation->deferred, js_retval);
  }

  fdn_device_query_system_parameters_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_device_query_system_parameters_tsfn);
}

static void
fdn_device_query_system_parameters_operation_free (FdnDeviceQuerySystemParametersOperation * operation)
{
  g_clear_pointer (&operation->cancellable, g_object_unref);
  g_clear_pointer (&operation->retval, g_hash_table_unref);
  g_slice_free (FdnDeviceQuerySystemParametersOperation, operation);
}

static napi_value
fdn_device_get_frontmost_application (napi_env env,
                                      napi_callback_info info)
{
  size_t argc = 2;
  napi_value args[2];
  napi_value jsthis;
  FridaDevice * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnDeviceGetFrontmostApplicationOperation * operation;
  GSource * source;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    return NULL;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    return NULL;

  napi_create_promise (env, &deferred, &promise);

  operation = g_slice_new0 (FdnDeviceGetFrontmostApplicationOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_frontmost_query_options_from_value (env, args[0], &operation->options))
      goto invalid_argument;
  }
  else
  {
    operation->options = NULL;
  }

  if (argc > 1 && !fdn_is_undefined_or_null (env, args[1]))
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

  

  operation->retval = frida_device_get_frontmost_application_finish (operation->handle, res,
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
    napi_value js_retval;
    if (operation->retval != NULL)
      js_retval = fdn_application_to_value (env, operation->retval);
    else
      napi_get_null (env, &js_retval);
    napi_resolve_deferred (env, operation->deferred, js_retval);
  }

  fdn_device_get_frontmost_application_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_device_get_frontmost_application_tsfn);
}

static void
fdn_device_get_frontmost_application_operation_free (FdnDeviceGetFrontmostApplicationOperation * operation)
{
  g_clear_pointer (&operation->options, frida_unref);
  g_clear_pointer (&operation->cancellable, g_object_unref);
  g_clear_pointer (&operation->retval, frida_unref);
  g_slice_free (FdnDeviceGetFrontmostApplicationOperation, operation);
}

static napi_value
fdn_device_enumerate_applications (napi_env env,
                                   napi_callback_info info)
{
  size_t argc = 2;
  napi_value args[2];
  napi_value jsthis;
  FridaDevice * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnDeviceEnumerateApplicationsOperation * operation;
  GSource * source;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    return NULL;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    return NULL;

  napi_create_promise (env, &deferred, &promise);

  operation = g_slice_new0 (FdnDeviceEnumerateApplicationsOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_application_query_options_from_value (env, args[0], &operation->options))
      goto invalid_argument;
  }
  else
  {
    operation->options = NULL;
  }

  if (argc > 1 && !fdn_is_undefined_or_null (env, args[1]))
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

  

  operation->retval = frida_device_enumerate_applications_finish (operation->handle, res,
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
    napi_value js_retval;
    js_retval = fdn_application_list_to_value (env, operation->retval);
    napi_resolve_deferred (env, operation->deferred, js_retval);
  }

  fdn_device_enumerate_applications_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_device_enumerate_applications_tsfn);
}

static void
fdn_device_enumerate_applications_operation_free (FdnDeviceEnumerateApplicationsOperation * operation)
{
  g_clear_pointer (&operation->options, frida_unref);
  g_clear_pointer (&operation->cancellable, g_object_unref);
  g_clear_pointer (&operation->retval, frida_unref);
  g_slice_free (FdnDeviceEnumerateApplicationsOperation, operation);
}

static napi_value
fdn_device_get_process_by_pid (napi_env env,
                               napi_callback_info info)
{
  size_t argc = 3;
  napi_value args[3];
  napi_value jsthis;
  FridaDevice * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnDeviceGetProcessByPidOperation * operation;
  GSource * source;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    return NULL;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    return NULL;

  napi_create_promise (env, &deferred, &promise);

  operation = g_slice_new0 (FdnDeviceGetProcessByPidOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_uint_from_value (env, args[0], &operation->pid))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: pid");
    goto invalid_argument;
  }

  if (argc > 1 && !fdn_is_undefined_or_null (env, args[1]))
  {
    if (!fdn_process_match_options_from_value (env, args[1], &operation->options))
      goto invalid_argument;
  }
  else
  {
    operation->options = NULL;
  }

  if (argc > 2 && !fdn_is_undefined_or_null (env, args[2]))
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

  

  operation->retval = frida_device_get_process_by_pid_finish (operation->handle, res,
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
    napi_value js_retval;
    js_retval = fdn_process_to_value (env, operation->retval);
    napi_resolve_deferred (env, operation->deferred, js_retval);
  }

  fdn_device_get_process_by_pid_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_device_get_process_by_pid_tsfn);
}

static void
fdn_device_get_process_by_pid_operation_free (FdnDeviceGetProcessByPidOperation * operation)
{
  g_clear_pointer (&operation->options, frida_unref);
  g_clear_pointer (&operation->cancellable, g_object_unref);
  g_clear_pointer (&operation->retval, frida_unref);
  g_slice_free (FdnDeviceGetProcessByPidOperation, operation);
}

static napi_value
fdn_device_get_process_by_name (napi_env env,
                                napi_callback_info info)
{
  size_t argc = 3;
  napi_value args[3];
  napi_value jsthis;
  FridaDevice * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnDeviceGetProcessByNameOperation * operation;
  GSource * source;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    return NULL;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    return NULL;

  napi_create_promise (env, &deferred, &promise);

  operation = g_slice_new0 (FdnDeviceGetProcessByNameOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_utf8_from_value (env, args[0], &operation->name))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: name");
    goto invalid_argument;
  }

  if (argc > 1 && !fdn_is_undefined_or_null (env, args[1]))
  {
    if (!fdn_process_match_options_from_value (env, args[1], &operation->options))
      goto invalid_argument;
  }
  else
  {
    operation->options = NULL;
  }

  if (argc > 2 && !fdn_is_undefined_or_null (env, args[2]))
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

  

  operation->retval = frida_device_get_process_by_name_finish (operation->handle, res,
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
    napi_value js_retval;
    js_retval = fdn_process_to_value (env, operation->retval);
    napi_resolve_deferred (env, operation->deferred, js_retval);
  }

  fdn_device_get_process_by_name_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_device_get_process_by_name_tsfn);
}

static void
fdn_device_get_process_by_name_operation_free (FdnDeviceGetProcessByNameOperation * operation)
{
  g_clear_pointer (&operation->name, g_free);
  g_clear_pointer (&operation->options, frida_unref);
  g_clear_pointer (&operation->cancellable, g_object_unref);
  g_clear_pointer (&operation->retval, frida_unref);
  g_slice_free (FdnDeviceGetProcessByNameOperation, operation);
}

static napi_value
fdn_device_find_process_by_pid (napi_env env,
                                napi_callback_info info)
{
  size_t argc = 3;
  napi_value args[3];
  napi_value jsthis;
  FridaDevice * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnDeviceFindProcessByPidOperation * operation;
  GSource * source;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    return NULL;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    return NULL;

  napi_create_promise (env, &deferred, &promise);

  operation = g_slice_new0 (FdnDeviceFindProcessByPidOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_uint_from_value (env, args[0], &operation->pid))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: pid");
    goto invalid_argument;
  }

  if (argc > 1 && !fdn_is_undefined_or_null (env, args[1]))
  {
    if (!fdn_process_match_options_from_value (env, args[1], &operation->options))
      goto invalid_argument;
  }
  else
  {
    operation->options = NULL;
  }

  if (argc > 2 && !fdn_is_undefined_or_null (env, args[2]))
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

  

  operation->retval = frida_device_find_process_by_pid_finish (operation->handle, res,
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
    napi_value js_retval;
    if (operation->retval != NULL)
      js_retval = fdn_process_to_value (env, operation->retval);
    else
      napi_get_null (env, &js_retval);
    napi_resolve_deferred (env, operation->deferred, js_retval);
  }

  fdn_device_find_process_by_pid_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_device_find_process_by_pid_tsfn);
}

static void
fdn_device_find_process_by_pid_operation_free (FdnDeviceFindProcessByPidOperation * operation)
{
  g_clear_pointer (&operation->options, frida_unref);
  g_clear_pointer (&operation->cancellable, g_object_unref);
  g_clear_pointer (&operation->retval, frida_unref);
  g_slice_free (FdnDeviceFindProcessByPidOperation, operation);
}

static napi_value
fdn_device_find_process_by_name (napi_env env,
                                 napi_callback_info info)
{
  size_t argc = 3;
  napi_value args[3];
  napi_value jsthis;
  FridaDevice * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnDeviceFindProcessByNameOperation * operation;
  GSource * source;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    return NULL;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    return NULL;

  napi_create_promise (env, &deferred, &promise);

  operation = g_slice_new0 (FdnDeviceFindProcessByNameOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_utf8_from_value (env, args[0], &operation->name))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: name");
    goto invalid_argument;
  }

  if (argc > 1 && !fdn_is_undefined_or_null (env, args[1]))
  {
    if (!fdn_process_match_options_from_value (env, args[1], &operation->options))
      goto invalid_argument;
  }
  else
  {
    operation->options = NULL;
  }

  if (argc > 2 && !fdn_is_undefined_or_null (env, args[2]))
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

  

  operation->retval = frida_device_find_process_by_name_finish (operation->handle, res,
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
    napi_value js_retval;
    if (operation->retval != NULL)
      js_retval = fdn_process_to_value (env, operation->retval);
    else
      napi_get_null (env, &js_retval);
    napi_resolve_deferred (env, operation->deferred, js_retval);
  }

  fdn_device_find_process_by_name_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_device_find_process_by_name_tsfn);
}

static void
fdn_device_find_process_by_name_operation_free (FdnDeviceFindProcessByNameOperation * operation)
{
  g_clear_pointer (&operation->name, g_free);
  g_clear_pointer (&operation->options, frida_unref);
  g_clear_pointer (&operation->cancellable, g_object_unref);
  g_clear_pointer (&operation->retval, frida_unref);
  g_slice_free (FdnDeviceFindProcessByNameOperation, operation);
}

static napi_value
fdn_device_enumerate_processes (napi_env env,
                                napi_callback_info info)
{
  size_t argc = 2;
  napi_value args[2];
  napi_value jsthis;
  FridaDevice * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnDeviceEnumerateProcessesOperation * operation;
  GSource * source;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    return NULL;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    return NULL;

  napi_create_promise (env, &deferred, &promise);

  operation = g_slice_new0 (FdnDeviceEnumerateProcessesOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_process_query_options_from_value (env, args[0], &operation->options))
      goto invalid_argument;
  }
  else
  {
    operation->options = NULL;
  }

  if (argc > 1 && !fdn_is_undefined_or_null (env, args[1]))
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

  

  operation->retval = frida_device_enumerate_processes_finish (operation->handle, res,
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
    napi_value js_retval;
    js_retval = fdn_process_list_to_value (env, operation->retval);
    napi_resolve_deferred (env, operation->deferred, js_retval);
  }

  fdn_device_enumerate_processes_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_device_enumerate_processes_tsfn);
}

static void
fdn_device_enumerate_processes_operation_free (FdnDeviceEnumerateProcessesOperation * operation)
{
  g_clear_pointer (&operation->options, frida_unref);
  g_clear_pointer (&operation->cancellable, g_object_unref);
  g_clear_pointer (&operation->retval, frida_unref);
  g_slice_free (FdnDeviceEnumerateProcessesOperation, operation);
}

static napi_value
fdn_device_enable_spawn_gating (napi_env env,
                                napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaDevice * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnDeviceEnableSpawnGatingOperation * operation;
  GSource * source;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    return NULL;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    return NULL;

  napi_create_promise (env, &deferred, &promise);

  operation = g_slice_new0 (FdnDeviceEnableSpawnGatingOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
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
    napi_value js_retval;
    napi_get_undefined (env, &js_retval);
    napi_resolve_deferred (env, operation->deferred, js_retval);
  }

  fdn_device_enable_spawn_gating_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_device_enable_spawn_gating_tsfn);
}

static void
fdn_device_enable_spawn_gating_operation_free (FdnDeviceEnableSpawnGatingOperation * operation)
{
  g_clear_pointer (&operation->cancellable, g_object_unref);
  g_slice_free (FdnDeviceEnableSpawnGatingOperation, operation);
}

static napi_value
fdn_device_disable_spawn_gating (napi_env env,
                                 napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaDevice * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnDeviceDisableSpawnGatingOperation * operation;
  GSource * source;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    return NULL;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    return NULL;

  napi_create_promise (env, &deferred, &promise);

  operation = g_slice_new0 (FdnDeviceDisableSpawnGatingOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
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
    napi_value js_retval;
    napi_get_undefined (env, &js_retval);
    napi_resolve_deferred (env, operation->deferred, js_retval);
  }

  fdn_device_disable_spawn_gating_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_device_disable_spawn_gating_tsfn);
}

static void
fdn_device_disable_spawn_gating_operation_free (FdnDeviceDisableSpawnGatingOperation * operation)
{
  g_clear_pointer (&operation->cancellable, g_object_unref);
  g_slice_free (FdnDeviceDisableSpawnGatingOperation, operation);
}

static napi_value
fdn_device_enumerate_pending_spawn (napi_env env,
                                    napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaDevice * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnDeviceEnumeratePendingSpawnOperation * operation;
  GSource * source;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    return NULL;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    return NULL;

  napi_create_promise (env, &deferred, &promise);

  operation = g_slice_new0 (FdnDeviceEnumeratePendingSpawnOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
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

  

  operation->retval = frida_device_enumerate_pending_spawn_finish (operation->handle, res,
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
    napi_value js_retval;
    js_retval = fdn_spawn_list_to_value (env, operation->retval);
    napi_resolve_deferred (env, operation->deferred, js_retval);
  }

  fdn_device_enumerate_pending_spawn_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_device_enumerate_pending_spawn_tsfn);
}

static void
fdn_device_enumerate_pending_spawn_operation_free (FdnDeviceEnumeratePendingSpawnOperation * operation)
{
  g_clear_pointer (&operation->cancellable, g_object_unref);
  g_clear_pointer (&operation->retval, frida_unref);
  g_slice_free (FdnDeviceEnumeratePendingSpawnOperation, operation);
}

static napi_value
fdn_device_enumerate_pending_children (napi_env env,
                                       napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaDevice * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnDeviceEnumeratePendingChildrenOperation * operation;
  GSource * source;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    return NULL;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    return NULL;

  napi_create_promise (env, &deferred, &promise);

  operation = g_slice_new0 (FdnDeviceEnumeratePendingChildrenOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
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

  

  operation->retval = frida_device_enumerate_pending_children_finish (operation->handle, res,
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
    napi_value js_retval;
    js_retval = fdn_child_list_to_value (env, operation->retval);
    napi_resolve_deferred (env, operation->deferred, js_retval);
  }

  fdn_device_enumerate_pending_children_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_device_enumerate_pending_children_tsfn);
}

static void
fdn_device_enumerate_pending_children_operation_free (FdnDeviceEnumeratePendingChildrenOperation * operation)
{
  g_clear_pointer (&operation->cancellable, g_object_unref);
  g_clear_pointer (&operation->retval, frida_unref);
  g_slice_free (FdnDeviceEnumeratePendingChildrenOperation, operation);
}

static napi_value
fdn_device_spawn (napi_env env,
                  napi_callback_info info)
{
  size_t argc = 3;
  napi_value args[3];
  napi_value jsthis;
  FridaDevice * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnDeviceSpawnOperation * operation;
  GSource * source;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    return NULL;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    return NULL;

  napi_create_promise (env, &deferred, &promise);

  operation = g_slice_new0 (FdnDeviceSpawnOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_utf8_from_value (env, args[0], &operation->program))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: program");
    goto invalid_argument;
  }

  if (argc > 1 && !fdn_is_undefined_or_null (env, args[1]))
  {
    if (!fdn_spawn_options_from_value (env, args[1], &operation->options))
      goto invalid_argument;
  }
  else
  {
    operation->options = NULL;
  }

  if (argc > 2 && !fdn_is_undefined_or_null (env, args[2]))
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

  

  operation->retval = frida_device_spawn_finish (operation->handle, res,
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
    napi_value js_retval;
    js_retval = fdn_uint_to_value (env, operation->retval);
    napi_resolve_deferred (env, operation->deferred, js_retval);
  }

  fdn_device_spawn_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_device_spawn_tsfn);
}

static void
fdn_device_spawn_operation_free (FdnDeviceSpawnOperation * operation)
{
  g_clear_pointer (&operation->program, g_free);
  g_clear_pointer (&operation->options, frida_unref);
  g_clear_pointer (&operation->cancellable, g_object_unref);
  g_slice_free (FdnDeviceSpawnOperation, operation);
}

static napi_value
fdn_device_input (napi_env env,
                  napi_callback_info info)
{
  size_t argc = 3;
  napi_value args[3];
  napi_value jsthis;
  FridaDevice * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnDeviceInputOperation * operation;
  GSource * source;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    return NULL;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    return NULL;

  napi_create_promise (env, &deferred, &promise);

  operation = g_slice_new0 (FdnDeviceInputOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_uint_from_value (env, args[0], &operation->pid))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: pid");
    goto invalid_argument;
  }

  if (argc > 1 && !fdn_is_undefined_or_null (env, args[1]))
  {
    if (!fdn_bytes_from_value (env, args[1], &operation->data))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: data");
    goto invalid_argument;
  }

  if (argc > 2 && !fdn_is_undefined_or_null (env, args[2]))
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
    napi_value js_retval;
    napi_get_undefined (env, &js_retval);
    napi_resolve_deferred (env, operation->deferred, js_retval);
  }

  fdn_device_input_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_device_input_tsfn);
}

static void
fdn_device_input_operation_free (FdnDeviceInputOperation * operation)
{
  g_clear_pointer (&operation->data, g_bytes_unref);
  g_clear_pointer (&operation->cancellable, g_object_unref);
  g_slice_free (FdnDeviceInputOperation, operation);
}

static napi_value
fdn_device_resume (napi_env env,
                   napi_callback_info info)
{
  size_t argc = 2;
  napi_value args[2];
  napi_value jsthis;
  FridaDevice * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnDeviceResumeOperation * operation;
  GSource * source;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    return NULL;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    return NULL;

  napi_create_promise (env, &deferred, &promise);

  operation = g_slice_new0 (FdnDeviceResumeOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_uint_from_value (env, args[0], &operation->pid))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: pid");
    goto invalid_argument;
  }

  if (argc > 1 && !fdn_is_undefined_or_null (env, args[1]))
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
    napi_value js_retval;
    napi_get_undefined (env, &js_retval);
    napi_resolve_deferred (env, operation->deferred, js_retval);
  }

  fdn_device_resume_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_device_resume_tsfn);
}

static void
fdn_device_resume_operation_free (FdnDeviceResumeOperation * operation)
{
  g_clear_pointer (&operation->cancellable, g_object_unref);
  g_slice_free (FdnDeviceResumeOperation, operation);
}

static napi_value
fdn_device_kill (napi_env env,
                 napi_callback_info info)
{
  size_t argc = 2;
  napi_value args[2];
  napi_value jsthis;
  FridaDevice * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnDeviceKillOperation * operation;
  GSource * source;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    return NULL;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    return NULL;

  napi_create_promise (env, &deferred, &promise);

  operation = g_slice_new0 (FdnDeviceKillOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_uint_from_value (env, args[0], &operation->pid))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: pid");
    goto invalid_argument;
  }

  if (argc > 1 && !fdn_is_undefined_or_null (env, args[1]))
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
    napi_value js_retval;
    napi_get_undefined (env, &js_retval);
    napi_resolve_deferred (env, operation->deferred, js_retval);
  }

  fdn_device_kill_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_device_kill_tsfn);
}

static void
fdn_device_kill_operation_free (FdnDeviceKillOperation * operation)
{
  g_clear_pointer (&operation->cancellable, g_object_unref);
  g_slice_free (FdnDeviceKillOperation, operation);
}

static napi_value
fdn_device_attach (napi_env env,
                   napi_callback_info info)
{
  size_t argc = 3;
  napi_value args[3];
  napi_value jsthis;
  FridaDevice * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnDeviceAttachOperation * operation;
  GSource * source;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    return NULL;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    return NULL;

  napi_create_promise (env, &deferred, &promise);

  operation = g_slice_new0 (FdnDeviceAttachOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_uint_from_value (env, args[0], &operation->pid))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: pid");
    goto invalid_argument;
  }

  if (argc > 1 && !fdn_is_undefined_or_null (env, args[1]))
  {
    if (!fdn_session_options_from_value (env, args[1], &operation->options))
      goto invalid_argument;
  }
  else
  {
    operation->options = NULL;
  }

  if (argc > 2 && !fdn_is_undefined_or_null (env, args[2]))
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

  

  operation->retval = frida_device_attach_finish (operation->handle, res,
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
    napi_value js_retval;
    js_retval = fdn_session_to_value (env, operation->retval);
    napi_resolve_deferred (env, operation->deferred, js_retval);
  }

  fdn_device_attach_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_device_attach_tsfn);
}

static void
fdn_device_attach_operation_free (FdnDeviceAttachOperation * operation)
{
  g_clear_pointer (&operation->options, frida_unref);
  g_clear_pointer (&operation->cancellable, g_object_unref);
  g_clear_pointer (&operation->retval, frida_unref);
  g_slice_free (FdnDeviceAttachOperation, operation);
}

static napi_value
fdn_device_inject_library_file (napi_env env,
                                napi_callback_info info)
{
  size_t argc = 5;
  napi_value args[5];
  napi_value jsthis;
  FridaDevice * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnDeviceInjectLibraryFileOperation * operation;
  GSource * source;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    return NULL;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    return NULL;

  napi_create_promise (env, &deferred, &promise);

  operation = g_slice_new0 (FdnDeviceInjectLibraryFileOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_uint_from_value (env, args[0], &operation->pid))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: pid");
    goto invalid_argument;
  }

  if (argc > 1 && !fdn_is_undefined_or_null (env, args[1]))
  {
    if (!fdn_utf8_from_value (env, args[1], &operation->path))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: path");
    goto invalid_argument;
  }

  if (argc > 2 && !fdn_is_undefined_or_null (env, args[2]))
  {
    if (!fdn_utf8_from_value (env, args[2], &operation->entrypoint))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: entrypoint");
    goto invalid_argument;
  }

  if (argc > 3 && !fdn_is_undefined_or_null (env, args[3]))
  {
    if (!fdn_utf8_from_value (env, args[3], &operation->data))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: data");
    goto invalid_argument;
  }

  if (argc > 4 && !fdn_is_undefined_or_null (env, args[4]))
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

  

  operation->retval = frida_device_inject_library_file_finish (operation->handle, res,
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
    napi_value js_retval;
    js_retval = fdn_uint_to_value (env, operation->retval);
    napi_resolve_deferred (env, operation->deferred, js_retval);
  }

  fdn_device_inject_library_file_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_device_inject_library_file_tsfn);
}

static void
fdn_device_inject_library_file_operation_free (FdnDeviceInjectLibraryFileOperation * operation)
{
  g_clear_pointer (&operation->path, g_free);
  g_clear_pointer (&operation->entrypoint, g_free);
  g_clear_pointer (&operation->data, g_free);
  g_clear_pointer (&operation->cancellable, g_object_unref);
  g_slice_free (FdnDeviceInjectLibraryFileOperation, operation);
}

static napi_value
fdn_device_inject_library_blob (napi_env env,
                                napi_callback_info info)
{
  size_t argc = 5;
  napi_value args[5];
  napi_value jsthis;
  FridaDevice * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnDeviceInjectLibraryBlobOperation * operation;
  GSource * source;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    return NULL;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    return NULL;

  napi_create_promise (env, &deferred, &promise);

  operation = g_slice_new0 (FdnDeviceInjectLibraryBlobOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_uint_from_value (env, args[0], &operation->pid))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: pid");
    goto invalid_argument;
  }

  if (argc > 1 && !fdn_is_undefined_or_null (env, args[1]))
  {
    if (!fdn_bytes_from_value (env, args[1], &operation->blob))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: blob");
    goto invalid_argument;
  }

  if (argc > 2 && !fdn_is_undefined_or_null (env, args[2]))
  {
    if (!fdn_utf8_from_value (env, args[2], &operation->entrypoint))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: entrypoint");
    goto invalid_argument;
  }

  if (argc > 3 && !fdn_is_undefined_or_null (env, args[3]))
  {
    if (!fdn_utf8_from_value (env, args[3], &operation->data))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: data");
    goto invalid_argument;
  }

  if (argc > 4 && !fdn_is_undefined_or_null (env, args[4]))
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

  

  operation->retval = frida_device_inject_library_blob_finish (operation->handle, res,
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
    napi_value js_retval;
    js_retval = fdn_uint_to_value (env, operation->retval);
    napi_resolve_deferred (env, operation->deferred, js_retval);
  }

  fdn_device_inject_library_blob_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_device_inject_library_blob_tsfn);
}

static void
fdn_device_inject_library_blob_operation_free (FdnDeviceInjectLibraryBlobOperation * operation)
{
  g_clear_pointer (&operation->blob, g_bytes_unref);
  g_clear_pointer (&operation->entrypoint, g_free);
  g_clear_pointer (&operation->data, g_free);
  g_clear_pointer (&operation->cancellable, g_object_unref);
  g_slice_free (FdnDeviceInjectLibraryBlobOperation, operation);
}

static napi_value
fdn_device_open_channel (napi_env env,
                         napi_callback_info info)
{
  size_t argc = 2;
  napi_value args[2];
  napi_value jsthis;
  FridaDevice * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnDeviceOpenChannelOperation * operation;
  GSource * source;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    return NULL;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    return NULL;

  napi_create_promise (env, &deferred, &promise);

  operation = g_slice_new0 (FdnDeviceOpenChannelOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_utf8_from_value (env, args[0], &operation->address))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: address");
    goto invalid_argument;
  }

  if (argc > 1 && !fdn_is_undefined_or_null (env, args[1]))
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

  

  operation->retval = frida_device_open_channel_finish (operation->handle, res,
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
    napi_value js_retval;
    js_retval = fdn_io_stream_to_value (env, operation->retval);
    napi_resolve_deferred (env, operation->deferred, js_retval);
  }

  fdn_device_open_channel_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_device_open_channel_tsfn);
}

static void
fdn_device_open_channel_operation_free (FdnDeviceOpenChannelOperation * operation)
{
  g_clear_pointer (&operation->address, g_free);
  g_clear_pointer (&operation->cancellable, g_object_unref);
  g_clear_pointer (&operation->retval, g_object_unref);
  g_slice_free (FdnDeviceOpenChannelOperation, operation);
}

static napi_value
fdn_device_open_service (napi_env env,
                         napi_callback_info info)
{
  size_t argc = 2;
  napi_value args[2];
  napi_value jsthis;
  FridaDevice * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnDeviceOpenServiceOperation * operation;
  GSource * source;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    return NULL;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    return NULL;

  napi_create_promise (env, &deferred, &promise);

  operation = g_slice_new0 (FdnDeviceOpenServiceOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_utf8_from_value (env, args[0], &operation->address))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: address");
    goto invalid_argument;
  }

  if (argc > 1 && !fdn_is_undefined_or_null (env, args[1]))
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

  

  operation->retval = frida_device_open_service_finish (operation->handle, res,
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
    napi_value js_retval;
    js_retval = fdn_service_to_value (env, operation->retval);
    napi_resolve_deferred (env, operation->deferred, js_retval);
  }

  fdn_device_open_service_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_device_open_service_tsfn);
}

static void
fdn_device_open_service_operation_free (FdnDeviceOpenServiceOperation * operation)
{
  g_clear_pointer (&operation->address, g_free);
  g_clear_pointer (&operation->cancellable, g_object_unref);
  g_clear_pointer (&operation->retval, frida_unref);
  g_slice_free (FdnDeviceOpenServiceOperation, operation);
}

static napi_value
fdn_device_unpair (napi_env env,
                   napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaDevice * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnDeviceUnpairOperation * operation;
  GSource * source;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    return NULL;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    return NULL;

  napi_create_promise (env, &deferred, &promise);

  operation = g_slice_new0 (FdnDeviceUnpairOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
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
    napi_value js_retval;
    napi_get_undefined (env, &js_retval);
    napi_resolve_deferred (env, operation->deferred, js_retval);
  }

  fdn_device_unpair_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_device_unpair_tsfn);
}

static void
fdn_device_unpair_operation_free (FdnDeviceUnpairOperation * operation)
{
  g_clear_pointer (&operation->cancellable, g_object_unref);
  g_slice_free (FdnDeviceUnpairOperation, operation);
}

static napi_value
fdn_device_get_id (napi_env env,
                   napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaDevice * handle;
  const gchar * retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_device_get_id (handle);

  js_retval = fdn_utf8_to_value (env, retval);

beach:
  return js_retval;
}

static napi_value
fdn_device_get_name (napi_env env,
                     napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaDevice * handle;
  const gchar * retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_device_get_name (handle);

  js_retval = fdn_utf8_to_value (env, retval);

beach:
  return js_retval;
}

static napi_value
fdn_device_get_icon (napi_env env,
                     napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaDevice * handle;
  GVariant * retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_device_get_icon (handle);

  if (retval != NULL)
    js_retval = fdn_variant_to_value (env, retval);
  else
    napi_get_null (env, &js_retval);

beach:
  return js_retval;
}

static napi_value
fdn_device_get_dtype (napi_env env,
                      napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaDevice * handle;
  FridaDeviceType retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_device_get_dtype (handle);

  js_retval = fdn_device_type_to_value (env, retval);

beach:
  return js_retval;
}

static napi_value
fdn_device_get_bus (napi_env env,
                    napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaDevice * handle;
  FridaBus * retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_device_get_bus (handle);

  js_retval = fdn_bus_to_value (env, retval);

beach:
  return js_retval;
}

static napi_value
fdn_device_get_spawn_added_signal (napi_env env,
                                   napi_callback_info info)
{
  return fdn_object_get_signal (env, info, "spawn-added", "_spawnAdded");
}

static napi_value
fdn_device_get_spawn_removed_signal (napi_env env,
                                     napi_callback_info info)
{
  return fdn_object_get_signal (env, info, "spawn-removed", "_spawnRemoved");
}

static napi_value
fdn_device_get_child_added_signal (napi_env env,
                                   napi_callback_info info)
{
  return fdn_object_get_signal (env, info, "child-added", "_childAdded");
}

static napi_value
fdn_device_get_child_removed_signal (napi_env env,
                                     napi_callback_info info)
{
  return fdn_object_get_signal (env, info, "child-removed", "_childRemoved");
}

static napi_value
fdn_device_get_process_crashed_signal (napi_env env,
                                       napi_callback_info info)
{
  return fdn_object_get_signal (env, info, "process-crashed", "_processCrashed");
}

static napi_value
fdn_device_get_output_signal (napi_env env,
                              napi_callback_info info)
{
  return fdn_object_get_signal (env, info, "output", "_output");
}

static napi_value
fdn_device_get_uninjected_signal (napi_env env,
                                  napi_callback_info info)
{
  return fdn_object_get_signal (env, info, "uninjected", "_uninjected");
}

static napi_value
fdn_device_get_lost_signal (napi_env env,
                            napi_callback_info info)
{
  return fdn_object_get_signal (env, info, "lost", "_lost");
}

static void
fdn_remote_device_options_register (napi_env env,
                                    napi_value exports)
{
  napi_property_descriptor properties[] =
  {
    { "certificate", NULL, NULL, fdn_remote_device_options_get_certificate, fdn_remote_device_options_set_certificate, NULL, napi_writable | napi_enumerable | napi_configurable, NULL },
    { "origin", NULL, NULL, fdn_remote_device_options_get_origin, fdn_remote_device_options_set_origin, NULL, napi_writable | napi_enumerable | napi_configurable, NULL },
    { "token", NULL, NULL, fdn_remote_device_options_get_token, fdn_remote_device_options_set_token, NULL, napi_writable | napi_enumerable | napi_configurable, NULL },
    { "keepaliveInterval", NULL, NULL, fdn_remote_device_options_get_keepalive_interval, fdn_remote_device_options_set_keepalive_interval, NULL, napi_writable | napi_enumerable | napi_configurable, NULL },
  };

  napi_value constructor;
  napi_define_class (env, "RemoteDeviceOptions", NAPI_AUTO_LENGTH, fdn_remote_device_options_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_remote_device_options_constructor);

  napi_set_named_property (env, exports, "RemoteDeviceOptions", constructor);
}

static gboolean
fdn_remote_device_options_from_value (napi_env env,
                                      napi_value value,
                                      FridaRemoteDeviceOptions ** handle)
{
  bool is_instance;

  if (napi_check_object_type_tag (env, value, &fdn_remote_device_options_type_tag, &is_instance) != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of RemoteDeviceOptions");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) handle);

  g_object_ref (*handle);

  return TRUE;
}

static napi_value
fdn_remote_device_options_to_value (napi_env env,
                                    FridaRemoteDeviceOptions * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_remote_device_options_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);
  napi_type_tag_object (env, handle_wrapper, &fdn_handle_wrapper_type_tag);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_remote_device_options_construct (napi_env env,
                                     napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaRemoteDeviceOptions * handle = NULL;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto propagate_error;

  if (argc == 0)
  {
    handle = frida_remote_device_options_new ();
  }
  else
  {
    bool is_instance;

    if (napi_check_object_type_tag (env, args[0], &fdn_handle_wrapper_type_tag, &is_instance) != napi_ok || !is_instance)
      goto invalid_handle;

    if (napi_get_value_external (env, args[0], (void **) &handle) != napi_ok)
      goto propagate_error;

    g_object_ref (handle);
  }

  if (napi_type_tag_object (env, jsthis, &fdn_remote_device_options_type_tag) != napi_ok)
    goto propagate_error;

  if (napi_wrap (env, jsthis, handle, NULL, NULL, NULL) != napi_ok)
    goto propagate_error;

  if (napi_add_finalizer (env, jsthis, handle, fdn_object_finalize, NULL, NULL) != napi_ok)
    goto propagate_error;

  return jsthis;

invalid_handle:
  {
    napi_throw_type_error (env, NULL, "expected a RemoteDeviceOptions handle");
    goto propagate_error;
  }
propagate_error:
  {
    g_clear_object (&handle);
    return NULL;
  }
}

static napi_value
fdn_remote_device_options_get_certificate (napi_env env,
                                           napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaRemoteDeviceOptions * handle;
  GTlsCertificate * retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_remote_device_options_get_certificate (handle);

  if (retval != NULL)
    js_retval = fdn_tls_certificate_to_value (env, retval);
  else
    napi_get_null (env, &js_retval);

beach:
  return js_retval;
}

static napi_value
fdn_remote_device_options_set_certificate (napi_env env,
                                           napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaRemoteDeviceOptions * handle;
  GTlsCertificate * value = NULL;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_tls_certificate_from_value (env, args[0], &value))
      goto beach;
  }
  else
  {
    value = NULL;
  }

  frida_remote_device_options_set_certificate (handle, value);

  napi_get_undefined (env, &js_retval);

beach:
  g_clear_pointer (&value, g_object_unref);
  return js_retval;
}

static napi_value
fdn_remote_device_options_get_origin (napi_env env,
                                      napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaRemoteDeviceOptions * handle;
  const gchar * retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_remote_device_options_get_origin (handle);

  if (retval != NULL)
    js_retval = fdn_utf8_to_value (env, retval);
  else
    napi_get_null (env, &js_retval);

beach:
  return js_retval;
}

static napi_value
fdn_remote_device_options_set_origin (napi_env env,
                                      napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaRemoteDeviceOptions * handle;
  gchar * value = NULL;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_utf8_from_value (env, args[0], &value))
      goto beach;
  }
  else
  {
    value = NULL;
  }

  frida_remote_device_options_set_origin (handle, value);

  napi_get_undefined (env, &js_retval);

beach:
  g_clear_pointer (&value, g_free);
  return js_retval;
}

static napi_value
fdn_remote_device_options_get_token (napi_env env,
                                     napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaRemoteDeviceOptions * handle;
  const gchar * retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_remote_device_options_get_token (handle);

  if (retval != NULL)
    js_retval = fdn_utf8_to_value (env, retval);
  else
    napi_get_null (env, &js_retval);

beach:
  return js_retval;
}

static napi_value
fdn_remote_device_options_set_token (napi_env env,
                                     napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaRemoteDeviceOptions * handle;
  gchar * value = NULL;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_utf8_from_value (env, args[0], &value))
      goto beach;
  }
  else
  {
    value = NULL;
  }

  frida_remote_device_options_set_token (handle, value);

  napi_get_undefined (env, &js_retval);

beach:
  g_clear_pointer (&value, g_free);
  return js_retval;
}

static napi_value
fdn_remote_device_options_get_keepalive_interval (napi_env env,
                                                  napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaRemoteDeviceOptions * handle;
  gint retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_remote_device_options_get_keepalive_interval (handle);

  js_retval = fdn_int_to_value (env, retval);

beach:
  return js_retval;
}

static napi_value
fdn_remote_device_options_set_keepalive_interval (napi_env env,
                                                  napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaRemoteDeviceOptions * handle;
  gint value;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_int_from_value (env, args[0], &value))
      goto beach;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: value");
    goto beach;
  }

  frida_remote_device_options_set_keepalive_interval (handle, value);

  napi_get_undefined (env, &js_retval);

beach:
  return js_retval;
}

static napi_value
fdn_application_list_to_value (napi_env env,
                               FridaApplicationList * list)
{
  napi_value result;
  gint size, i;

  size = frida_application_list_size (list);
  napi_create_array_with_length (env, size, &result);

  for (i = 0; i != size; i++)
  {
    FridaApplication * handle = frida_application_list_get (list, i);
    napi_set_element (env, result, i, fdn_application_to_value (env, handle));
    g_object_unref (handle);
  }

  return result;
}

static void
fdn_application_register (napi_env env,
                          napi_value exports)
{
  napi_property_descriptor properties[] =
  {
    { "identifier", NULL, NULL, fdn_application_get_identifier, NULL, NULL, napi_enumerable | napi_configurable, NULL },
    { "name", NULL, NULL, fdn_application_get_name, NULL, NULL, napi_enumerable | napi_configurable, NULL },
    { "pid", NULL, NULL, fdn_application_get_pid, NULL, NULL, napi_enumerable | napi_configurable, NULL },
    { "parameters", NULL, NULL, fdn_application_get_parameters, NULL, NULL, napi_enumerable | napi_configurable, NULL },
  };

  napi_value constructor;
  napi_define_class (env, "Application", NAPI_AUTO_LENGTH, fdn_application_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_application_constructor);

  napi_set_named_property (env, exports, "Application", constructor);
}

static gboolean
fdn_application_from_value (napi_env env,
                            napi_value value,
                            FridaApplication ** handle)
{
  bool is_instance;

  if (napi_check_object_type_tag (env, value, &fdn_application_type_tag, &is_instance) != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of Application");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) handle);

  g_object_ref (*handle);

  return TRUE;
}

static napi_value
fdn_application_to_value (napi_env env,
                          FridaApplication * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_application_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);
  napi_type_tag_object (env, handle_wrapper, &fdn_handle_wrapper_type_tag);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_application_construct (napi_env env,
                           napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaApplication * handle = NULL;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto propagate_error;

  if (argc == 0)
  {
    napi_throw_error (env, NULL, "type Application cannot be constructed because it lacks a default constructor");
    return NULL;
  }
  else
  {
    bool is_instance;

    if (napi_check_object_type_tag (env, args[0], &fdn_handle_wrapper_type_tag, &is_instance) != napi_ok || !is_instance)
      goto invalid_handle;

    if (napi_get_value_external (env, args[0], (void **) &handle) != napi_ok)
      goto propagate_error;

    g_object_ref (handle);
  }

  if (napi_type_tag_object (env, jsthis, &fdn_application_type_tag) != napi_ok)
    goto propagate_error;

  if (napi_wrap (env, jsthis, handle, NULL, NULL, NULL) != napi_ok)
    goto propagate_error;

  if (napi_add_finalizer (env, jsthis, handle, fdn_object_finalize, NULL, NULL) != napi_ok)
    goto propagate_error;

  return jsthis;

invalid_handle:
  {
    napi_throw_type_error (env, NULL, "expected a Application handle");
    goto propagate_error;
  }
propagate_error:
  {
    g_clear_object (&handle);
    return NULL;
  }
}

static napi_value
fdn_application_get_identifier (napi_env env,
                                napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaApplication * handle;
  const gchar * retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_application_get_identifier (handle);

  js_retval = fdn_utf8_to_value (env, retval);

beach:
  return js_retval;
}

static napi_value
fdn_application_get_name (napi_env env,
                          napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaApplication * handle;
  const gchar * retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_application_get_name (handle);

  js_retval = fdn_utf8_to_value (env, retval);

beach:
  return js_retval;
}

static napi_value
fdn_application_get_pid (napi_env env,
                         napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaApplication * handle;
  guint retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_application_get_pid (handle);

  js_retval = fdn_uint_to_value (env, retval);

beach:
  return js_retval;
}

static napi_value
fdn_application_get_parameters (napi_env env,
                                napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaApplication * handle;
  GHashTable * retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_application_get_parameters (handle);

  js_retval = fdn_vardict_to_value (env, retval);

beach:
  return js_retval;
}

static napi_value
fdn_process_list_to_value (napi_env env,
                           FridaProcessList * list)
{
  napi_value result;
  gint size, i;

  size = frida_process_list_size (list);
  napi_create_array_with_length (env, size, &result);

  for (i = 0; i != size; i++)
  {
    FridaProcess * handle = frida_process_list_get (list, i);
    napi_set_element (env, result, i, fdn_process_to_value (env, handle));
    g_object_unref (handle);
  }

  return result;
}

static void
fdn_process_register (napi_env env,
                      napi_value exports)
{
  napi_property_descriptor properties[] =
  {
    { "pid", NULL, NULL, fdn_process_get_pid, NULL, NULL, napi_enumerable | napi_configurable, NULL },
    { "name", NULL, NULL, fdn_process_get_name, NULL, NULL, napi_enumerable | napi_configurable, NULL },
    { "parameters", NULL, NULL, fdn_process_get_parameters, NULL, NULL, napi_enumerable | napi_configurable, NULL },
  };

  napi_value constructor;
  napi_define_class (env, "Process", NAPI_AUTO_LENGTH, fdn_process_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_process_constructor);

  napi_set_named_property (env, exports, "Process", constructor);
}

static gboolean
fdn_process_from_value (napi_env env,
                        napi_value value,
                        FridaProcess ** handle)
{
  bool is_instance;

  if (napi_check_object_type_tag (env, value, &fdn_process_type_tag, &is_instance) != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of Process");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) handle);

  g_object_ref (*handle);

  return TRUE;
}

static napi_value
fdn_process_to_value (napi_env env,
                      FridaProcess * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_process_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);
  napi_type_tag_object (env, handle_wrapper, &fdn_handle_wrapper_type_tag);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_process_construct (napi_env env,
                       napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaProcess * handle = NULL;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto propagate_error;

  if (argc == 0)
  {
    napi_throw_error (env, NULL, "type Process cannot be constructed because it lacks a default constructor");
    return NULL;
  }
  else
  {
    bool is_instance;

    if (napi_check_object_type_tag (env, args[0], &fdn_handle_wrapper_type_tag, &is_instance) != napi_ok || !is_instance)
      goto invalid_handle;

    if (napi_get_value_external (env, args[0], (void **) &handle) != napi_ok)
      goto propagate_error;

    g_object_ref (handle);
  }

  if (napi_type_tag_object (env, jsthis, &fdn_process_type_tag) != napi_ok)
    goto propagate_error;

  if (napi_wrap (env, jsthis, handle, NULL, NULL, NULL) != napi_ok)
    goto propagate_error;

  if (napi_add_finalizer (env, jsthis, handle, fdn_object_finalize, NULL, NULL) != napi_ok)
    goto propagate_error;

  return jsthis;

invalid_handle:
  {
    napi_throw_type_error (env, NULL, "expected a Process handle");
    goto propagate_error;
  }
propagate_error:
  {
    g_clear_object (&handle);
    return NULL;
  }
}

static napi_value
fdn_process_get_pid (napi_env env,
                     napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaProcess * handle;
  guint retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_process_get_pid (handle);

  js_retval = fdn_uint_to_value (env, retval);

beach:
  return js_retval;
}

static napi_value
fdn_process_get_name (napi_env env,
                      napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaProcess * handle;
  const gchar * retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_process_get_name (handle);

  js_retval = fdn_utf8_to_value (env, retval);

beach:
  return js_retval;
}

static napi_value
fdn_process_get_parameters (napi_env env,
                            napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaProcess * handle;
  GHashTable * retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_process_get_parameters (handle);

  js_retval = fdn_vardict_to_value (env, retval);

beach:
  return js_retval;
}

static void
fdn_process_match_options_register (napi_env env,
                                    napi_value exports)
{
  napi_property_descriptor properties[] =
  {
    { "timeout", NULL, NULL, fdn_process_match_options_get_timeout, fdn_process_match_options_set_timeout, NULL, napi_writable | napi_enumerable | napi_configurable, NULL },
    { "scope", NULL, NULL, fdn_process_match_options_get_scope, fdn_process_match_options_set_scope, NULL, napi_writable | napi_enumerable | napi_configurable, NULL },
  };

  napi_value constructor;
  napi_define_class (env, "ProcessMatchOptions", NAPI_AUTO_LENGTH, fdn_process_match_options_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_process_match_options_constructor);

  napi_set_named_property (env, exports, "ProcessMatchOptions", constructor);
}

static gboolean
fdn_process_match_options_from_value (napi_env env,
                                      napi_value value,
                                      FridaProcessMatchOptions ** handle)
{
  bool is_instance;

  if (napi_check_object_type_tag (env, value, &fdn_process_match_options_type_tag, &is_instance) != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of ProcessMatchOptions");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) handle);

  g_object_ref (*handle);

  return TRUE;
}

static napi_value
fdn_process_match_options_to_value (napi_env env,
                                    FridaProcessMatchOptions * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_process_match_options_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);
  napi_type_tag_object (env, handle_wrapper, &fdn_handle_wrapper_type_tag);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_process_match_options_construct (napi_env env,
                                     napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaProcessMatchOptions * handle = NULL;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto propagate_error;

  if (argc == 0)
  {
    handle = frida_process_match_options_new ();
  }
  else
  {
    bool is_instance;

    if (napi_check_object_type_tag (env, args[0], &fdn_handle_wrapper_type_tag, &is_instance) != napi_ok || !is_instance)
      goto invalid_handle;

    if (napi_get_value_external (env, args[0], (void **) &handle) != napi_ok)
      goto propagate_error;

    g_object_ref (handle);
  }

  if (napi_type_tag_object (env, jsthis, &fdn_process_match_options_type_tag) != napi_ok)
    goto propagate_error;

  if (napi_wrap (env, jsthis, handle, NULL, NULL, NULL) != napi_ok)
    goto propagate_error;

  if (napi_add_finalizer (env, jsthis, handle, fdn_object_finalize, NULL, NULL) != napi_ok)
    goto propagate_error;

  return jsthis;

invalid_handle:
  {
    napi_throw_type_error (env, NULL, "expected a ProcessMatchOptions handle");
    goto propagate_error;
  }
propagate_error:
  {
    g_clear_object (&handle);
    return NULL;
  }
}

static napi_value
fdn_process_match_options_get_timeout (napi_env env,
                                       napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaProcessMatchOptions * handle;
  gint retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_process_match_options_get_timeout (handle);

  js_retval = fdn_int_to_value (env, retval);

beach:
  return js_retval;
}

static napi_value
fdn_process_match_options_set_timeout (napi_env env,
                                       napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaProcessMatchOptions * handle;
  gint value;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_int_from_value (env, args[0], &value))
      goto beach;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: value");
    goto beach;
  }

  frida_process_match_options_set_timeout (handle, value);

  napi_get_undefined (env, &js_retval);

beach:
  return js_retval;
}

static napi_value
fdn_process_match_options_get_scope (napi_env env,
                                     napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaProcessMatchOptions * handle;
  FridaScope retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_process_match_options_get_scope (handle);

  js_retval = fdn_scope_to_value (env, retval);

beach:
  return js_retval;
}

static napi_value
fdn_process_match_options_set_scope (napi_env env,
                                     napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaProcessMatchOptions * handle;
  FridaScope value;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_scope_from_value (env, args[0], &value))
      goto beach;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: value");
    goto beach;
  }

  frida_process_match_options_set_scope (handle, value);

  napi_get_undefined (env, &js_retval);

beach:
  return js_retval;
}

static void
fdn_spawn_options_register (napi_env env,
                            napi_value exports)
{
  napi_property_descriptor properties[] =
  {
    { "argv", NULL, NULL, fdn_spawn_options_get_argv, fdn_spawn_options_set_argv, NULL, napi_writable | napi_enumerable | napi_configurable, NULL },
    { "envp", NULL, NULL, fdn_spawn_options_get_envp, fdn_spawn_options_set_envp, NULL, napi_writable | napi_enumerable | napi_configurable, NULL },
    { "env", NULL, NULL, fdn_spawn_options_get_env, fdn_spawn_options_set_env, NULL, napi_writable | napi_enumerable | napi_configurable, NULL },
    { "cwd", NULL, NULL, fdn_spawn_options_get_cwd, fdn_spawn_options_set_cwd, NULL, napi_writable | napi_enumerable | napi_configurable, NULL },
    { "stdio", NULL, NULL, fdn_spawn_options_get_stdio, fdn_spawn_options_set_stdio, NULL, napi_writable | napi_enumerable | napi_configurable, NULL },
    { "aux", NULL, NULL, fdn_spawn_options_get_aux, fdn_spawn_options_set_aux, NULL, napi_writable | napi_enumerable | napi_configurable, NULL },
  };

  napi_value constructor;
  napi_define_class (env, "SpawnOptions", NAPI_AUTO_LENGTH, fdn_spawn_options_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_spawn_options_constructor);

  napi_set_named_property (env, exports, "SpawnOptions", constructor);
}

static gboolean
fdn_spawn_options_from_value (napi_env env,
                              napi_value value,
                              FridaSpawnOptions ** handle)
{
  bool is_instance;

  if (napi_check_object_type_tag (env, value, &fdn_spawn_options_type_tag, &is_instance) != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of SpawnOptions");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) handle);

  g_object_ref (*handle);

  return TRUE;
}

static napi_value
fdn_spawn_options_to_value (napi_env env,
                            FridaSpawnOptions * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_spawn_options_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);
  napi_type_tag_object (env, handle_wrapper, &fdn_handle_wrapper_type_tag);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_spawn_options_construct (napi_env env,
                             napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaSpawnOptions * handle = NULL;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto propagate_error;

  if (argc == 0)
  {
    handle = frida_spawn_options_new ();
  }
  else
  {
    bool is_instance;

    if (napi_check_object_type_tag (env, args[0], &fdn_handle_wrapper_type_tag, &is_instance) != napi_ok || !is_instance)
      goto invalid_handle;

    if (napi_get_value_external (env, args[0], (void **) &handle) != napi_ok)
      goto propagate_error;

    g_object_ref (handle);
  }

  if (napi_type_tag_object (env, jsthis, &fdn_spawn_options_type_tag) != napi_ok)
    goto propagate_error;

  if (napi_wrap (env, jsthis, handle, NULL, NULL, NULL) != napi_ok)
    goto propagate_error;

  if (napi_add_finalizer (env, jsthis, handle, fdn_object_finalize, NULL, NULL) != napi_ok)
    goto propagate_error;

  return jsthis;

invalid_handle:
  {
    napi_throw_type_error (env, NULL, "expected a SpawnOptions handle");
    goto propagate_error;
  }
propagate_error:
  {
    g_clear_object (&handle);
    return NULL;
  }
}

static napi_value
fdn_spawn_options_get_argv (napi_env env,
                            napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaSpawnOptions * handle;
  gint * result_length1 = NULL;
  gchar ** retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_spawn_options_get_argv (handle, result_length1);

  if (retval != NULL)
    js_retval = fdn_strv_to_value (env, retval);
  else
    napi_get_null (env, &js_retval);

beach:
  return js_retval;
}

static napi_value
fdn_spawn_options_set_argv (napi_env env,
                            napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 2;
  napi_value args[2];
  napi_value jsthis;
  FridaSpawnOptions * handle;
  gchar ** value = NULL;
  gint value_length1;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_strv_from_value (env, args[0], &value))
      goto beach;
  }
  else
  {
    value = NULL;
  }
  if (argc > 1 && !fdn_is_undefined_or_null (env, args[1]))
  {
    if (!fdn_int_from_value (env, args[1], &value_length1))
      goto beach;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: valueLength1");
    goto beach;
  }

  frida_spawn_options_set_argv (handle, value, value_length1);

  napi_get_undefined (env, &js_retval);

beach:
  g_clear_pointer (&value, g_strfreev);
  return js_retval;
}

static napi_value
fdn_spawn_options_get_envp (napi_env env,
                            napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaSpawnOptions * handle;
  gint * result_length1 = NULL;
  gchar ** retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_spawn_options_get_envp (handle, result_length1);

  if (retval != NULL)
    js_retval = fdn_strv_to_value (env, retval);
  else
    napi_get_null (env, &js_retval);

beach:
  return js_retval;
}

static napi_value
fdn_spawn_options_set_envp (napi_env env,
                            napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 2;
  napi_value args[2];
  napi_value jsthis;
  FridaSpawnOptions * handle;
  gchar ** value = NULL;
  gint value_length1;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_strv_from_value (env, args[0], &value))
      goto beach;
  }
  else
  {
    value = NULL;
  }
  if (argc > 1 && !fdn_is_undefined_or_null (env, args[1]))
  {
    if (!fdn_int_from_value (env, args[1], &value_length1))
      goto beach;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: valueLength1");
    goto beach;
  }

  frida_spawn_options_set_envp (handle, value, value_length1);

  napi_get_undefined (env, &js_retval);

beach:
  g_clear_pointer (&value, g_strfreev);
  return js_retval;
}

static napi_value
fdn_spawn_options_get_env (napi_env env,
                           napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaSpawnOptions * handle;
  gint * result_length1 = NULL;
  gchar ** retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_spawn_options_get_env (handle, result_length1);

  if (retval != NULL)
    js_retval = fdn_strv_to_value (env, retval);
  else
    napi_get_null (env, &js_retval);

beach:
  return js_retval;
}

static napi_value
fdn_spawn_options_set_env (napi_env env,
                           napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 2;
  napi_value args[2];
  napi_value jsthis;
  FridaSpawnOptions * handle;
  gchar ** value = NULL;
  gint value_length1;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_strv_from_value (env, args[0], &value))
      goto beach;
  }
  else
  {
    value = NULL;
  }
  if (argc > 1 && !fdn_is_undefined_or_null (env, args[1]))
  {
    if (!fdn_int_from_value (env, args[1], &value_length1))
      goto beach;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: valueLength1");
    goto beach;
  }

  frida_spawn_options_set_env (handle, value, value_length1);

  napi_get_undefined (env, &js_retval);

beach:
  g_clear_pointer (&value, g_strfreev);
  return js_retval;
}

static napi_value
fdn_spawn_options_get_cwd (napi_env env,
                           napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaSpawnOptions * handle;
  const gchar * retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_spawn_options_get_cwd (handle);

  if (retval != NULL)
    js_retval = fdn_utf8_to_value (env, retval);
  else
    napi_get_null (env, &js_retval);

beach:
  return js_retval;
}

static napi_value
fdn_spawn_options_set_cwd (napi_env env,
                           napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaSpawnOptions * handle;
  gchar * value = NULL;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_utf8_from_value (env, args[0], &value))
      goto beach;
  }
  else
  {
    value = NULL;
  }

  frida_spawn_options_set_cwd (handle, value);

  napi_get_undefined (env, &js_retval);

beach:
  g_clear_pointer (&value, g_free);
  return js_retval;
}

static napi_value
fdn_spawn_options_get_stdio (napi_env env,
                             napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaSpawnOptions * handle;
  FridaStdio retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_spawn_options_get_stdio (handle);

  js_retval = fdn_stdio_to_value (env, retval);

beach:
  return js_retval;
}

static napi_value
fdn_spawn_options_set_stdio (napi_env env,
                             napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaSpawnOptions * handle;
  FridaStdio value;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_stdio_from_value (env, args[0], &value))
      goto beach;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: value");
    goto beach;
  }

  frida_spawn_options_set_stdio (handle, value);

  napi_get_undefined (env, &js_retval);

beach:
  return js_retval;
}

static napi_value
fdn_spawn_options_get_aux (napi_env env,
                           napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaSpawnOptions * handle;
  GHashTable * retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_spawn_options_get_aux (handle);

  js_retval = fdn_vardict_to_value (env, retval);

beach:
  return js_retval;
}

static napi_value
fdn_spawn_options_set_aux (napi_env env,
                           napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaSpawnOptions * handle;
  GHashTable * value = NULL;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_vardict_from_value (env, args[0], &value))
      goto beach;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: value");
    goto beach;
  }

  frida_spawn_options_set_aux (handle, value);

  napi_get_undefined (env, &js_retval);

beach:
  g_clear_pointer (&value, g_hash_table_unref);
  return js_retval;
}

static napi_value
fdn_spawn_list_to_value (napi_env env,
                         FridaSpawnList * list)
{
  napi_value result;
  gint size, i;

  size = frida_spawn_list_size (list);
  napi_create_array_with_length (env, size, &result);

  for (i = 0; i != size; i++)
  {
    FridaSpawn * handle = frida_spawn_list_get (list, i);
    napi_set_element (env, result, i, fdn_spawn_to_value (env, handle));
    g_object_unref (handle);
  }

  return result;
}

static void
fdn_spawn_register (napi_env env,
                    napi_value exports)
{
  napi_property_descriptor properties[] =
  {
    { "pid", NULL, NULL, fdn_spawn_get_pid, NULL, NULL, napi_enumerable | napi_configurable, NULL },
    { "identifier", NULL, NULL, fdn_spawn_get_identifier, NULL, NULL, napi_enumerable | napi_configurable, NULL },
  };

  napi_value constructor;
  napi_define_class (env, "Spawn", NAPI_AUTO_LENGTH, fdn_spawn_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_spawn_constructor);

  napi_set_named_property (env, exports, "Spawn", constructor);
}

static gboolean
fdn_spawn_from_value (napi_env env,
                      napi_value value,
                      FridaSpawn ** handle)
{
  bool is_instance;

  if (napi_check_object_type_tag (env, value, &fdn_spawn_type_tag, &is_instance) != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of Spawn");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) handle);

  g_object_ref (*handle);

  return TRUE;
}

static napi_value
fdn_spawn_to_value (napi_env env,
                    FridaSpawn * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_spawn_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);
  napi_type_tag_object (env, handle_wrapper, &fdn_handle_wrapper_type_tag);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_spawn_construct (napi_env env,
                     napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaSpawn * handle = NULL;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto propagate_error;

  if (argc == 0)
  {
    napi_throw_error (env, NULL, "type Spawn cannot be constructed because it lacks a default constructor");
    return NULL;
  }
  else
  {
    bool is_instance;

    if (napi_check_object_type_tag (env, args[0], &fdn_handle_wrapper_type_tag, &is_instance) != napi_ok || !is_instance)
      goto invalid_handle;

    if (napi_get_value_external (env, args[0], (void **) &handle) != napi_ok)
      goto propagate_error;

    g_object_ref (handle);
  }

  if (napi_type_tag_object (env, jsthis, &fdn_spawn_type_tag) != napi_ok)
    goto propagate_error;

  if (napi_wrap (env, jsthis, handle, NULL, NULL, NULL) != napi_ok)
    goto propagate_error;

  if (napi_add_finalizer (env, jsthis, handle, fdn_object_finalize, NULL, NULL) != napi_ok)
    goto propagate_error;

  return jsthis;

invalid_handle:
  {
    napi_throw_type_error (env, NULL, "expected a Spawn handle");
    goto propagate_error;
  }
propagate_error:
  {
    g_clear_object (&handle);
    return NULL;
  }
}

static napi_value
fdn_spawn_get_pid (napi_env env,
                   napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaSpawn * handle;
  guint retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_spawn_get_pid (handle);

  js_retval = fdn_uint_to_value (env, retval);

beach:
  return js_retval;
}

static napi_value
fdn_spawn_get_identifier (napi_env env,
                          napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaSpawn * handle;
  const gchar * retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_spawn_get_identifier (handle);

  if (retval != NULL)
    js_retval = fdn_utf8_to_value (env, retval);
  else
    napi_get_null (env, &js_retval);

beach:
  return js_retval;
}

static napi_value
fdn_child_list_to_value (napi_env env,
                         FridaChildList * list)
{
  napi_value result;
  gint size, i;

  size = frida_child_list_size (list);
  napi_create_array_with_length (env, size, &result);

  for (i = 0; i != size; i++)
  {
    FridaChild * handle = frida_child_list_get (list, i);
    napi_set_element (env, result, i, fdn_child_to_value (env, handle));
    g_object_unref (handle);
  }

  return result;
}

static void
fdn_child_register (napi_env env,
                    napi_value exports)
{
  napi_property_descriptor properties[] =
  {
    { "pid", NULL, NULL, fdn_child_get_pid, NULL, NULL, napi_enumerable | napi_configurable, NULL },
    { "parentPid", NULL, NULL, fdn_child_get_parent_pid, NULL, NULL, napi_enumerable | napi_configurable, NULL },
    { "origin", NULL, NULL, fdn_child_get_origin, NULL, NULL, napi_enumerable | napi_configurable, NULL },
    { "identifier", NULL, NULL, fdn_child_get_identifier, NULL, NULL, napi_enumerable | napi_configurable, NULL },
    { "path", NULL, NULL, fdn_child_get_path, NULL, NULL, napi_enumerable | napi_configurable, NULL },
    { "argv", NULL, NULL, fdn_child_get_argv, NULL, NULL, napi_enumerable | napi_configurable, NULL },
    { "envp", NULL, NULL, fdn_child_get_envp, NULL, NULL, napi_enumerable | napi_configurable, NULL },
  };

  napi_value constructor;
  napi_define_class (env, "Child", NAPI_AUTO_LENGTH, fdn_child_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_child_constructor);

  napi_set_named_property (env, exports, "Child", constructor);
}

static gboolean
fdn_child_from_value (napi_env env,
                      napi_value value,
                      FridaChild ** handle)
{
  bool is_instance;

  if (napi_check_object_type_tag (env, value, &fdn_child_type_tag, &is_instance) != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of Child");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) handle);

  g_object_ref (*handle);

  return TRUE;
}

static napi_value
fdn_child_to_value (napi_env env,
                    FridaChild * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_child_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);
  napi_type_tag_object (env, handle_wrapper, &fdn_handle_wrapper_type_tag);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_child_construct (napi_env env,
                     napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaChild * handle = NULL;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto propagate_error;

  if (argc == 0)
  {
    napi_throw_error (env, NULL, "type Child cannot be constructed because it lacks a default constructor");
    return NULL;
  }
  else
  {
    bool is_instance;

    if (napi_check_object_type_tag (env, args[0], &fdn_handle_wrapper_type_tag, &is_instance) != napi_ok || !is_instance)
      goto invalid_handle;

    if (napi_get_value_external (env, args[0], (void **) &handle) != napi_ok)
      goto propagate_error;

    g_object_ref (handle);
  }

  if (napi_type_tag_object (env, jsthis, &fdn_child_type_tag) != napi_ok)
    goto propagate_error;

  if (napi_wrap (env, jsthis, handle, NULL, NULL, NULL) != napi_ok)
    goto propagate_error;

  if (napi_add_finalizer (env, jsthis, handle, fdn_object_finalize, NULL, NULL) != napi_ok)
    goto propagate_error;

  return jsthis;

invalid_handle:
  {
    napi_throw_type_error (env, NULL, "expected a Child handle");
    goto propagate_error;
  }
propagate_error:
  {
    g_clear_object (&handle);
    return NULL;
  }
}

static napi_value
fdn_child_get_pid (napi_env env,
                   napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaChild * handle;
  guint retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_child_get_pid (handle);

  js_retval = fdn_uint_to_value (env, retval);

beach:
  return js_retval;
}

static napi_value
fdn_child_get_parent_pid (napi_env env,
                          napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaChild * handle;
  guint retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_child_get_parent_pid (handle);

  js_retval = fdn_uint_to_value (env, retval);

beach:
  return js_retval;
}

static napi_value
fdn_child_get_origin (napi_env env,
                      napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaChild * handle;
  FridaChildOrigin retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_child_get_origin (handle);

  js_retval = fdn_child_origin_to_value (env, retval);

beach:
  return js_retval;
}

static napi_value
fdn_child_get_identifier (napi_env env,
                          napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaChild * handle;
  const gchar * retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_child_get_identifier (handle);

  if (retval != NULL)
    js_retval = fdn_utf8_to_value (env, retval);
  else
    napi_get_null (env, &js_retval);

beach:
  return js_retval;
}

static napi_value
fdn_child_get_path (napi_env env,
                    napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaChild * handle;
  const gchar * retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_child_get_path (handle);

  if (retval != NULL)
    js_retval = fdn_utf8_to_value (env, retval);
  else
    napi_get_null (env, &js_retval);

beach:
  return js_retval;
}

static napi_value
fdn_child_get_argv (napi_env env,
                    napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaChild * handle;
  gint * result_length1 = NULL;
  gchar ** retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_child_get_argv (handle, result_length1);

  if (retval != NULL)
    js_retval = fdn_strv_to_value (env, retval);
  else
    napi_get_null (env, &js_retval);

beach:
  return js_retval;
}

static napi_value
fdn_child_get_envp (napi_env env,
                    napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaChild * handle;
  gint * result_length1 = NULL;
  gchar ** retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_child_get_envp (handle, result_length1);

  if (retval != NULL)
    js_retval = fdn_strv_to_value (env, retval);
  else
    napi_get_null (env, &js_retval);

beach:
  return js_retval;
}

static void
fdn_crash_register (napi_env env,
                    napi_value exports)
{
  napi_property_descriptor properties[] =
  {
    { "pid", NULL, NULL, fdn_crash_get_pid, NULL, NULL, napi_enumerable | napi_configurable, NULL },
    { "processName", NULL, NULL, fdn_crash_get_process_name, NULL, NULL, napi_enumerable | napi_configurable, NULL },
    { "summary", NULL, NULL, fdn_crash_get_summary, NULL, NULL, napi_enumerable | napi_configurable, NULL },
    { "report", NULL, NULL, fdn_crash_get_report, NULL, NULL, napi_enumerable | napi_configurable, NULL },
    { "parameters", NULL, NULL, fdn_crash_get_parameters, NULL, NULL, napi_enumerable | napi_configurable, NULL },
  };

  napi_value constructor;
  napi_define_class (env, "Crash", NAPI_AUTO_LENGTH, fdn_crash_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_crash_constructor);

  napi_set_named_property (env, exports, "Crash", constructor);
}

static gboolean
fdn_crash_from_value (napi_env env,
                      napi_value value,
                      FridaCrash ** handle)
{
  bool is_instance;

  if (napi_check_object_type_tag (env, value, &fdn_crash_type_tag, &is_instance) != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of Crash");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) handle);

  g_object_ref (*handle);

  return TRUE;
}

static napi_value
fdn_crash_to_value (napi_env env,
                    FridaCrash * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_crash_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);
  napi_type_tag_object (env, handle_wrapper, &fdn_handle_wrapper_type_tag);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_crash_construct (napi_env env,
                     napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaCrash * handle = NULL;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto propagate_error;

  if (argc == 0)
  {
    napi_throw_error (env, NULL, "type Crash cannot be constructed because it lacks a default constructor");
    return NULL;
  }
  else
  {
    bool is_instance;

    if (napi_check_object_type_tag (env, args[0], &fdn_handle_wrapper_type_tag, &is_instance) != napi_ok || !is_instance)
      goto invalid_handle;

    if (napi_get_value_external (env, args[0], (void **) &handle) != napi_ok)
      goto propagate_error;

    g_object_ref (handle);
  }

  if (napi_type_tag_object (env, jsthis, &fdn_crash_type_tag) != napi_ok)
    goto propagate_error;

  if (napi_wrap (env, jsthis, handle, NULL, NULL, NULL) != napi_ok)
    goto propagate_error;

  if (napi_add_finalizer (env, jsthis, handle, fdn_object_finalize, NULL, NULL) != napi_ok)
    goto propagate_error;

  return jsthis;

invalid_handle:
  {
    napi_throw_type_error (env, NULL, "expected a Crash handle");
    goto propagate_error;
  }
propagate_error:
  {
    g_clear_object (&handle);
    return NULL;
  }
}

static napi_value
fdn_crash_get_pid (napi_env env,
                   napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaCrash * handle;
  guint retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_crash_get_pid (handle);

  js_retval = fdn_uint_to_value (env, retval);

beach:
  return js_retval;
}

static napi_value
fdn_crash_get_process_name (napi_env env,
                            napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaCrash * handle;
  const gchar * retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_crash_get_process_name (handle);

  js_retval = fdn_utf8_to_value (env, retval);

beach:
  return js_retval;
}

static napi_value
fdn_crash_get_summary (napi_env env,
                       napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaCrash * handle;
  const gchar * retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_crash_get_summary (handle);

  js_retval = fdn_utf8_to_value (env, retval);

beach:
  return js_retval;
}

static napi_value
fdn_crash_get_report (napi_env env,
                      napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaCrash * handle;
  const gchar * retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_crash_get_report (handle);

  js_retval = fdn_utf8_to_value (env, retval);

beach:
  return js_retval;
}

static napi_value
fdn_crash_get_parameters (napi_env env,
                          napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaCrash * handle;
  GHashTable * retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_crash_get_parameters (handle);

  js_retval = fdn_vardict_to_value (env, retval);

beach:
  return js_retval;
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
    { "device", NULL, NULL, fdn_bus_get_device, NULL, NULL, napi_enumerable | napi_configurable, NULL },
    { "detached", NULL, NULL, fdn_bus_get_detached_signal, NULL, NULL, napi_default, NULL },
    { "message", NULL, NULL, fdn_bus_get_message_signal, NULL, NULL, napi_default, NULL },
  };

  napi_value constructor;
  napi_define_class (env, "Bus", NAPI_AUTO_LENGTH, fdn_bus_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_bus_constructor);

  napi_set_named_property (env, exports, "Bus", constructor);

  napi_value resource_name;

  napi_create_string_utf8 (env, "attach", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_bus_attach_deliver, &fdn_bus_attach_tsfn);
  napi_unref_threadsafe_function (env, fdn_bus_attach_tsfn);
}

static gboolean
fdn_bus_from_value (napi_env env,
                    napi_value value,
                    FridaBus ** handle)
{
  bool is_instance;

  if (napi_check_object_type_tag (env, value, &fdn_bus_type_tag, &is_instance) != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of Bus");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) handle);

  g_object_ref (*handle);

  return TRUE;
}

static napi_value
fdn_bus_to_value (napi_env env,
                  FridaBus * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_bus_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);
  napi_type_tag_object (env, handle_wrapper, &fdn_handle_wrapper_type_tag);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_bus_construct (napi_env env,
                   napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaBus * handle = NULL;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto propagate_error;

  if (argc == 0)
  {
    napi_throw_error (env, NULL, "type Bus cannot be constructed because it lacks a default constructor");
    return NULL;
  }
  else
  {
    bool is_instance;

    if (napi_check_object_type_tag (env, args[0], &fdn_handle_wrapper_type_tag, &is_instance) != napi_ok || !is_instance)
      goto invalid_handle;

    if (napi_get_value_external (env, args[0], (void **) &handle) != napi_ok)
      goto propagate_error;

    g_object_ref (handle);
  }

  if (napi_type_tag_object (env, jsthis, &fdn_bus_type_tag) != napi_ok)
    goto propagate_error;

  if (napi_wrap (env, jsthis, handle, NULL, NULL, NULL) != napi_ok)
    goto propagate_error;

  if (napi_add_finalizer (env, jsthis, handle, fdn_object_finalize, NULL, NULL) != napi_ok)
    goto propagate_error;

  return jsthis;

invalid_handle:
  {
    napi_throw_type_error (env, NULL, "expected a Bus handle");
    goto propagate_error;
  }
propagate_error:
  {
    g_clear_object (&handle);
    return NULL;
  }
}

static napi_value
fdn_bus_is_detached (napi_env env,
                     napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaBus * handle;
  gboolean retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_bus_is_detached (handle);

  js_retval = fdn_boolean_to_value (env, retval);

beach:
  return js_retval;
}

static napi_value
fdn_bus_attach (napi_env env,
                napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaBus * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnBusAttachOperation * operation;
  GSource * source;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    return NULL;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    return NULL;

  napi_create_promise (env, &deferred, &promise);

  operation = g_slice_new0 (FdnBusAttachOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
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
    napi_value js_retval;
    napi_get_undefined (env, &js_retval);
    napi_resolve_deferred (env, operation->deferred, js_retval);
  }

  fdn_bus_attach_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_bus_attach_tsfn);
}

static void
fdn_bus_attach_operation_free (FdnBusAttachOperation * operation)
{
  g_clear_pointer (&operation->cancellable, g_object_unref);
  g_slice_free (FdnBusAttachOperation, operation);
}

static napi_value
fdn_bus_post (napi_env env,
              napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 2;
  napi_value args[2];
  napi_value jsthis;
  FridaBus * handle;
  gchar * json = NULL;
  GBytes * data = NULL;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_utf8_from_value (env, args[0], &json))
      goto beach;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: json");
    goto beach;
  }
  if (argc > 1 && !fdn_is_undefined_or_null (env, args[1]))
  {
    if (!fdn_bytes_from_value (env, args[1], &data))
      goto beach;
  }
  else
  {
    data = NULL;
  }

  frida_bus_post (handle, json, data);

  napi_get_undefined (env, &js_retval);

beach:
  g_clear_pointer (&json, g_free);
  g_clear_pointer (&data, g_bytes_unref);
  return js_retval;
}

static napi_value
fdn_bus_get_device (napi_env env,
                    napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaBus * handle;
  FridaDevice * retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_bus_get_device (handle);

  js_retval = fdn_device_to_value (env, retval);

beach:
  return js_retval;
}

static napi_value
fdn_bus_get_detached_signal (napi_env env,
                             napi_callback_info info)
{
  return fdn_object_get_signal (env, info, "detached", "_detached");
}

static napi_value
fdn_bus_get_message_signal (napi_env env,
                            napi_callback_info info)
{
  return fdn_object_get_signal (env, info, "message", "_message");
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
    { "pid", NULL, NULL, fdn_session_get_pid, NULL, NULL, napi_enumerable | napi_configurable, NULL },
    { "persistTimeout", NULL, NULL, fdn_session_get_persist_timeout, NULL, NULL, napi_enumerable | napi_configurable, NULL },
    { "detached", NULL, NULL, fdn_session_get_detached_signal, NULL, NULL, napi_default, NULL },
  };

  napi_value constructor;
  napi_define_class (env, "Session", NAPI_AUTO_LENGTH, fdn_session_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_session_constructor);

  napi_set_named_property (env, exports, "Session", constructor);

  napi_value resource_name;

  napi_create_string_utf8 (env, "detach", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_session_detach_deliver, &fdn_session_detach_tsfn);
  napi_unref_threadsafe_function (env, fdn_session_detach_tsfn);

  napi_create_string_utf8 (env, "resume", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_session_resume_deliver, &fdn_session_resume_tsfn);
  napi_unref_threadsafe_function (env, fdn_session_resume_tsfn);

  napi_create_string_utf8 (env, "enableChildGating", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_session_enable_child_gating_deliver, &fdn_session_enable_child_gating_tsfn);
  napi_unref_threadsafe_function (env, fdn_session_enable_child_gating_tsfn);

  napi_create_string_utf8 (env, "disableChildGating", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_session_disable_child_gating_deliver, &fdn_session_disable_child_gating_tsfn);
  napi_unref_threadsafe_function (env, fdn_session_disable_child_gating_tsfn);

  napi_create_string_utf8 (env, "createScript", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_session_create_script_deliver, &fdn_session_create_script_tsfn);
  napi_unref_threadsafe_function (env, fdn_session_create_script_tsfn);

  napi_create_string_utf8 (env, "createScriptFromBytes", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_session_create_script_from_bytes_deliver, &fdn_session_create_script_from_bytes_tsfn);
  napi_unref_threadsafe_function (env, fdn_session_create_script_from_bytes_tsfn);

  napi_create_string_utf8 (env, "compileScript", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_session_compile_script_deliver, &fdn_session_compile_script_tsfn);
  napi_unref_threadsafe_function (env, fdn_session_compile_script_tsfn);

  napi_create_string_utf8 (env, "snapshotScript", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_session_snapshot_script_deliver, &fdn_session_snapshot_script_tsfn);
  napi_unref_threadsafe_function (env, fdn_session_snapshot_script_tsfn);

  napi_create_string_utf8 (env, "setupPeerConnection", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_session_setup_peer_connection_deliver, &fdn_session_setup_peer_connection_tsfn);
  napi_unref_threadsafe_function (env, fdn_session_setup_peer_connection_tsfn);

  napi_create_string_utf8 (env, "joinPortal", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_session_join_portal_deliver, &fdn_session_join_portal_tsfn);
  napi_unref_threadsafe_function (env, fdn_session_join_portal_tsfn);
}

static gboolean
fdn_session_from_value (napi_env env,
                        napi_value value,
                        FridaSession ** handle)
{
  bool is_instance;

  if (napi_check_object_type_tag (env, value, &fdn_session_type_tag, &is_instance) != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of Session");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) handle);

  g_object_ref (*handle);

  return TRUE;
}

static napi_value
fdn_session_to_value (napi_env env,
                      FridaSession * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_session_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);
  napi_type_tag_object (env, handle_wrapper, &fdn_handle_wrapper_type_tag);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_session_construct (napi_env env,
                       napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaSession * handle = NULL;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto propagate_error;

  if (argc == 0)
  {
    napi_throw_error (env, NULL, "type Session cannot be constructed because it lacks a default constructor");
    return NULL;
  }
  else
  {
    bool is_instance;

    if (napi_check_object_type_tag (env, args[0], &fdn_handle_wrapper_type_tag, &is_instance) != napi_ok || !is_instance)
      goto invalid_handle;

    if (napi_get_value_external (env, args[0], (void **) &handle) != napi_ok)
      goto propagate_error;

    g_object_ref (handle);
  }

  if (napi_type_tag_object (env, jsthis, &fdn_session_type_tag) != napi_ok)
    goto propagate_error;

  if (napi_wrap (env, jsthis, handle, NULL, NULL, NULL) != napi_ok)
    goto propagate_error;

  if (napi_add_finalizer (env, jsthis, handle, fdn_object_finalize, NULL, NULL) != napi_ok)
    goto propagate_error;

  return jsthis;

invalid_handle:
  {
    napi_throw_type_error (env, NULL, "expected a Session handle");
    goto propagate_error;
  }
propagate_error:
  {
    g_clear_object (&handle);
    return NULL;
  }
}

static napi_value
fdn_session_is_detached (napi_env env,
                         napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaSession * handle;
  gboolean retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_session_is_detached (handle);

  js_retval = fdn_boolean_to_value (env, retval);

beach:
  return js_retval;
}

static napi_value
fdn_session_detach (napi_env env,
                    napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaSession * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnSessionDetachOperation * operation;
  GSource * source;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    return NULL;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    return NULL;

  napi_create_promise (env, &deferred, &promise);

  operation = g_slice_new0 (FdnSessionDetachOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
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
    napi_value js_retval;
    napi_get_undefined (env, &js_retval);
    napi_resolve_deferred (env, operation->deferred, js_retval);
  }

  fdn_session_detach_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_session_detach_tsfn);
}

static void
fdn_session_detach_operation_free (FdnSessionDetachOperation * operation)
{
  g_clear_pointer (&operation->cancellable, g_object_unref);
  g_slice_free (FdnSessionDetachOperation, operation);
}

static napi_value
fdn_session_resume (napi_env env,
                    napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaSession * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnSessionResumeOperation * operation;
  GSource * source;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    return NULL;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    return NULL;

  napi_create_promise (env, &deferred, &promise);

  operation = g_slice_new0 (FdnSessionResumeOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
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
    napi_value js_retval;
    napi_get_undefined (env, &js_retval);
    napi_resolve_deferred (env, operation->deferred, js_retval);
  }

  fdn_session_resume_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_session_resume_tsfn);
}

static void
fdn_session_resume_operation_free (FdnSessionResumeOperation * operation)
{
  g_clear_pointer (&operation->cancellable, g_object_unref);
  g_slice_free (FdnSessionResumeOperation, operation);
}

static napi_value
fdn_session_enable_child_gating (napi_env env,
                                 napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaSession * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnSessionEnableChildGatingOperation * operation;
  GSource * source;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    return NULL;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    return NULL;

  napi_create_promise (env, &deferred, &promise);

  operation = g_slice_new0 (FdnSessionEnableChildGatingOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
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
    napi_value js_retval;
    napi_get_undefined (env, &js_retval);
    napi_resolve_deferred (env, operation->deferred, js_retval);
  }

  fdn_session_enable_child_gating_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_session_enable_child_gating_tsfn);
}

static void
fdn_session_enable_child_gating_operation_free (FdnSessionEnableChildGatingOperation * operation)
{
  g_clear_pointer (&operation->cancellable, g_object_unref);
  g_slice_free (FdnSessionEnableChildGatingOperation, operation);
}

static napi_value
fdn_session_disable_child_gating (napi_env env,
                                  napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaSession * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnSessionDisableChildGatingOperation * operation;
  GSource * source;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    return NULL;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    return NULL;

  napi_create_promise (env, &deferred, &promise);

  operation = g_slice_new0 (FdnSessionDisableChildGatingOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
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
    napi_value js_retval;
    napi_get_undefined (env, &js_retval);
    napi_resolve_deferred (env, operation->deferred, js_retval);
  }

  fdn_session_disable_child_gating_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_session_disable_child_gating_tsfn);
}

static void
fdn_session_disable_child_gating_operation_free (FdnSessionDisableChildGatingOperation * operation)
{
  g_clear_pointer (&operation->cancellable, g_object_unref);
  g_slice_free (FdnSessionDisableChildGatingOperation, operation);
}

static napi_value
fdn_session_create_script (napi_env env,
                           napi_callback_info info)
{
  size_t argc = 3;
  napi_value args[3];
  napi_value jsthis;
  FridaSession * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnSessionCreateScriptOperation * operation;
  GSource * source;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    return NULL;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    return NULL;

  napi_create_promise (env, &deferred, &promise);

  operation = g_slice_new0 (FdnSessionCreateScriptOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_utf8_from_value (env, args[0], &operation->source))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: source");
    goto invalid_argument;
  }

  if (argc > 1 && !fdn_is_undefined_or_null (env, args[1]))
  {
    if (!fdn_script_options_from_value (env, args[1], &operation->options))
      goto invalid_argument;
  }
  else
  {
    operation->options = NULL;
  }

  if (argc > 2 && !fdn_is_undefined_or_null (env, args[2]))
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

  

  operation->retval = frida_session_create_script_finish (operation->handle, res,
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
    napi_value js_retval;
    js_retval = fdn_script_to_value (env, operation->retval);
    napi_resolve_deferred (env, operation->deferred, js_retval);
  }

  fdn_session_create_script_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_session_create_script_tsfn);
}

static void
fdn_session_create_script_operation_free (FdnSessionCreateScriptOperation * operation)
{
  g_clear_pointer (&operation->source, g_free);
  g_clear_pointer (&operation->options, frida_unref);
  g_clear_pointer (&operation->cancellable, g_object_unref);
  g_clear_pointer (&operation->retval, frida_unref);
  g_slice_free (FdnSessionCreateScriptOperation, operation);
}

static napi_value
fdn_session_create_script_from_bytes (napi_env env,
                                      napi_callback_info info)
{
  size_t argc = 3;
  napi_value args[3];
  napi_value jsthis;
  FridaSession * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnSessionCreateScriptFromBytesOperation * operation;
  GSource * source;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    return NULL;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    return NULL;

  napi_create_promise (env, &deferred, &promise);

  operation = g_slice_new0 (FdnSessionCreateScriptFromBytesOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_bytes_from_value (env, args[0], &operation->bytes))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: bytes");
    goto invalid_argument;
  }

  if (argc > 1 && !fdn_is_undefined_or_null (env, args[1]))
  {
    if (!fdn_script_options_from_value (env, args[1], &operation->options))
      goto invalid_argument;
  }
  else
  {
    operation->options = NULL;
  }

  if (argc > 2 && !fdn_is_undefined_or_null (env, args[2]))
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

  

  operation->retval = frida_session_create_script_from_bytes_finish (operation->handle, res,
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
    napi_value js_retval;
    js_retval = fdn_script_to_value (env, operation->retval);
    napi_resolve_deferred (env, operation->deferred, js_retval);
  }

  fdn_session_create_script_from_bytes_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_session_create_script_from_bytes_tsfn);
}

static void
fdn_session_create_script_from_bytes_operation_free (FdnSessionCreateScriptFromBytesOperation * operation)
{
  g_clear_pointer (&operation->bytes, g_bytes_unref);
  g_clear_pointer (&operation->options, frida_unref);
  g_clear_pointer (&operation->cancellable, g_object_unref);
  g_clear_pointer (&operation->retval, frida_unref);
  g_slice_free (FdnSessionCreateScriptFromBytesOperation, operation);
}

static napi_value
fdn_session_compile_script (napi_env env,
                            napi_callback_info info)
{
  size_t argc = 3;
  napi_value args[3];
  napi_value jsthis;
  FridaSession * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnSessionCompileScriptOperation * operation;
  GSource * source;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    return NULL;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    return NULL;

  napi_create_promise (env, &deferred, &promise);

  operation = g_slice_new0 (FdnSessionCompileScriptOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_utf8_from_value (env, args[0], &operation->source))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: source");
    goto invalid_argument;
  }

  if (argc > 1 && !fdn_is_undefined_or_null (env, args[1]))
  {
    if (!fdn_script_options_from_value (env, args[1], &operation->options))
      goto invalid_argument;
  }
  else
  {
    operation->options = NULL;
  }

  if (argc > 2 && !fdn_is_undefined_or_null (env, args[2]))
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

  

  operation->retval = frida_session_compile_script_finish (operation->handle, res,
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
    napi_value js_retval;
    js_retval = fdn_bytes_to_value (env, operation->retval);
    napi_resolve_deferred (env, operation->deferred, js_retval);
  }

  fdn_session_compile_script_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_session_compile_script_tsfn);
}

static void
fdn_session_compile_script_operation_free (FdnSessionCompileScriptOperation * operation)
{
  g_clear_pointer (&operation->source, g_free);
  g_clear_pointer (&operation->options, frida_unref);
  g_clear_pointer (&operation->cancellable, g_object_unref);
  g_clear_pointer (&operation->retval, g_bytes_unref);
  g_slice_free (FdnSessionCompileScriptOperation, operation);
}

static napi_value
fdn_session_snapshot_script (napi_env env,
                             napi_callback_info info)
{
  size_t argc = 3;
  napi_value args[3];
  napi_value jsthis;
  FridaSession * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnSessionSnapshotScriptOperation * operation;
  GSource * source;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    return NULL;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    return NULL;

  napi_create_promise (env, &deferred, &promise);

  operation = g_slice_new0 (FdnSessionSnapshotScriptOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_utf8_from_value (env, args[0], &operation->embed_script))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: embedScript");
    goto invalid_argument;
  }

  if (argc > 1 && !fdn_is_undefined_or_null (env, args[1]))
  {
    if (!fdn_snapshot_options_from_value (env, args[1], &operation->options))
      goto invalid_argument;
  }
  else
  {
    operation->options = NULL;
  }

  if (argc > 2 && !fdn_is_undefined_or_null (env, args[2]))
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

  

  operation->retval = frida_session_snapshot_script_finish (operation->handle, res,
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
    napi_value js_retval;
    js_retval = fdn_bytes_to_value (env, operation->retval);
    napi_resolve_deferred (env, operation->deferred, js_retval);
  }

  fdn_session_snapshot_script_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_session_snapshot_script_tsfn);
}

static void
fdn_session_snapshot_script_operation_free (FdnSessionSnapshotScriptOperation * operation)
{
  g_clear_pointer (&operation->embed_script, g_free);
  g_clear_pointer (&operation->options, frida_unref);
  g_clear_pointer (&operation->cancellable, g_object_unref);
  g_clear_pointer (&operation->retval, g_bytes_unref);
  g_slice_free (FdnSessionSnapshotScriptOperation, operation);
}

static napi_value
fdn_session_setup_peer_connection (napi_env env,
                                   napi_callback_info info)
{
  size_t argc = 2;
  napi_value args[2];
  napi_value jsthis;
  FridaSession * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnSessionSetupPeerConnectionOperation * operation;
  GSource * source;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    return NULL;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    return NULL;

  napi_create_promise (env, &deferred, &promise);

  operation = g_slice_new0 (FdnSessionSetupPeerConnectionOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_peer_options_from_value (env, args[0], &operation->options))
      goto invalid_argument;
  }
  else
  {
    operation->options = NULL;
  }

  if (argc > 1 && !fdn_is_undefined_or_null (env, args[1]))
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
    napi_value js_retval;
    napi_get_undefined (env, &js_retval);
    napi_resolve_deferred (env, operation->deferred, js_retval);
  }

  fdn_session_setup_peer_connection_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_session_setup_peer_connection_tsfn);
}

static void
fdn_session_setup_peer_connection_operation_free (FdnSessionSetupPeerConnectionOperation * operation)
{
  g_clear_pointer (&operation->options, frida_unref);
  g_clear_pointer (&operation->cancellable, g_object_unref);
  g_slice_free (FdnSessionSetupPeerConnectionOperation, operation);
}

static napi_value
fdn_session_join_portal (napi_env env,
                         napi_callback_info info)
{
  size_t argc = 3;
  napi_value args[3];
  napi_value jsthis;
  FridaSession * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnSessionJoinPortalOperation * operation;
  GSource * source;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    return NULL;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    return NULL;

  napi_create_promise (env, &deferred, &promise);

  operation = g_slice_new0 (FdnSessionJoinPortalOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_utf8_from_value (env, args[0], &operation->address))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: address");
    goto invalid_argument;
  }

  if (argc > 1 && !fdn_is_undefined_or_null (env, args[1]))
  {
    if (!fdn_portal_options_from_value (env, args[1], &operation->options))
      goto invalid_argument;
  }
  else
  {
    operation->options = NULL;
  }

  if (argc > 2 && !fdn_is_undefined_or_null (env, args[2]))
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

  

  operation->retval = frida_session_join_portal_finish (operation->handle, res,
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
    napi_value js_retval;
    js_retval = fdn_portal_membership_to_value (env, operation->retval);
    napi_resolve_deferred (env, operation->deferred, js_retval);
  }

  fdn_session_join_portal_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_session_join_portal_tsfn);
}

static void
fdn_session_join_portal_operation_free (FdnSessionJoinPortalOperation * operation)
{
  g_clear_pointer (&operation->address, g_free);
  g_clear_pointer (&operation->options, frida_unref);
  g_clear_pointer (&operation->cancellable, g_object_unref);
  g_clear_pointer (&operation->retval, frida_unref);
  g_slice_free (FdnSessionJoinPortalOperation, operation);
}

static napi_value
fdn_session_get_pid (napi_env env,
                     napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaSession * handle;
  guint retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_session_get_pid (handle);

  js_retval = fdn_uint_to_value (env, retval);

beach:
  return js_retval;
}

static napi_value
fdn_session_get_persist_timeout (napi_env env,
                                 napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaSession * handle;
  guint retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_session_get_persist_timeout (handle);

  js_retval = fdn_uint_to_value (env, retval);

beach:
  return js_retval;
}

static napi_value
fdn_session_get_detached_signal (napi_env env,
                                 napi_callback_info info)
{
  return fdn_object_get_signal (env, info, "detached", "_detached");
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
    { "destroyed", NULL, NULL, fdn_script_get_destroyed_signal, NULL, NULL, napi_default, NULL },
    { "message", NULL, NULL, fdn_script_get_message_signal, NULL, NULL, napi_default, NULL },
  };

  napi_value constructor;
  napi_define_class (env, "Script", NAPI_AUTO_LENGTH, fdn_script_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_script_constructor);

  napi_set_named_property (env, exports, "Script", constructor);

  napi_value resource_name;

  napi_create_string_utf8 (env, "load", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_script_load_deliver, &fdn_script_load_tsfn);
  napi_unref_threadsafe_function (env, fdn_script_load_tsfn);

  napi_create_string_utf8 (env, "unload", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_script_unload_deliver, &fdn_script_unload_tsfn);
  napi_unref_threadsafe_function (env, fdn_script_unload_tsfn);

  napi_create_string_utf8 (env, "eternalize", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_script_eternalize_deliver, &fdn_script_eternalize_tsfn);
  napi_unref_threadsafe_function (env, fdn_script_eternalize_tsfn);

  napi_create_string_utf8 (env, "enableDebugger", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_script_enable_debugger_deliver, &fdn_script_enable_debugger_tsfn);
  napi_unref_threadsafe_function (env, fdn_script_enable_debugger_tsfn);

  napi_create_string_utf8 (env, "disableDebugger", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_script_disable_debugger_deliver, &fdn_script_disable_debugger_tsfn);
  napi_unref_threadsafe_function (env, fdn_script_disable_debugger_tsfn);
}

static gboolean
fdn_script_from_value (napi_env env,
                       napi_value value,
                       FridaScript ** handle)
{
  bool is_instance;

  if (napi_check_object_type_tag (env, value, &fdn_script_type_tag, &is_instance) != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of Script");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) handle);

  g_object_ref (*handle);

  return TRUE;
}

static napi_value
fdn_script_to_value (napi_env env,
                     FridaScript * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_script_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);
  napi_type_tag_object (env, handle_wrapper, &fdn_handle_wrapper_type_tag);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_script_construct (napi_env env,
                      napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaScript * handle = NULL;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto propagate_error;

  if (argc == 0)
  {
    napi_throw_error (env, NULL, "type Script cannot be constructed because it lacks a default constructor");
    return NULL;
  }
  else
  {
    bool is_instance;

    if (napi_check_object_type_tag (env, args[0], &fdn_handle_wrapper_type_tag, &is_instance) != napi_ok || !is_instance)
      goto invalid_handle;

    if (napi_get_value_external (env, args[0], (void **) &handle) != napi_ok)
      goto propagate_error;

    g_object_ref (handle);
  }

  if (napi_type_tag_object (env, jsthis, &fdn_script_type_tag) != napi_ok)
    goto propagate_error;

  if (napi_wrap (env, jsthis, handle, NULL, NULL, NULL) != napi_ok)
    goto propagate_error;

  if (napi_add_finalizer (env, jsthis, handle, fdn_object_finalize, NULL, NULL) != napi_ok)
    goto propagate_error;

  return jsthis;

invalid_handle:
  {
    napi_throw_type_error (env, NULL, "expected a Script handle");
    goto propagate_error;
  }
propagate_error:
  {
    g_clear_object (&handle);
    return NULL;
  }
}

static napi_value
fdn_script_is_destroyed (napi_env env,
                         napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaScript * handle;
  gboolean retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_script_is_destroyed (handle);

  js_retval = fdn_boolean_to_value (env, retval);

beach:
  return js_retval;
}

static napi_value
fdn_script_load (napi_env env,
                 napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaScript * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnScriptLoadOperation * operation;
  GSource * source;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    return NULL;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    return NULL;

  napi_create_promise (env, &deferred, &promise);

  operation = g_slice_new0 (FdnScriptLoadOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
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
    napi_value js_retval;
    napi_get_undefined (env, &js_retval);
    napi_resolve_deferred (env, operation->deferred, js_retval);
  }

  fdn_script_load_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_script_load_tsfn);
}

static void
fdn_script_load_operation_free (FdnScriptLoadOperation * operation)
{
  g_clear_pointer (&operation->cancellable, g_object_unref);
  g_slice_free (FdnScriptLoadOperation, operation);
}

static napi_value
fdn_script_unload (napi_env env,
                   napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaScript * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnScriptUnloadOperation * operation;
  GSource * source;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    return NULL;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    return NULL;

  napi_create_promise (env, &deferred, &promise);

  operation = g_slice_new0 (FdnScriptUnloadOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
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
    napi_value js_retval;
    napi_get_undefined (env, &js_retval);
    napi_resolve_deferred (env, operation->deferred, js_retval);
  }

  fdn_script_unload_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_script_unload_tsfn);
}

static void
fdn_script_unload_operation_free (FdnScriptUnloadOperation * operation)
{
  g_clear_pointer (&operation->cancellable, g_object_unref);
  g_slice_free (FdnScriptUnloadOperation, operation);
}

static napi_value
fdn_script_eternalize (napi_env env,
                       napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaScript * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnScriptEternalizeOperation * operation;
  GSource * source;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    return NULL;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    return NULL;

  napi_create_promise (env, &deferred, &promise);

  operation = g_slice_new0 (FdnScriptEternalizeOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
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
    napi_value js_retval;
    napi_get_undefined (env, &js_retval);
    napi_resolve_deferred (env, operation->deferred, js_retval);
  }

  fdn_script_eternalize_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_script_eternalize_tsfn);
}

static void
fdn_script_eternalize_operation_free (FdnScriptEternalizeOperation * operation)
{
  g_clear_pointer (&operation->cancellable, g_object_unref);
  g_slice_free (FdnScriptEternalizeOperation, operation);
}

static napi_value
fdn_script_post (napi_env env,
                 napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 2;
  napi_value args[2];
  napi_value jsthis;
  FridaScript * handle;
  gchar * json = NULL;
  GBytes * data = NULL;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_utf8_from_value (env, args[0], &json))
      goto beach;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: json");
    goto beach;
  }
  if (argc > 1 && !fdn_is_undefined_or_null (env, args[1]))
  {
    if (!fdn_bytes_from_value (env, args[1], &data))
      goto beach;
  }
  else
  {
    data = NULL;
  }

  frida_script_post (handle, json, data);

  napi_get_undefined (env, &js_retval);

beach:
  g_clear_pointer (&json, g_free);
  g_clear_pointer (&data, g_bytes_unref);
  return js_retval;
}

static napi_value
fdn_script_enable_debugger (napi_env env,
                            napi_callback_info info)
{
  size_t argc = 2;
  napi_value args[2];
  napi_value jsthis;
  FridaScript * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnScriptEnableDebuggerOperation * operation;
  GSource * source;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    return NULL;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    return NULL;

  napi_create_promise (env, &deferred, &promise);

  operation = g_slice_new0 (FdnScriptEnableDebuggerOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_uint16_from_value (env, args[0], &operation->port))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: port");
    goto invalid_argument;
  }

  if (argc > 1 && !fdn_is_undefined_or_null (env, args[1]))
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
    napi_value js_retval;
    napi_get_undefined (env, &js_retval);
    napi_resolve_deferred (env, operation->deferred, js_retval);
  }

  fdn_script_enable_debugger_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_script_enable_debugger_tsfn);
}

static void
fdn_script_enable_debugger_operation_free (FdnScriptEnableDebuggerOperation * operation)
{
  g_clear_pointer (&operation->cancellable, g_object_unref);
  g_slice_free (FdnScriptEnableDebuggerOperation, operation);
}

static napi_value
fdn_script_disable_debugger (napi_env env,
                             napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaScript * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnScriptDisableDebuggerOperation * operation;
  GSource * source;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    return NULL;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    return NULL;

  napi_create_promise (env, &deferred, &promise);

  operation = g_slice_new0 (FdnScriptDisableDebuggerOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
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
    napi_value js_retval;
    napi_get_undefined (env, &js_retval);
    napi_resolve_deferred (env, operation->deferred, js_retval);
  }

  fdn_script_disable_debugger_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_script_disable_debugger_tsfn);
}

static void
fdn_script_disable_debugger_operation_free (FdnScriptDisableDebuggerOperation * operation)
{
  g_clear_pointer (&operation->cancellable, g_object_unref);
  g_slice_free (FdnScriptDisableDebuggerOperation, operation);
}

static napi_value
fdn_script_get_destroyed_signal (napi_env env,
                                 napi_callback_info info)
{
  return fdn_object_get_signal (env, info, "destroyed", "_destroyed");
}

static napi_value
fdn_script_get_message_signal (napi_env env,
                               napi_callback_info info)
{
  return fdn_object_get_signal (env, info, "message", "_message");
}

static void
fdn_portal_membership_register (napi_env env,
                                napi_value exports)
{
  napi_property_descriptor properties[] =
  {
    { "terminate", NULL, fdn_portal_membership_terminate, NULL, NULL, NULL, napi_default, NULL },
  };

  napi_value constructor;
  napi_define_class (env, "PortalMembership", NAPI_AUTO_LENGTH, fdn_portal_membership_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_portal_membership_constructor);

  napi_set_named_property (env, exports, "PortalMembership", constructor);

  napi_value resource_name;

  napi_create_string_utf8 (env, "terminate", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_portal_membership_terminate_deliver, &fdn_portal_membership_terminate_tsfn);
  napi_unref_threadsafe_function (env, fdn_portal_membership_terminate_tsfn);
}

static gboolean
fdn_portal_membership_from_value (napi_env env,
                                  napi_value value,
                                  FridaPortalMembership ** handle)
{
  bool is_instance;

  if (napi_check_object_type_tag (env, value, &fdn_portal_membership_type_tag, &is_instance) != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of PortalMembership");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) handle);

  g_object_ref (*handle);

  return TRUE;
}

static napi_value
fdn_portal_membership_to_value (napi_env env,
                                FridaPortalMembership * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_portal_membership_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);
  napi_type_tag_object (env, handle_wrapper, &fdn_handle_wrapper_type_tag);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_portal_membership_construct (napi_env env,
                                 napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaPortalMembership * handle = NULL;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto propagate_error;

  if (argc == 0)
  {
    napi_throw_error (env, NULL, "type PortalMembership cannot be constructed because it lacks a default constructor");
    return NULL;
  }
  else
  {
    bool is_instance;

    if (napi_check_object_type_tag (env, args[0], &fdn_handle_wrapper_type_tag, &is_instance) != napi_ok || !is_instance)
      goto invalid_handle;

    if (napi_get_value_external (env, args[0], (void **) &handle) != napi_ok)
      goto propagate_error;

    g_object_ref (handle);
  }

  if (napi_type_tag_object (env, jsthis, &fdn_portal_membership_type_tag) != napi_ok)
    goto propagate_error;

  if (napi_wrap (env, jsthis, handle, NULL, NULL, NULL) != napi_ok)
    goto propagate_error;

  if (napi_add_finalizer (env, jsthis, handle, fdn_object_finalize, NULL, NULL) != napi_ok)
    goto propagate_error;

  return jsthis;

invalid_handle:
  {
    napi_throw_type_error (env, NULL, "expected a PortalMembership handle");
    goto propagate_error;
  }
propagate_error:
  {
    g_clear_object (&handle);
    return NULL;
  }
}

static napi_value
fdn_portal_membership_terminate (napi_env env,
                                 napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaPortalMembership * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnPortalMembershipTerminateOperation * operation;
  GSource * source;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    return NULL;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    return NULL;

  napi_create_promise (env, &deferred, &promise);

  operation = g_slice_new0 (FdnPortalMembershipTerminateOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
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
    napi_value js_retval;
    napi_get_undefined (env, &js_retval);
    napi_resolve_deferred (env, operation->deferred, js_retval);
  }

  fdn_portal_membership_terminate_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_portal_membership_terminate_tsfn);
}

static void
fdn_portal_membership_terminate_operation_free (FdnPortalMembershipTerminateOperation * operation)
{
  g_clear_pointer (&operation->cancellable, g_object_unref);
  g_slice_free (FdnPortalMembershipTerminateOperation, operation);
}

static void
fdn_control_service_options_register (napi_env env,
                                      napi_value exports)
{
  napi_property_descriptor properties[] =
  {
    { "sysroot", NULL, NULL, fdn_control_service_options_get_sysroot, fdn_control_service_options_set_sysroot, NULL, napi_writable | napi_enumerable | napi_configurable, NULL },
    { "enablePreload", NULL, NULL, fdn_control_service_options_get_enable_preload, fdn_control_service_options_set_enable_preload, NULL, napi_writable | napi_enumerable | napi_configurable, NULL },
    { "reportCrashes", NULL, NULL, fdn_control_service_options_get_report_crashes, fdn_control_service_options_set_report_crashes, NULL, napi_writable | napi_enumerable | napi_configurable, NULL },
  };

  napi_value constructor;
  napi_define_class (env, "ControlServiceOptions", NAPI_AUTO_LENGTH, fdn_control_service_options_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_control_service_options_constructor);

  napi_set_named_property (env, exports, "ControlServiceOptions", constructor);
}

static gboolean
fdn_control_service_options_from_value (napi_env env,
                                        napi_value value,
                                        FridaControlServiceOptions ** handle)
{
  bool is_instance;

  if (napi_check_object_type_tag (env, value, &fdn_control_service_options_type_tag, &is_instance) != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of ControlServiceOptions");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) handle);

  g_object_ref (*handle);

  return TRUE;
}

static napi_value
fdn_control_service_options_to_value (napi_env env,
                                      FridaControlServiceOptions * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_control_service_options_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);
  napi_type_tag_object (env, handle_wrapper, &fdn_handle_wrapper_type_tag);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_control_service_options_construct (napi_env env,
                                       napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaControlServiceOptions * handle = NULL;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto propagate_error;

  if (argc == 0)
  {
    handle = frida_control_service_options_new ();
  }
  else
  {
    bool is_instance;

    if (napi_check_object_type_tag (env, args[0], &fdn_handle_wrapper_type_tag, &is_instance) != napi_ok || !is_instance)
      goto invalid_handle;

    if (napi_get_value_external (env, args[0], (void **) &handle) != napi_ok)
      goto propagate_error;

    g_object_ref (handle);
  }

  if (napi_type_tag_object (env, jsthis, &fdn_control_service_options_type_tag) != napi_ok)
    goto propagate_error;

  if (napi_wrap (env, jsthis, handle, NULL, NULL, NULL) != napi_ok)
    goto propagate_error;

  if (napi_add_finalizer (env, jsthis, handle, fdn_object_finalize, NULL, NULL) != napi_ok)
    goto propagate_error;

  return jsthis;

invalid_handle:
  {
    napi_throw_type_error (env, NULL, "expected a ControlServiceOptions handle");
    goto propagate_error;
  }
propagate_error:
  {
    g_clear_object (&handle);
    return NULL;
  }
}

static napi_value
fdn_control_service_options_get_sysroot (napi_env env,
                                         napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaControlServiceOptions * handle;
  const gchar * retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_control_service_options_get_sysroot (handle);

  if (retval != NULL)
    js_retval = fdn_utf8_to_value (env, retval);
  else
    napi_get_null (env, &js_retval);

beach:
  return js_retval;
}

static napi_value
fdn_control_service_options_set_sysroot (napi_env env,
                                         napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaControlServiceOptions * handle;
  gchar * value = NULL;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_utf8_from_value (env, args[0], &value))
      goto beach;
  }
  else
  {
    value = NULL;
  }

  frida_control_service_options_set_sysroot (handle, value);

  napi_get_undefined (env, &js_retval);

beach:
  g_clear_pointer (&value, g_free);
  return js_retval;
}

static napi_value
fdn_control_service_options_get_enable_preload (napi_env env,
                                                napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaControlServiceOptions * handle;
  gboolean retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_control_service_options_get_enable_preload (handle);

  js_retval = fdn_boolean_to_value (env, retval);

beach:
  return js_retval;
}

static napi_value
fdn_control_service_options_set_enable_preload (napi_env env,
                                                napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaControlServiceOptions * handle;
  gboolean value;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_boolean_from_value (env, args[0], &value))
      goto beach;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: value");
    goto beach;
  }

  frida_control_service_options_set_enable_preload (handle, value);

  napi_get_undefined (env, &js_retval);

beach:
  return js_retval;
}

static napi_value
fdn_control_service_options_get_report_crashes (napi_env env,
                                                napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaControlServiceOptions * handle;
  gboolean retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_control_service_options_get_report_crashes (handle);

  js_retval = fdn_boolean_to_value (env, retval);

beach:
  return js_retval;
}

static napi_value
fdn_control_service_options_set_report_crashes (napi_env env,
                                                napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaControlServiceOptions * handle;
  gboolean value;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_boolean_from_value (env, args[0], &value))
      goto beach;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: value");
    goto beach;
  }

  frida_control_service_options_set_report_crashes (handle, value);

  napi_get_undefined (env, &js_retval);

beach:
  return js_retval;
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
    { "device", NULL, NULL, fdn_portal_service_get_device, NULL, NULL, napi_enumerable | napi_configurable, NULL },
    { "clusterParams", NULL, NULL, fdn_portal_service_get_cluster_params, NULL, NULL, napi_enumerable | napi_configurable, NULL },
    { "controlParams", NULL, NULL, fdn_portal_service_get_control_params, NULL, NULL, napi_enumerable | napi_configurable, NULL },
    { "nodeConnected", NULL, NULL, fdn_portal_service_get_node_connected_signal, NULL, NULL, napi_default, NULL },
    { "nodeJoined", NULL, NULL, fdn_portal_service_get_node_joined_signal, NULL, NULL, napi_default, NULL },
    { "nodeLeft", NULL, NULL, fdn_portal_service_get_node_left_signal, NULL, NULL, napi_default, NULL },
    { "nodeDisconnected", NULL, NULL, fdn_portal_service_get_node_disconnected_signal, NULL, NULL, napi_default, NULL },
    { "controllerConnected", NULL, NULL, fdn_portal_service_get_controller_connected_signal, NULL, NULL, napi_default, NULL },
    { "controllerDisconnected", NULL, NULL, fdn_portal_service_get_controller_disconnected_signal, NULL, NULL, napi_default, NULL },
    { "authenticated", NULL, NULL, fdn_portal_service_get_authenticated_signal, NULL, NULL, napi_default, NULL },
    { "subscribe", NULL, NULL, fdn_portal_service_get_subscribe_signal, NULL, NULL, napi_default, NULL },
    { "message", NULL, NULL, fdn_portal_service_get_message_signal, NULL, NULL, napi_default, NULL },
  };

  napi_value constructor;
  napi_define_class (env, "PortalService", NAPI_AUTO_LENGTH, fdn_portal_service_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_portal_service_constructor);

  napi_set_named_property (env, exports, "PortalService", constructor);

  napi_value resource_name;

  napi_create_string_utf8 (env, "start", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_portal_service_start_deliver, &fdn_portal_service_start_tsfn);
  napi_unref_threadsafe_function (env, fdn_portal_service_start_tsfn);

  napi_create_string_utf8 (env, "stop", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_portal_service_stop_deliver, &fdn_portal_service_stop_tsfn);
  napi_unref_threadsafe_function (env, fdn_portal_service_stop_tsfn);
}

static gboolean
fdn_portal_service_from_value (napi_env env,
                               napi_value value,
                               FridaPortalService ** handle)
{
  bool is_instance;

  if (napi_check_object_type_tag (env, value, &fdn_portal_service_type_tag, &is_instance) != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of PortalService");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) handle);

  g_object_ref (*handle);

  return TRUE;
}

static napi_value
fdn_portal_service_to_value (napi_env env,
                             FridaPortalService * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_portal_service_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);
  napi_type_tag_object (env, handle_wrapper, &fdn_handle_wrapper_type_tag);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_portal_service_construct (napi_env env,
                              napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaPortalService * handle = NULL;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto propagate_error;

  if (argc == 0)
  {
    napi_throw_error (env, NULL, "type PortalService cannot be constructed because it lacks a default constructor");
    return NULL;
  }
  else
  {
    bool is_instance;

    if (napi_check_object_type_tag (env, args[0], &fdn_handle_wrapper_type_tag, &is_instance) != napi_ok || !is_instance)
      goto invalid_handle;

    if (napi_get_value_external (env, args[0], (void **) &handle) != napi_ok)
      goto propagate_error;

    g_object_ref (handle);
  }

  if (napi_type_tag_object (env, jsthis, &fdn_portal_service_type_tag) != napi_ok)
    goto propagate_error;

  if (napi_wrap (env, jsthis, handle, NULL, NULL, NULL) != napi_ok)
    goto propagate_error;

  if (napi_add_finalizer (env, jsthis, handle, fdn_object_finalize, NULL, NULL) != napi_ok)
    goto propagate_error;

  return jsthis;

invalid_handle:
  {
    napi_throw_type_error (env, NULL, "expected a PortalService handle");
    goto propagate_error;
  }
propagate_error:
  {
    g_clear_object (&handle);
    return NULL;
  }
}

static napi_value
fdn_portal_service_start (napi_env env,
                          napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaPortalService * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnPortalServiceStartOperation * operation;
  GSource * source;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    return NULL;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    return NULL;

  napi_create_promise (env, &deferred, &promise);

  operation = g_slice_new0 (FdnPortalServiceStartOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
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
    napi_value js_retval;
    napi_get_undefined (env, &js_retval);
    napi_resolve_deferred (env, operation->deferred, js_retval);
  }

  fdn_portal_service_start_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_portal_service_start_tsfn);
}

static void
fdn_portal_service_start_operation_free (FdnPortalServiceStartOperation * operation)
{
  g_clear_pointer (&operation->cancellable, g_object_unref);
  g_slice_free (FdnPortalServiceStartOperation, operation);
}

static napi_value
fdn_portal_service_stop (napi_env env,
                         napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaPortalService * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnPortalServiceStopOperation * operation;
  GSource * source;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    return NULL;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    return NULL;

  napi_create_promise (env, &deferred, &promise);

  operation = g_slice_new0 (FdnPortalServiceStopOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
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
    napi_value js_retval;
    napi_get_undefined (env, &js_retval);
    napi_resolve_deferred (env, operation->deferred, js_retval);
  }

  fdn_portal_service_stop_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_portal_service_stop_tsfn);
}

static void
fdn_portal_service_stop_operation_free (FdnPortalServiceStopOperation * operation)
{
  g_clear_pointer (&operation->cancellable, g_object_unref);
  g_slice_free (FdnPortalServiceStopOperation, operation);
}

static napi_value
fdn_portal_service_kick (napi_env env,
                         napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaPortalService * handle;
  guint connection_id;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_uint_from_value (env, args[0], &connection_id))
      goto beach;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: connectionId");
    goto beach;
  }

  frida_portal_service_kick (handle, connection_id);

  napi_get_undefined (env, &js_retval);

beach:
  return js_retval;
}

static napi_value
fdn_portal_service_post (napi_env env,
                         napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 3;
  napi_value args[3];
  napi_value jsthis;
  FridaPortalService * handle;
  guint connection_id;
  gchar * json = NULL;
  GBytes * data = NULL;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_uint_from_value (env, args[0], &connection_id))
      goto beach;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: connectionId");
    goto beach;
  }
  if (argc > 1 && !fdn_is_undefined_or_null (env, args[1]))
  {
    if (!fdn_utf8_from_value (env, args[1], &json))
      goto beach;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: json");
    goto beach;
  }
  if (argc > 2 && !fdn_is_undefined_or_null (env, args[2]))
  {
    if (!fdn_bytes_from_value (env, args[2], &data))
      goto beach;
  }
  else
  {
    data = NULL;
  }

  frida_portal_service_post (handle, connection_id, json, data);

  napi_get_undefined (env, &js_retval);

beach:
  g_clear_pointer (&json, g_free);
  g_clear_pointer (&data, g_bytes_unref);
  return js_retval;
}

static napi_value
fdn_portal_service_narrowcast (napi_env env,
                               napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 3;
  napi_value args[3];
  napi_value jsthis;
  FridaPortalService * handle;
  gchar * tag = NULL;
  gchar * json = NULL;
  GBytes * data = NULL;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_utf8_from_value (env, args[0], &tag))
      goto beach;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: tag");
    goto beach;
  }
  if (argc > 1 && !fdn_is_undefined_or_null (env, args[1]))
  {
    if (!fdn_utf8_from_value (env, args[1], &json))
      goto beach;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: json");
    goto beach;
  }
  if (argc > 2 && !fdn_is_undefined_or_null (env, args[2]))
  {
    if (!fdn_bytes_from_value (env, args[2], &data))
      goto beach;
  }
  else
  {
    data = NULL;
  }

  frida_portal_service_narrowcast (handle, tag, json, data);

  napi_get_undefined (env, &js_retval);

beach:
  g_clear_pointer (&tag, g_free);
  g_clear_pointer (&json, g_free);
  g_clear_pointer (&data, g_bytes_unref);
  return js_retval;
}

static napi_value
fdn_portal_service_broadcast (napi_env env,
                              napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 2;
  napi_value args[2];
  napi_value jsthis;
  FridaPortalService * handle;
  gchar * json = NULL;
  GBytes * data = NULL;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_utf8_from_value (env, args[0], &json))
      goto beach;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: json");
    goto beach;
  }
  if (argc > 1 && !fdn_is_undefined_or_null (env, args[1]))
  {
    if (!fdn_bytes_from_value (env, args[1], &data))
      goto beach;
  }
  else
  {
    data = NULL;
  }

  frida_portal_service_broadcast (handle, json, data);

  napi_get_undefined (env, &js_retval);

beach:
  g_clear_pointer (&json, g_free);
  g_clear_pointer (&data, g_bytes_unref);
  return js_retval;
}

static napi_value
fdn_portal_service_enumerate_tags (napi_env env,
                                   napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 2;
  napi_value args[2];
  napi_value jsthis;
  FridaPortalService * handle;
  guint connection_id;
  gint * result_length1 = NULL;
  gchar ** retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_uint_from_value (env, args[0], &connection_id))
      goto beach;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: connectionId");
    goto beach;
  }

  retval = frida_portal_service_enumerate_tags (handle, connection_id, result_length1);

  if (retval != NULL)
    js_retval = fdn_strv_to_value (env, retval);
  else
    napi_get_null (env, &js_retval);

beach:
  return js_retval;
}

static napi_value
fdn_portal_service_tag (napi_env env,
                        napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 2;
  napi_value args[2];
  napi_value jsthis;
  FridaPortalService * handle;
  guint connection_id;
  gchar * tag = NULL;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_uint_from_value (env, args[0], &connection_id))
      goto beach;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: connectionId");
    goto beach;
  }
  if (argc > 1 && !fdn_is_undefined_or_null (env, args[1]))
  {
    if (!fdn_utf8_from_value (env, args[1], &tag))
      goto beach;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: tag");
    goto beach;
  }

  frida_portal_service_tag (handle, connection_id, tag);

  napi_get_undefined (env, &js_retval);

beach:
  g_clear_pointer (&tag, g_free);
  return js_retval;
}

static napi_value
fdn_portal_service_untag (napi_env env,
                          napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 2;
  napi_value args[2];
  napi_value jsthis;
  FridaPortalService * handle;
  guint connection_id;
  gchar * tag = NULL;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_uint_from_value (env, args[0], &connection_id))
      goto beach;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: connectionId");
    goto beach;
  }
  if (argc > 1 && !fdn_is_undefined_or_null (env, args[1]))
  {
    if (!fdn_utf8_from_value (env, args[1], &tag))
      goto beach;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: tag");
    goto beach;
  }

  frida_portal_service_untag (handle, connection_id, tag);

  napi_get_undefined (env, &js_retval);

beach:
  g_clear_pointer (&tag, g_free);
  return js_retval;
}

static napi_value
fdn_portal_service_get_device (napi_env env,
                               napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaPortalService * handle;
  FridaDevice * retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_portal_service_get_device (handle);

  js_retval = fdn_device_to_value (env, retval);

beach:
  return js_retval;
}

static napi_value
fdn_portal_service_get_cluster_params (napi_env env,
                                       napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaPortalService * handle;
  FridaEndpointParameters * retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_portal_service_get_cluster_params (handle);

  js_retval = fdn_endpoint_parameters_to_value (env, retval);

beach:
  return js_retval;
}

static napi_value
fdn_portal_service_get_control_params (napi_env env,
                                       napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaPortalService * handle;
  FridaEndpointParameters * retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_portal_service_get_control_params (handle);

  if (retval != NULL)
    js_retval = fdn_endpoint_parameters_to_value (env, retval);
  else
    napi_get_null (env, &js_retval);

beach:
  return js_retval;
}

static napi_value
fdn_portal_service_get_node_connected_signal (napi_env env,
                                              napi_callback_info info)
{
  return fdn_object_get_signal (env, info, "node-connected", "_nodeConnected");
}

static napi_value
fdn_portal_service_get_node_joined_signal (napi_env env,
                                           napi_callback_info info)
{
  return fdn_object_get_signal (env, info, "node-joined", "_nodeJoined");
}

static napi_value
fdn_portal_service_get_node_left_signal (napi_env env,
                                         napi_callback_info info)
{
  return fdn_object_get_signal (env, info, "node-left", "_nodeLeft");
}

static napi_value
fdn_portal_service_get_node_disconnected_signal (napi_env env,
                                                 napi_callback_info info)
{
  return fdn_object_get_signal (env, info, "node-disconnected", "_nodeDisconnected");
}

static napi_value
fdn_portal_service_get_controller_connected_signal (napi_env env,
                                                    napi_callback_info info)
{
  return fdn_object_get_signal (env, info, "controller-connected", "_controllerConnected");
}

static napi_value
fdn_portal_service_get_controller_disconnected_signal (napi_env env,
                                                       napi_callback_info info)
{
  return fdn_object_get_signal (env, info, "controller-disconnected", "_controllerDisconnected");
}

static napi_value
fdn_portal_service_get_authenticated_signal (napi_env env,
                                             napi_callback_info info)
{
  return fdn_object_get_signal (env, info, "authenticated", "_authenticated");
}

static napi_value
fdn_portal_service_get_subscribe_signal (napi_env env,
                                         napi_callback_info info)
{
  return fdn_object_get_signal (env, info, "subscribe", "_subscribe");
}

static napi_value
fdn_portal_service_get_message_signal (napi_env env,
                                       napi_callback_info info)
{
  return fdn_object_get_signal (env, info, "message", "_message");
}

static void
fdn_file_monitor_register (napi_env env,
                           napi_value exports)
{
  napi_property_descriptor properties[] =
  {
    { "enable", NULL, fdn_file_monitor_enable, NULL, NULL, NULL, napi_default, NULL },
    { "disable", NULL, fdn_file_monitor_disable, NULL, NULL, NULL, napi_default, NULL },
    { "path", NULL, NULL, fdn_file_monitor_get_path, NULL, NULL, napi_enumerable | napi_configurable, NULL },
    { "change", NULL, NULL, fdn_file_monitor_get_change_signal, NULL, NULL, napi_default, NULL },
  };

  napi_value constructor;
  napi_define_class (env, "FileMonitor", NAPI_AUTO_LENGTH, fdn_file_monitor_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_file_monitor_constructor);

  napi_set_named_property (env, exports, "FileMonitor", constructor);

  napi_value resource_name;

  napi_create_string_utf8 (env, "enable", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_file_monitor_enable_deliver, &fdn_file_monitor_enable_tsfn);
  napi_unref_threadsafe_function (env, fdn_file_monitor_enable_tsfn);

  napi_create_string_utf8 (env, "disable", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_file_monitor_disable_deliver, &fdn_file_monitor_disable_tsfn);
  napi_unref_threadsafe_function (env, fdn_file_monitor_disable_tsfn);
}

static gboolean
fdn_file_monitor_from_value (napi_env env,
                             napi_value value,
                             FridaFileMonitor ** handle)
{
  bool is_instance;

  if (napi_check_object_type_tag (env, value, &fdn_file_monitor_type_tag, &is_instance) != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of FileMonitor");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) handle);

  g_object_ref (*handle);

  return TRUE;
}

static napi_value
fdn_file_monitor_to_value (napi_env env,
                           FridaFileMonitor * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_file_monitor_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);
  napi_type_tag_object (env, handle_wrapper, &fdn_handle_wrapper_type_tag);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_file_monitor_construct (napi_env env,
                            napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaFileMonitor * handle = NULL;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto propagate_error;

  if (argc == 0)
  {
    napi_throw_error (env, NULL, "type FileMonitor cannot be constructed because it lacks a default constructor");
    return NULL;
  }
  else
  {
    bool is_instance;

    if (napi_check_object_type_tag (env, args[0], &fdn_handle_wrapper_type_tag, &is_instance) != napi_ok || !is_instance)
      goto invalid_handle;

    if (napi_get_value_external (env, args[0], (void **) &handle) != napi_ok)
      goto propagate_error;

    g_object_ref (handle);
  }

  if (napi_type_tag_object (env, jsthis, &fdn_file_monitor_type_tag) != napi_ok)
    goto propagate_error;

  if (napi_wrap (env, jsthis, handle, NULL, NULL, NULL) != napi_ok)
    goto propagate_error;

  if (napi_add_finalizer (env, jsthis, handle, fdn_object_finalize, NULL, NULL) != napi_ok)
    goto propagate_error;

  return jsthis;

invalid_handle:
  {
    napi_throw_type_error (env, NULL, "expected a FileMonitor handle");
    goto propagate_error;
  }
propagate_error:
  {
    g_clear_object (&handle);
    return NULL;
  }
}

static napi_value
fdn_file_monitor_enable (napi_env env,
                         napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaFileMonitor * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnFileMonitorEnableOperation * operation;
  GSource * source;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    return NULL;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    return NULL;

  napi_create_promise (env, &deferred, &promise);

  operation = g_slice_new0 (FdnFileMonitorEnableOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
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
    napi_value js_retval;
    napi_get_undefined (env, &js_retval);
    napi_resolve_deferred (env, operation->deferred, js_retval);
  }

  fdn_file_monitor_enable_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_file_monitor_enable_tsfn);
}

static void
fdn_file_monitor_enable_operation_free (FdnFileMonitorEnableOperation * operation)
{
  g_clear_pointer (&operation->cancellable, g_object_unref);
  g_slice_free (FdnFileMonitorEnableOperation, operation);
}

static napi_value
fdn_file_monitor_disable (napi_env env,
                          napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaFileMonitor * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnFileMonitorDisableOperation * operation;
  GSource * source;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    return NULL;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    return NULL;

  napi_create_promise (env, &deferred, &promise);

  operation = g_slice_new0 (FdnFileMonitorDisableOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
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
    napi_value js_retval;
    napi_get_undefined (env, &js_retval);
    napi_resolve_deferred (env, operation->deferred, js_retval);
  }

  fdn_file_monitor_disable_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_file_monitor_disable_tsfn);
}

static void
fdn_file_monitor_disable_operation_free (FdnFileMonitorDisableOperation * operation)
{
  g_clear_pointer (&operation->cancellable, g_object_unref);
  g_slice_free (FdnFileMonitorDisableOperation, operation);
}

static napi_value
fdn_file_monitor_get_path (napi_env env,
                           napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaFileMonitor * handle;
  const gchar * retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_file_monitor_get_path (handle);

  js_retval = fdn_utf8_to_value (env, retval);

beach:
  return js_retval;
}

static napi_value
fdn_file_monitor_get_change_signal (napi_env env,
                                    napi_callback_info info)
{
  return fdn_object_get_signal (env, info, "change", "_change");
}

static void
fdn_compiler_register (napi_env env,
                       napi_value exports)
{
  napi_property_descriptor properties[] =
  {
    { "build", NULL, fdn_compiler_build, NULL, NULL, NULL, napi_default, NULL },
    { "watch", NULL, fdn_compiler_watch, NULL, NULL, NULL, napi_default, NULL },
    { "manager", NULL, NULL, fdn_compiler_get_manager, NULL, NULL, napi_enumerable | napi_configurable, NULL },
    { "starting", NULL, NULL, fdn_compiler_get_starting_signal, NULL, NULL, napi_default, NULL },
    { "finished", NULL, NULL, fdn_compiler_get_finished_signal, NULL, NULL, napi_default, NULL },
    { "output", NULL, NULL, fdn_compiler_get_output_signal, NULL, NULL, napi_default, NULL },
    { "diagnostics", NULL, NULL, fdn_compiler_get_diagnostics_signal, NULL, NULL, napi_default, NULL },
  };

  napi_value constructor;
  napi_define_class (env, "Compiler", NAPI_AUTO_LENGTH, fdn_compiler_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_compiler_constructor);

  napi_set_named_property (env, exports, "Compiler", constructor);

  napi_value resource_name;

  napi_create_string_utf8 (env, "build", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_compiler_build_deliver, &fdn_compiler_build_tsfn);
  napi_unref_threadsafe_function (env, fdn_compiler_build_tsfn);

  napi_create_string_utf8 (env, "watch", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_compiler_watch_deliver, &fdn_compiler_watch_tsfn);
  napi_unref_threadsafe_function (env, fdn_compiler_watch_tsfn);
}

static gboolean
fdn_compiler_from_value (napi_env env,
                         napi_value value,
                         FridaCompiler ** handle)
{
  bool is_instance;

  if (napi_check_object_type_tag (env, value, &fdn_compiler_type_tag, &is_instance) != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of Compiler");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) handle);

  g_object_ref (*handle);

  return TRUE;
}

static napi_value
fdn_compiler_to_value (napi_env env,
                       FridaCompiler * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_compiler_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);
  napi_type_tag_object (env, handle_wrapper, &fdn_handle_wrapper_type_tag);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_compiler_construct (napi_env env,
                        napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaCompiler * handle = NULL;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto propagate_error;

  if (argc == 0)
  {
    napi_throw_error (env, NULL, "type Compiler cannot be constructed because it lacks a default constructor");
    return NULL;
  }
  else
  {
    bool is_instance;

    if (napi_check_object_type_tag (env, args[0], &fdn_handle_wrapper_type_tag, &is_instance) != napi_ok || !is_instance)
      goto invalid_handle;

    if (napi_get_value_external (env, args[0], (void **) &handle) != napi_ok)
      goto propagate_error;

    g_object_ref (handle);
  }

  if (napi_type_tag_object (env, jsthis, &fdn_compiler_type_tag) != napi_ok)
    goto propagate_error;

  if (napi_wrap (env, jsthis, handle, NULL, NULL, NULL) != napi_ok)
    goto propagate_error;

  if (napi_add_finalizer (env, jsthis, handle, fdn_object_finalize, NULL, NULL) != napi_ok)
    goto propagate_error;

  return jsthis;

invalid_handle:
  {
    napi_throw_type_error (env, NULL, "expected a Compiler handle");
    goto propagate_error;
  }
propagate_error:
  {
    g_clear_object (&handle);
    return NULL;
  }
}

static napi_value
fdn_compiler_build (napi_env env,
                    napi_callback_info info)
{
  size_t argc = 3;
  napi_value args[3];
  napi_value jsthis;
  FridaCompiler * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnCompilerBuildOperation * operation;
  GSource * source;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    return NULL;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    return NULL;

  napi_create_promise (env, &deferred, &promise);

  operation = g_slice_new0 (FdnCompilerBuildOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_utf8_from_value (env, args[0], &operation->entrypoint))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: entrypoint");
    goto invalid_argument;
  }

  if (argc > 1 && !fdn_is_undefined_or_null (env, args[1]))
  {
    if (!fdn_build_options_from_value (env, args[1], &operation->options))
      goto invalid_argument;
  }
  else
  {
    operation->options = NULL;
  }

  if (argc > 2 && !fdn_is_undefined_or_null (env, args[2]))
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

  

  operation->retval = frida_compiler_build_finish (operation->handle, res,
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
    napi_value js_retval;
    js_retval = fdn_utf8_to_value (env, operation->retval);
    napi_resolve_deferred (env, operation->deferred, js_retval);
  }

  fdn_compiler_build_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_compiler_build_tsfn);
}

static void
fdn_compiler_build_operation_free (FdnCompilerBuildOperation * operation)
{
  g_clear_pointer (&operation->entrypoint, g_free);
  g_clear_pointer (&operation->options, frida_unref);
  g_clear_pointer (&operation->cancellable, g_object_unref);
  g_clear_pointer (&operation->retval, g_free);
  g_slice_free (FdnCompilerBuildOperation, operation);
}

static napi_value
fdn_compiler_watch (napi_env env,
                    napi_callback_info info)
{
  size_t argc = 3;
  napi_value args[3];
  napi_value jsthis;
  FridaCompiler * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnCompilerWatchOperation * operation;
  GSource * source;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    return NULL;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    return NULL;

  napi_create_promise (env, &deferred, &promise);

  operation = g_slice_new0 (FdnCompilerWatchOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_utf8_from_value (env, args[0], &operation->entrypoint))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: entrypoint");
    goto invalid_argument;
  }

  if (argc > 1 && !fdn_is_undefined_or_null (env, args[1]))
  {
    if (!fdn_watch_options_from_value (env, args[1], &operation->options))
      goto invalid_argument;
  }
  else
  {
    operation->options = NULL;
  }

  if (argc > 2 && !fdn_is_undefined_or_null (env, args[2]))
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
    napi_value js_retval;
    napi_get_undefined (env, &js_retval);
    napi_resolve_deferred (env, operation->deferred, js_retval);
  }

  fdn_compiler_watch_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_compiler_watch_tsfn);
}

static void
fdn_compiler_watch_operation_free (FdnCompilerWatchOperation * operation)
{
  g_clear_pointer (&operation->entrypoint, g_free);
  g_clear_pointer (&operation->options, frida_unref);
  g_clear_pointer (&operation->cancellable, g_object_unref);
  g_slice_free (FdnCompilerWatchOperation, operation);
}

static napi_value
fdn_compiler_get_manager (napi_env env,
                          napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaCompiler * handle;
  FridaDeviceManager * retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_compiler_get_manager (handle);

  js_retval = fdn_device_manager_to_value (env, retval);

beach:
  return js_retval;
}

static napi_value
fdn_compiler_get_starting_signal (napi_env env,
                                  napi_callback_info info)
{
  return fdn_object_get_signal (env, info, "starting", "_starting");
}

static napi_value
fdn_compiler_get_finished_signal (napi_env env,
                                  napi_callback_info info)
{
  return fdn_object_get_signal (env, info, "finished", "_finished");
}

static napi_value
fdn_compiler_get_output_signal (napi_env env,
                                napi_callback_info info)
{
  return fdn_object_get_signal (env, info, "output", "_output");
}

static napi_value
fdn_compiler_get_diagnostics_signal (napi_env env,
                                     napi_callback_info info)
{
  return fdn_object_get_signal (env, info, "diagnostics", "_diagnostics");
}

static void
fdn_compiler_options_register (napi_env env,
                               napi_value exports)
{
  napi_property_descriptor properties[] =
  {
    { "projectRoot", NULL, NULL, fdn_compiler_options_get_project_root, fdn_compiler_options_set_project_root, NULL, napi_writable | napi_enumerable | napi_configurable, NULL },
    { "sourceMaps", NULL, NULL, fdn_compiler_options_get_source_maps, fdn_compiler_options_set_source_maps, NULL, napi_writable | napi_enumerable | napi_configurable, NULL },
    { "compression", NULL, NULL, fdn_compiler_options_get_compression, fdn_compiler_options_set_compression, NULL, napi_writable | napi_enumerable | napi_configurable, NULL },
  };

  napi_value constructor;
  napi_define_class (env, "CompilerOptions", NAPI_AUTO_LENGTH, fdn_compiler_options_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_compiler_options_constructor);

  napi_set_named_property (env, exports, "CompilerOptions", constructor);
}

static gboolean
fdn_compiler_options_from_value (napi_env env,
                                 napi_value value,
                                 FridaCompilerOptions ** handle)
{
  bool is_instance;

  if (napi_check_object_type_tag (env, value, &fdn_compiler_options_type_tag, &is_instance) != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of CompilerOptions");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) handle);

  g_object_ref (*handle);

  return TRUE;
}

static napi_value
fdn_compiler_options_to_value (napi_env env,
                               FridaCompilerOptions * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_compiler_options_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);
  napi_type_tag_object (env, handle_wrapper, &fdn_handle_wrapper_type_tag);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_compiler_options_construct (napi_env env,
                                napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaCompilerOptions * handle = NULL;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto propagate_error;

  if (argc == 0)
  {
    handle = frida_compiler_options_new ();
  }
  else
  {
    bool is_instance;

    if (napi_check_object_type_tag (env, args[0], &fdn_handle_wrapper_type_tag, &is_instance) != napi_ok || !is_instance)
      goto invalid_handle;

    if (napi_get_value_external (env, args[0], (void **) &handle) != napi_ok)
      goto propagate_error;

    g_object_ref (handle);
  }

  if (napi_type_tag_object (env, jsthis, &fdn_compiler_options_type_tag) != napi_ok)
    goto propagate_error;

  if (napi_wrap (env, jsthis, handle, NULL, NULL, NULL) != napi_ok)
    goto propagate_error;

  if (napi_add_finalizer (env, jsthis, handle, fdn_object_finalize, NULL, NULL) != napi_ok)
    goto propagate_error;

  return jsthis;

invalid_handle:
  {
    napi_throw_type_error (env, NULL, "expected a CompilerOptions handle");
    goto propagate_error;
  }
propagate_error:
  {
    g_clear_object (&handle);
    return NULL;
  }
}

static napi_value
fdn_compiler_options_get_project_root (napi_env env,
                                       napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaCompilerOptions * handle;
  const gchar * retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_compiler_options_get_project_root (handle);

  if (retval != NULL)
    js_retval = fdn_utf8_to_value (env, retval);
  else
    napi_get_null (env, &js_retval);

beach:
  return js_retval;
}

static napi_value
fdn_compiler_options_set_project_root (napi_env env,
                                       napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaCompilerOptions * handle;
  gchar * value = NULL;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_utf8_from_value (env, args[0], &value))
      goto beach;
  }
  else
  {
    value = NULL;
  }

  frida_compiler_options_set_project_root (handle, value);

  napi_get_undefined (env, &js_retval);

beach:
  g_clear_pointer (&value, g_free);
  return js_retval;
}

static napi_value
fdn_compiler_options_get_source_maps (napi_env env,
                                      napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaCompilerOptions * handle;
  FridaSourceMaps retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_compiler_options_get_source_maps (handle);

  js_retval = fdn_source_maps_to_value (env, retval);

beach:
  return js_retval;
}

static napi_value
fdn_compiler_options_set_source_maps (napi_env env,
                                      napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaCompilerOptions * handle;
  FridaSourceMaps value;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_source_maps_from_value (env, args[0], &value))
      goto beach;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: value");
    goto beach;
  }

  frida_compiler_options_set_source_maps (handle, value);

  napi_get_undefined (env, &js_retval);

beach:
  return js_retval;
}

static napi_value
fdn_compiler_options_get_compression (napi_env env,
                                      napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaCompilerOptions * handle;
  FridaJsCompression retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_compiler_options_get_compression (handle);

  js_retval = fdn_js_compression_to_value (env, retval);

beach:
  return js_retval;
}

static napi_value
fdn_compiler_options_set_compression (napi_env env,
                                      napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaCompilerOptions * handle;
  FridaJsCompression value;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_js_compression_from_value (env, args[0], &value))
      goto beach;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: value");
    goto beach;
  }

  frida_compiler_options_set_compression (handle, value);

  napi_get_undefined (env, &js_retval);

beach:
  return js_retval;
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
                              FridaBuildOptions ** handle)
{
  bool is_instance;

  if (napi_check_object_type_tag (env, value, &fdn_build_options_type_tag, &is_instance) != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of BuildOptions");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) handle);

  g_object_ref (*handle);

  return TRUE;
}

static napi_value
fdn_build_options_to_value (napi_env env,
                            FridaBuildOptions * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_build_options_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);
  napi_type_tag_object (env, handle_wrapper, &fdn_handle_wrapper_type_tag);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_build_options_construct (napi_env env,
                             napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaBuildOptions * handle = NULL;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto propagate_error;

  if (argc == 0)
  {
    handle = frida_build_options_new ();
  }
  else
  {
    bool is_instance;

    if (napi_check_object_type_tag (env, args[0], &fdn_handle_wrapper_type_tag, &is_instance) != napi_ok || !is_instance)
      goto invalid_handle;

    if (napi_get_value_external (env, args[0], (void **) &handle) != napi_ok)
      goto propagate_error;

    g_object_ref (handle);
  }

  if (napi_type_tag_object (env, jsthis, &fdn_build_options_type_tag) != napi_ok)
    goto propagate_error;

  if (napi_wrap (env, jsthis, handle, NULL, NULL, NULL) != napi_ok)
    goto propagate_error;

  if (napi_add_finalizer (env, jsthis, handle, fdn_object_finalize, NULL, NULL) != napi_ok)
    goto propagate_error;

  return jsthis;

invalid_handle:
  {
    napi_throw_type_error (env, NULL, "expected a BuildOptions handle");
    goto propagate_error;
  }
propagate_error:
  {
    g_clear_object (&handle);
    return NULL;
  }
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
                              FridaWatchOptions ** handle)
{
  bool is_instance;

  if (napi_check_object_type_tag (env, value, &fdn_watch_options_type_tag, &is_instance) != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of WatchOptions");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) handle);

  g_object_ref (*handle);

  return TRUE;
}

static napi_value
fdn_watch_options_to_value (napi_env env,
                            FridaWatchOptions * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_watch_options_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);
  napi_type_tag_object (env, handle_wrapper, &fdn_handle_wrapper_type_tag);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_watch_options_construct (napi_env env,
                             napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaWatchOptions * handle = NULL;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto propagate_error;

  if (argc == 0)
  {
    handle = frida_watch_options_new ();
  }
  else
  {
    bool is_instance;

    if (napi_check_object_type_tag (env, args[0], &fdn_handle_wrapper_type_tag, &is_instance) != napi_ok || !is_instance)
      goto invalid_handle;

    if (napi_get_value_external (env, args[0], (void **) &handle) != napi_ok)
      goto propagate_error;

    g_object_ref (handle);
  }

  if (napi_type_tag_object (env, jsthis, &fdn_watch_options_type_tag) != napi_ok)
    goto propagate_error;

  if (napi_wrap (env, jsthis, handle, NULL, NULL, NULL) != napi_ok)
    goto propagate_error;

  if (napi_add_finalizer (env, jsthis, handle, fdn_object_finalize, NULL, NULL) != napi_ok)
    goto propagate_error;

  return jsthis;

invalid_handle:
  {
    napi_throw_type_error (env, NULL, "expected a WatchOptions handle");
    goto propagate_error;
  }
propagate_error:
  {
    g_clear_object (&handle);
    return NULL;
  }
}

static void
fdn_static_authentication_service_register (napi_env env,
                                            napi_value exports)
{
  napi_property_descriptor properties[] =
  {
    { "tokenHash", NULL, NULL, fdn_static_authentication_service_get_token_hash, NULL, NULL, napi_enumerable | napi_configurable, NULL },
  };

  napi_value constructor;
  napi_define_class (env, "StaticAuthenticationService", NAPI_AUTO_LENGTH, fdn_static_authentication_service_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_static_authentication_service_constructor);

  napi_set_named_property (env, exports, "StaticAuthenticationService", constructor);
}

static gboolean
fdn_static_authentication_service_from_value (napi_env env,
                                              napi_value value,
                                              FridaStaticAuthenticationService ** handle)
{
  bool is_instance;

  if (napi_check_object_type_tag (env, value, &fdn_static_authentication_service_type_tag, &is_instance) != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of StaticAuthenticationService");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) handle);

  g_object_ref (*handle);

  return TRUE;
}

static napi_value
fdn_static_authentication_service_to_value (napi_env env,
                                            FridaStaticAuthenticationService * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_static_authentication_service_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);
  napi_type_tag_object (env, handle_wrapper, &fdn_handle_wrapper_type_tag);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_static_authentication_service_construct (napi_env env,
                                             napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaStaticAuthenticationService * handle = NULL;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto propagate_error;

  if (argc == 0)
  {
    napi_throw_error (env, NULL, "type StaticAuthenticationService cannot be constructed because it lacks a default constructor");
    return NULL;
  }
  else
  {
    bool is_instance;

    if (napi_check_object_type_tag (env, args[0], &fdn_handle_wrapper_type_tag, &is_instance) != napi_ok || !is_instance)
      goto invalid_handle;

    if (napi_get_value_external (env, args[0], (void **) &handle) != napi_ok)
      goto propagate_error;

    g_object_ref (handle);
  }

  if (napi_type_tag_object (env, jsthis, &fdn_static_authentication_service_type_tag) != napi_ok)
    goto propagate_error;

  if (napi_wrap (env, jsthis, handle, NULL, NULL, NULL) != napi_ok)
    goto propagate_error;

  if (napi_add_finalizer (env, jsthis, handle, fdn_object_finalize, NULL, NULL) != napi_ok)
    goto propagate_error;

  return jsthis;

invalid_handle:
  {
    napi_throw_type_error (env, NULL, "expected a StaticAuthenticationService handle");
    goto propagate_error;
  }
propagate_error:
  {
    g_clear_object (&handle);
    return NULL;
  }
}

static napi_value
fdn_static_authentication_service_get_token_hash (napi_env env,
                                                  napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaStaticAuthenticationService * handle;
  const gchar * retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_static_authentication_service_get_token_hash (handle);

  js_retval = fdn_utf8_to_value (env, retval);

beach:
  return js_retval;
}

static void
fdn_frontmost_query_options_register (napi_env env,
                                      napi_value exports)
{
  napi_property_descriptor properties[] =
  {
    { "scope", NULL, NULL, fdn_frontmost_query_options_get_scope, fdn_frontmost_query_options_set_scope, NULL, napi_writable | napi_enumerable | napi_configurable, NULL },
  };

  napi_value constructor;
  napi_define_class (env, "FrontmostQueryOptions", NAPI_AUTO_LENGTH, fdn_frontmost_query_options_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_frontmost_query_options_constructor);

  napi_set_named_property (env, exports, "FrontmostQueryOptions", constructor);
}

static gboolean
fdn_frontmost_query_options_from_value (napi_env env,
                                        napi_value value,
                                        FridaFrontmostQueryOptions ** handle)
{
  bool is_instance;

  if (napi_check_object_type_tag (env, value, &fdn_frontmost_query_options_type_tag, &is_instance) != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of FrontmostQueryOptions");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) handle);

  g_object_ref (*handle);

  return TRUE;
}

static napi_value
fdn_frontmost_query_options_to_value (napi_env env,
                                      FridaFrontmostQueryOptions * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_frontmost_query_options_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);
  napi_type_tag_object (env, handle_wrapper, &fdn_handle_wrapper_type_tag);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_frontmost_query_options_construct (napi_env env,
                                       napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaFrontmostQueryOptions * handle = NULL;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto propagate_error;

  if (argc == 0)
  {
    handle = frida_frontmost_query_options_new ();
  }
  else
  {
    bool is_instance;

    if (napi_check_object_type_tag (env, args[0], &fdn_handle_wrapper_type_tag, &is_instance) != napi_ok || !is_instance)
      goto invalid_handle;

    if (napi_get_value_external (env, args[0], (void **) &handle) != napi_ok)
      goto propagate_error;

    g_object_ref (handle);
  }

  if (napi_type_tag_object (env, jsthis, &fdn_frontmost_query_options_type_tag) != napi_ok)
    goto propagate_error;

  if (napi_wrap (env, jsthis, handle, NULL, NULL, NULL) != napi_ok)
    goto propagate_error;

  if (napi_add_finalizer (env, jsthis, handle, fdn_object_finalize, NULL, NULL) != napi_ok)
    goto propagate_error;

  return jsthis;

invalid_handle:
  {
    napi_throw_type_error (env, NULL, "expected a FrontmostQueryOptions handle");
    goto propagate_error;
  }
propagate_error:
  {
    g_clear_object (&handle);
    return NULL;
  }
}

static napi_value
fdn_frontmost_query_options_get_scope (napi_env env,
                                       napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaFrontmostQueryOptions * handle;
  FridaScope retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_frontmost_query_options_get_scope (handle);

  js_retval = fdn_scope_to_value (env, retval);

beach:
  return js_retval;
}

static napi_value
fdn_frontmost_query_options_set_scope (napi_env env,
                                       napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaFrontmostQueryOptions * handle;
  FridaScope value;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_scope_from_value (env, args[0], &value))
      goto beach;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: value");
    goto beach;
  }

  frida_frontmost_query_options_set_scope (handle, value);

  napi_get_undefined (env, &js_retval);

beach:
  return js_retval;
}

static void
fdn_application_query_options_register (napi_env env,
                                        napi_value exports)
{
  napi_property_descriptor properties[] =
  {
    { "selectIdentifier", NULL, fdn_application_query_options_select_identifier, NULL, NULL, NULL, napi_default, NULL },
    { "hasSelectedIdentifiers", NULL, fdn_application_query_options_has_selected_identifiers, NULL, NULL, NULL, napi_default, NULL },
    { "scope", NULL, NULL, fdn_application_query_options_get_scope, fdn_application_query_options_set_scope, NULL, napi_writable | napi_enumerable | napi_configurable, NULL },
  };

  napi_value constructor;
  napi_define_class (env, "ApplicationQueryOptions", NAPI_AUTO_LENGTH, fdn_application_query_options_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_application_query_options_constructor);

  napi_set_named_property (env, exports, "ApplicationQueryOptions", constructor);
}

static gboolean
fdn_application_query_options_from_value (napi_env env,
                                          napi_value value,
                                          FridaApplicationQueryOptions ** handle)
{
  bool is_instance;

  if (napi_check_object_type_tag (env, value, &fdn_application_query_options_type_tag, &is_instance) != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of ApplicationQueryOptions");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) handle);

  g_object_ref (*handle);

  return TRUE;
}

static napi_value
fdn_application_query_options_to_value (napi_env env,
                                        FridaApplicationQueryOptions * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_application_query_options_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);
  napi_type_tag_object (env, handle_wrapper, &fdn_handle_wrapper_type_tag);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_application_query_options_construct (napi_env env,
                                         napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaApplicationQueryOptions * handle = NULL;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto propagate_error;

  if (argc == 0)
  {
    handle = frida_application_query_options_new ();
  }
  else
  {
    bool is_instance;

    if (napi_check_object_type_tag (env, args[0], &fdn_handle_wrapper_type_tag, &is_instance) != napi_ok || !is_instance)
      goto invalid_handle;

    if (napi_get_value_external (env, args[0], (void **) &handle) != napi_ok)
      goto propagate_error;

    g_object_ref (handle);
  }

  if (napi_type_tag_object (env, jsthis, &fdn_application_query_options_type_tag) != napi_ok)
    goto propagate_error;

  if (napi_wrap (env, jsthis, handle, NULL, NULL, NULL) != napi_ok)
    goto propagate_error;

  if (napi_add_finalizer (env, jsthis, handle, fdn_object_finalize, NULL, NULL) != napi_ok)
    goto propagate_error;

  return jsthis;

invalid_handle:
  {
    napi_throw_type_error (env, NULL, "expected a ApplicationQueryOptions handle");
    goto propagate_error;
  }
propagate_error:
  {
    g_clear_object (&handle);
    return NULL;
  }
}

static napi_value
fdn_application_query_options_select_identifier (napi_env env,
                                                 napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaApplicationQueryOptions * handle;
  gchar * identifier = NULL;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_utf8_from_value (env, args[0], &identifier))
      goto beach;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: identifier");
    goto beach;
  }

  frida_application_query_options_select_identifier (handle, identifier);

  napi_get_undefined (env, &js_retval);

beach:
  g_clear_pointer (&identifier, g_free);
  return js_retval;
}

static napi_value
fdn_application_query_options_has_selected_identifiers (napi_env env,
                                                        napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaApplicationQueryOptions * handle;
  gboolean retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_application_query_options_has_selected_identifiers (handle);

  js_retval = fdn_boolean_to_value (env, retval);

beach:
  return js_retval;
}

static napi_value
fdn_application_query_options_get_scope (napi_env env,
                                         napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaApplicationQueryOptions * handle;
  FridaScope retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_application_query_options_get_scope (handle);

  js_retval = fdn_scope_to_value (env, retval);

beach:
  return js_retval;
}

static napi_value
fdn_application_query_options_set_scope (napi_env env,
                                         napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaApplicationQueryOptions * handle;
  FridaScope value;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_scope_from_value (env, args[0], &value))
      goto beach;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: value");
    goto beach;
  }

  frida_application_query_options_set_scope (handle, value);

  napi_get_undefined (env, &js_retval);

beach:
  return js_retval;
}

static void
fdn_process_query_options_register (napi_env env,
                                    napi_value exports)
{
  napi_property_descriptor properties[] =
  {
    { "selectPid", NULL, fdn_process_query_options_select_pid, NULL, NULL, NULL, napi_default, NULL },
    { "hasSelectedPids", NULL, fdn_process_query_options_has_selected_pids, NULL, NULL, NULL, napi_default, NULL },
    { "scope", NULL, NULL, fdn_process_query_options_get_scope, fdn_process_query_options_set_scope, NULL, napi_writable | napi_enumerable | napi_configurable, NULL },
  };

  napi_value constructor;
  napi_define_class (env, "ProcessQueryOptions", NAPI_AUTO_LENGTH, fdn_process_query_options_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_process_query_options_constructor);

  napi_set_named_property (env, exports, "ProcessQueryOptions", constructor);
}

static gboolean
fdn_process_query_options_from_value (napi_env env,
                                      napi_value value,
                                      FridaProcessQueryOptions ** handle)
{
  bool is_instance;

  if (napi_check_object_type_tag (env, value, &fdn_process_query_options_type_tag, &is_instance) != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of ProcessQueryOptions");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) handle);

  g_object_ref (*handle);

  return TRUE;
}

static napi_value
fdn_process_query_options_to_value (napi_env env,
                                    FridaProcessQueryOptions * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_process_query_options_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);
  napi_type_tag_object (env, handle_wrapper, &fdn_handle_wrapper_type_tag);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_process_query_options_construct (napi_env env,
                                     napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaProcessQueryOptions * handle = NULL;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto propagate_error;

  if (argc == 0)
  {
    handle = frida_process_query_options_new ();
  }
  else
  {
    bool is_instance;

    if (napi_check_object_type_tag (env, args[0], &fdn_handle_wrapper_type_tag, &is_instance) != napi_ok || !is_instance)
      goto invalid_handle;

    if (napi_get_value_external (env, args[0], (void **) &handle) != napi_ok)
      goto propagate_error;

    g_object_ref (handle);
  }

  if (napi_type_tag_object (env, jsthis, &fdn_process_query_options_type_tag) != napi_ok)
    goto propagate_error;

  if (napi_wrap (env, jsthis, handle, NULL, NULL, NULL) != napi_ok)
    goto propagate_error;

  if (napi_add_finalizer (env, jsthis, handle, fdn_object_finalize, NULL, NULL) != napi_ok)
    goto propagate_error;

  return jsthis;

invalid_handle:
  {
    napi_throw_type_error (env, NULL, "expected a ProcessQueryOptions handle");
    goto propagate_error;
  }
propagate_error:
  {
    g_clear_object (&handle);
    return NULL;
  }
}

static napi_value
fdn_process_query_options_select_pid (napi_env env,
                                      napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaProcessQueryOptions * handle;
  guint pid;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_uint_from_value (env, args[0], &pid))
      goto beach;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: pid");
    goto beach;
  }

  frida_process_query_options_select_pid (handle, pid);

  napi_get_undefined (env, &js_retval);

beach:
  return js_retval;
}

static napi_value
fdn_process_query_options_has_selected_pids (napi_env env,
                                             napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaProcessQueryOptions * handle;
  gboolean retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_process_query_options_has_selected_pids (handle);

  js_retval = fdn_boolean_to_value (env, retval);

beach:
  return js_retval;
}

static napi_value
fdn_process_query_options_get_scope (napi_env env,
                                     napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaProcessQueryOptions * handle;
  FridaScope retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_process_query_options_get_scope (handle);

  js_retval = fdn_scope_to_value (env, retval);

beach:
  return js_retval;
}

static napi_value
fdn_process_query_options_set_scope (napi_env env,
                                     napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaProcessQueryOptions * handle;
  FridaScope value;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_scope_from_value (env, args[0], &value))
      goto beach;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: value");
    goto beach;
  }

  frida_process_query_options_set_scope (handle, value);

  napi_get_undefined (env, &js_retval);

beach:
  return js_retval;
}

static void
fdn_session_options_register (napi_env env,
                              napi_value exports)
{
  napi_property_descriptor properties[] =
  {
    { "realm", NULL, NULL, fdn_session_options_get_realm, fdn_session_options_set_realm, NULL, napi_writable | napi_enumerable | napi_configurable, NULL },
    { "persistTimeout", NULL, NULL, fdn_session_options_get_persist_timeout, fdn_session_options_set_persist_timeout, NULL, napi_writable | napi_enumerable | napi_configurable, NULL },
    { "emulatedAgentPath", NULL, NULL, fdn_session_options_get_emulated_agent_path, fdn_session_options_set_emulated_agent_path, NULL, napi_writable | napi_enumerable | napi_configurable, NULL },
  };

  napi_value constructor;
  napi_define_class (env, "SessionOptions", NAPI_AUTO_LENGTH, fdn_session_options_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_session_options_constructor);

  napi_set_named_property (env, exports, "SessionOptions", constructor);
}

static gboolean
fdn_session_options_from_value (napi_env env,
                                napi_value value,
                                FridaSessionOptions ** handle)
{
  bool is_instance;

  if (napi_check_object_type_tag (env, value, &fdn_session_options_type_tag, &is_instance) != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of SessionOptions");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) handle);

  g_object_ref (*handle);

  return TRUE;
}

static napi_value
fdn_session_options_to_value (napi_env env,
                              FridaSessionOptions * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_session_options_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);
  napi_type_tag_object (env, handle_wrapper, &fdn_handle_wrapper_type_tag);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_session_options_construct (napi_env env,
                               napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaSessionOptions * handle = NULL;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto propagate_error;

  if (argc == 0)
  {
    handle = frida_session_options_new ();
  }
  else
  {
    bool is_instance;

    if (napi_check_object_type_tag (env, args[0], &fdn_handle_wrapper_type_tag, &is_instance) != napi_ok || !is_instance)
      goto invalid_handle;

    if (napi_get_value_external (env, args[0], (void **) &handle) != napi_ok)
      goto propagate_error;

    g_object_ref (handle);
  }

  if (napi_type_tag_object (env, jsthis, &fdn_session_options_type_tag) != napi_ok)
    goto propagate_error;

  if (napi_wrap (env, jsthis, handle, NULL, NULL, NULL) != napi_ok)
    goto propagate_error;

  if (napi_add_finalizer (env, jsthis, handle, fdn_object_finalize, NULL, NULL) != napi_ok)
    goto propagate_error;

  return jsthis;

invalid_handle:
  {
    napi_throw_type_error (env, NULL, "expected a SessionOptions handle");
    goto propagate_error;
  }
propagate_error:
  {
    g_clear_object (&handle);
    return NULL;
  }
}

static napi_value
fdn_session_options_get_realm (napi_env env,
                               napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaSessionOptions * handle;
  FridaRealm retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_session_options_get_realm (handle);

  js_retval = fdn_realm_to_value (env, retval);

beach:
  return js_retval;
}

static napi_value
fdn_session_options_set_realm (napi_env env,
                               napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaSessionOptions * handle;
  FridaRealm value;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_realm_from_value (env, args[0], &value))
      goto beach;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: value");
    goto beach;
  }

  frida_session_options_set_realm (handle, value);

  napi_get_undefined (env, &js_retval);

beach:
  return js_retval;
}

static napi_value
fdn_session_options_get_persist_timeout (napi_env env,
                                         napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaSessionOptions * handle;
  guint retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_session_options_get_persist_timeout (handle);

  js_retval = fdn_uint_to_value (env, retval);

beach:
  return js_retval;
}

static napi_value
fdn_session_options_set_persist_timeout (napi_env env,
                                         napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaSessionOptions * handle;
  guint value;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_uint_from_value (env, args[0], &value))
      goto beach;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: value");
    goto beach;
  }

  frida_session_options_set_persist_timeout (handle, value);

  napi_get_undefined (env, &js_retval);

beach:
  return js_retval;
}

static napi_value
fdn_session_options_get_emulated_agent_path (napi_env env,
                                             napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaSessionOptions * handle;
  const gchar * retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_session_options_get_emulated_agent_path (handle);

  if (retval != NULL)
    js_retval = fdn_utf8_to_value (env, retval);
  else
    napi_get_null (env, &js_retval);

beach:
  return js_retval;
}

static napi_value
fdn_session_options_set_emulated_agent_path (napi_env env,
                                             napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaSessionOptions * handle;
  gchar * value = NULL;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_utf8_from_value (env, args[0], &value))
      goto beach;
  }
  else
  {
    value = NULL;
  }

  frida_session_options_set_emulated_agent_path (handle, value);

  napi_get_undefined (env, &js_retval);

beach:
  g_clear_pointer (&value, g_free);
  return js_retval;
}

static void
fdn_script_options_register (napi_env env,
                             napi_value exports)
{
  napi_property_descriptor properties[] =
  {
    { "name", NULL, NULL, fdn_script_options_get_name, fdn_script_options_set_name, NULL, napi_writable | napi_enumerable | napi_configurable, NULL },
    { "snapshot", NULL, NULL, fdn_script_options_get_snapshot, fdn_script_options_set_snapshot, NULL, napi_writable | napi_enumerable | napi_configurable, NULL },
    { "snapshotTransport", NULL, NULL, fdn_script_options_get_snapshot_transport, fdn_script_options_set_snapshot_transport, NULL, napi_writable | napi_enumerable | napi_configurable, NULL },
    { "runtime", NULL, NULL, fdn_script_options_get_runtime, fdn_script_options_set_runtime, NULL, napi_writable | napi_enumerable | napi_configurable, NULL },
  };

  napi_value constructor;
  napi_define_class (env, "ScriptOptions", NAPI_AUTO_LENGTH, fdn_script_options_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_script_options_constructor);

  napi_set_named_property (env, exports, "ScriptOptions", constructor);
}

static gboolean
fdn_script_options_from_value (napi_env env,
                               napi_value value,
                               FridaScriptOptions ** handle)
{
  bool is_instance;

  if (napi_check_object_type_tag (env, value, &fdn_script_options_type_tag, &is_instance) != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of ScriptOptions");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) handle);

  g_object_ref (*handle);

  return TRUE;
}

static napi_value
fdn_script_options_to_value (napi_env env,
                             FridaScriptOptions * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_script_options_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);
  napi_type_tag_object (env, handle_wrapper, &fdn_handle_wrapper_type_tag);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_script_options_construct (napi_env env,
                              napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaScriptOptions * handle = NULL;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto propagate_error;

  if (argc == 0)
  {
    handle = frida_script_options_new ();
  }
  else
  {
    bool is_instance;

    if (napi_check_object_type_tag (env, args[0], &fdn_handle_wrapper_type_tag, &is_instance) != napi_ok || !is_instance)
      goto invalid_handle;

    if (napi_get_value_external (env, args[0], (void **) &handle) != napi_ok)
      goto propagate_error;

    g_object_ref (handle);
  }

  if (napi_type_tag_object (env, jsthis, &fdn_script_options_type_tag) != napi_ok)
    goto propagate_error;

  if (napi_wrap (env, jsthis, handle, NULL, NULL, NULL) != napi_ok)
    goto propagate_error;

  if (napi_add_finalizer (env, jsthis, handle, fdn_object_finalize, NULL, NULL) != napi_ok)
    goto propagate_error;

  return jsthis;

invalid_handle:
  {
    napi_throw_type_error (env, NULL, "expected a ScriptOptions handle");
    goto propagate_error;
  }
propagate_error:
  {
    g_clear_object (&handle);
    return NULL;
  }
}

static napi_value
fdn_script_options_get_name (napi_env env,
                             napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaScriptOptions * handle;
  const gchar * retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_script_options_get_name (handle);

  if (retval != NULL)
    js_retval = fdn_utf8_to_value (env, retval);
  else
    napi_get_null (env, &js_retval);

beach:
  return js_retval;
}

static napi_value
fdn_script_options_set_name (napi_env env,
                             napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaScriptOptions * handle;
  gchar * value = NULL;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_utf8_from_value (env, args[0], &value))
      goto beach;
  }
  else
  {
    value = NULL;
  }

  frida_script_options_set_name (handle, value);

  napi_get_undefined (env, &js_retval);

beach:
  g_clear_pointer (&value, g_free);
  return js_retval;
}

static napi_value
fdn_script_options_get_snapshot (napi_env env,
                                 napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaScriptOptions * handle;
  GBytes * retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_script_options_get_snapshot (handle);

  if (retval != NULL)
    js_retval = fdn_bytes_to_value (env, retval);
  else
    napi_get_null (env, &js_retval);

beach:
  return js_retval;
}

static napi_value
fdn_script_options_set_snapshot (napi_env env,
                                 napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaScriptOptions * handle;
  GBytes * value = NULL;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_bytes_from_value (env, args[0], &value))
      goto beach;
  }
  else
  {
    value = NULL;
  }

  frida_script_options_set_snapshot (handle, value);

  napi_get_undefined (env, &js_retval);

beach:
  g_clear_pointer (&value, g_bytes_unref);
  return js_retval;
}

static napi_value
fdn_script_options_get_snapshot_transport (napi_env env,
                                           napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaScriptOptions * handle;
  FridaSnapshotTransport retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_script_options_get_snapshot_transport (handle);

  js_retval = fdn_snapshot_transport_to_value (env, retval);

beach:
  return js_retval;
}

static napi_value
fdn_script_options_set_snapshot_transport (napi_env env,
                                           napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaScriptOptions * handle;
  FridaSnapshotTransport value;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_snapshot_transport_from_value (env, args[0], &value))
      goto beach;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: value");
    goto beach;
  }

  frida_script_options_set_snapshot_transport (handle, value);

  napi_get_undefined (env, &js_retval);

beach:
  return js_retval;
}

static napi_value
fdn_script_options_get_runtime (napi_env env,
                                napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaScriptOptions * handle;
  FridaScriptRuntime retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_script_options_get_runtime (handle);

  js_retval = fdn_script_runtime_to_value (env, retval);

beach:
  return js_retval;
}

static napi_value
fdn_script_options_set_runtime (napi_env env,
                                napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaScriptOptions * handle;
  FridaScriptRuntime value;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_script_runtime_from_value (env, args[0], &value))
      goto beach;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: value");
    goto beach;
  }

  frida_script_options_set_runtime (handle, value);

  napi_get_undefined (env, &js_retval);

beach:
  return js_retval;
}

static void
fdn_snapshot_options_register (napi_env env,
                               napi_value exports)
{
  napi_property_descriptor properties[] =
  {
    { "warmupScript", NULL, NULL, fdn_snapshot_options_get_warmup_script, fdn_snapshot_options_set_warmup_script, NULL, napi_writable | napi_enumerable | napi_configurable, NULL },
    { "runtime", NULL, NULL, fdn_snapshot_options_get_runtime, fdn_snapshot_options_set_runtime, NULL, napi_writable | napi_enumerable | napi_configurable, NULL },
  };

  napi_value constructor;
  napi_define_class (env, "SnapshotOptions", NAPI_AUTO_LENGTH, fdn_snapshot_options_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_snapshot_options_constructor);

  napi_set_named_property (env, exports, "SnapshotOptions", constructor);
}

static gboolean
fdn_snapshot_options_from_value (napi_env env,
                                 napi_value value,
                                 FridaSnapshotOptions ** handle)
{
  bool is_instance;

  if (napi_check_object_type_tag (env, value, &fdn_snapshot_options_type_tag, &is_instance) != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of SnapshotOptions");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) handle);

  g_object_ref (*handle);

  return TRUE;
}

static napi_value
fdn_snapshot_options_to_value (napi_env env,
                               FridaSnapshotOptions * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_snapshot_options_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);
  napi_type_tag_object (env, handle_wrapper, &fdn_handle_wrapper_type_tag);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_snapshot_options_construct (napi_env env,
                                napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaSnapshotOptions * handle = NULL;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto propagate_error;

  if (argc == 0)
  {
    handle = frida_snapshot_options_new ();
  }
  else
  {
    bool is_instance;

    if (napi_check_object_type_tag (env, args[0], &fdn_handle_wrapper_type_tag, &is_instance) != napi_ok || !is_instance)
      goto invalid_handle;

    if (napi_get_value_external (env, args[0], (void **) &handle) != napi_ok)
      goto propagate_error;

    g_object_ref (handle);
  }

  if (napi_type_tag_object (env, jsthis, &fdn_snapshot_options_type_tag) != napi_ok)
    goto propagate_error;

  if (napi_wrap (env, jsthis, handle, NULL, NULL, NULL) != napi_ok)
    goto propagate_error;

  if (napi_add_finalizer (env, jsthis, handle, fdn_object_finalize, NULL, NULL) != napi_ok)
    goto propagate_error;

  return jsthis;

invalid_handle:
  {
    napi_throw_type_error (env, NULL, "expected a SnapshotOptions handle");
    goto propagate_error;
  }
propagate_error:
  {
    g_clear_object (&handle);
    return NULL;
  }
}

static napi_value
fdn_snapshot_options_get_warmup_script (napi_env env,
                                        napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaSnapshotOptions * handle;
  const gchar * retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_snapshot_options_get_warmup_script (handle);

  if (retval != NULL)
    js_retval = fdn_utf8_to_value (env, retval);
  else
    napi_get_null (env, &js_retval);

beach:
  return js_retval;
}

static napi_value
fdn_snapshot_options_set_warmup_script (napi_env env,
                                        napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaSnapshotOptions * handle;
  gchar * value = NULL;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_utf8_from_value (env, args[0], &value))
      goto beach;
  }
  else
  {
    value = NULL;
  }

  frida_snapshot_options_set_warmup_script (handle, value);

  napi_get_undefined (env, &js_retval);

beach:
  g_clear_pointer (&value, g_free);
  return js_retval;
}

static napi_value
fdn_snapshot_options_get_runtime (napi_env env,
                                  napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaSnapshotOptions * handle;
  FridaScriptRuntime retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_snapshot_options_get_runtime (handle);

  js_retval = fdn_script_runtime_to_value (env, retval);

beach:
  return js_retval;
}

static napi_value
fdn_snapshot_options_set_runtime (napi_env env,
                                  napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaSnapshotOptions * handle;
  FridaScriptRuntime value;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_script_runtime_from_value (env, args[0], &value))
      goto beach;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: value");
    goto beach;
  }

  frida_snapshot_options_set_runtime (handle, value);

  napi_get_undefined (env, &js_retval);

beach:
  return js_retval;
}

static void
fdn_portal_options_register (napi_env env,
                             napi_value exports)
{
  napi_property_descriptor properties[] =
  {
    { "certificate", NULL, NULL, fdn_portal_options_get_certificate, fdn_portal_options_set_certificate, NULL, napi_writable | napi_enumerable | napi_configurable, NULL },
    { "token", NULL, NULL, fdn_portal_options_get_token, fdn_portal_options_set_token, NULL, napi_writable | napi_enumerable | napi_configurable, NULL },
    { "acl", NULL, NULL, fdn_portal_options_get_acl, fdn_portal_options_set_acl, NULL, napi_writable | napi_enumerable | napi_configurable, NULL },
  };

  napi_value constructor;
  napi_define_class (env, "PortalOptions", NAPI_AUTO_LENGTH, fdn_portal_options_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_portal_options_constructor);

  napi_set_named_property (env, exports, "PortalOptions", constructor);
}

static gboolean
fdn_portal_options_from_value (napi_env env,
                               napi_value value,
                               FridaPortalOptions ** handle)
{
  bool is_instance;

  if (napi_check_object_type_tag (env, value, &fdn_portal_options_type_tag, &is_instance) != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of PortalOptions");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) handle);

  g_object_ref (*handle);

  return TRUE;
}

static napi_value
fdn_portal_options_to_value (napi_env env,
                             FridaPortalOptions * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_portal_options_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);
  napi_type_tag_object (env, handle_wrapper, &fdn_handle_wrapper_type_tag);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_portal_options_construct (napi_env env,
                              napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaPortalOptions * handle = NULL;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto propagate_error;

  if (argc == 0)
  {
    handle = frida_portal_options_new ();
  }
  else
  {
    bool is_instance;

    if (napi_check_object_type_tag (env, args[0], &fdn_handle_wrapper_type_tag, &is_instance) != napi_ok || !is_instance)
      goto invalid_handle;

    if (napi_get_value_external (env, args[0], (void **) &handle) != napi_ok)
      goto propagate_error;

    g_object_ref (handle);
  }

  if (napi_type_tag_object (env, jsthis, &fdn_portal_options_type_tag) != napi_ok)
    goto propagate_error;

  if (napi_wrap (env, jsthis, handle, NULL, NULL, NULL) != napi_ok)
    goto propagate_error;

  if (napi_add_finalizer (env, jsthis, handle, fdn_object_finalize, NULL, NULL) != napi_ok)
    goto propagate_error;

  return jsthis;

invalid_handle:
  {
    napi_throw_type_error (env, NULL, "expected a PortalOptions handle");
    goto propagate_error;
  }
propagate_error:
  {
    g_clear_object (&handle);
    return NULL;
  }
}

static napi_value
fdn_portal_options_get_certificate (napi_env env,
                                    napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaPortalOptions * handle;
  GTlsCertificate * retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_portal_options_get_certificate (handle);

  if (retval != NULL)
    js_retval = fdn_tls_certificate_to_value (env, retval);
  else
    napi_get_null (env, &js_retval);

beach:
  return js_retval;
}

static napi_value
fdn_portal_options_set_certificate (napi_env env,
                                    napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaPortalOptions * handle;
  GTlsCertificate * value = NULL;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_tls_certificate_from_value (env, args[0], &value))
      goto beach;
  }
  else
  {
    value = NULL;
  }

  frida_portal_options_set_certificate (handle, value);

  napi_get_undefined (env, &js_retval);

beach:
  g_clear_pointer (&value, g_object_unref);
  return js_retval;
}

static napi_value
fdn_portal_options_get_token (napi_env env,
                              napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaPortalOptions * handle;
  const gchar * retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_portal_options_get_token (handle);

  if (retval != NULL)
    js_retval = fdn_utf8_to_value (env, retval);
  else
    napi_get_null (env, &js_retval);

beach:
  return js_retval;
}

static napi_value
fdn_portal_options_set_token (napi_env env,
                              napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaPortalOptions * handle;
  gchar * value = NULL;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_utf8_from_value (env, args[0], &value))
      goto beach;
  }
  else
  {
    value = NULL;
  }

  frida_portal_options_set_token (handle, value);

  napi_get_undefined (env, &js_retval);

beach:
  g_clear_pointer (&value, g_free);
  return js_retval;
}

static napi_value
fdn_portal_options_get_acl (napi_env env,
                            napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaPortalOptions * handle;
  gint * result_length1 = NULL;
  gchar ** retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_portal_options_get_acl (handle, result_length1);

  if (retval != NULL)
    js_retval = fdn_strv_to_value (env, retval);
  else
    napi_get_null (env, &js_retval);

beach:
  return js_retval;
}

static napi_value
fdn_portal_options_set_acl (napi_env env,
                            napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 2;
  napi_value args[2];
  napi_value jsthis;
  FridaPortalOptions * handle;
  gchar ** value = NULL;
  gint value_length1;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_strv_from_value (env, args[0], &value))
      goto beach;
  }
  else
  {
    value = NULL;
  }
  if (argc > 1 && !fdn_is_undefined_or_null (env, args[1]))
  {
    if (!fdn_int_from_value (env, args[1], &value_length1))
      goto beach;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: valueLength1");
    goto beach;
  }

  frida_portal_options_set_acl (handle, value, value_length1);

  napi_get_undefined (env, &js_retval);

beach:
  g_clear_pointer (&value, g_strfreev);
  return js_retval;
}

static void
fdn_peer_options_register (napi_env env,
                           napi_value exports)
{
  napi_property_descriptor properties[] =
  {
    { "clearRelays", NULL, fdn_peer_options_clear_relays, NULL, NULL, NULL, napi_default, NULL },
    { "addRelay", NULL, fdn_peer_options_add_relay, NULL, NULL, NULL, napi_default, NULL },
    { "stunServer", NULL, NULL, fdn_peer_options_get_stun_server, fdn_peer_options_set_stun_server, NULL, napi_writable | napi_enumerable | napi_configurable, NULL },
  };

  napi_value constructor;
  napi_define_class (env, "PeerOptions", NAPI_AUTO_LENGTH, fdn_peer_options_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_peer_options_constructor);

  napi_set_named_property (env, exports, "PeerOptions", constructor);
}

static gboolean
fdn_peer_options_from_value (napi_env env,
                             napi_value value,
                             FridaPeerOptions ** handle)
{
  bool is_instance;

  if (napi_check_object_type_tag (env, value, &fdn_peer_options_type_tag, &is_instance) != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of PeerOptions");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) handle);

  g_object_ref (*handle);

  return TRUE;
}

static napi_value
fdn_peer_options_to_value (napi_env env,
                           FridaPeerOptions * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_peer_options_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);
  napi_type_tag_object (env, handle_wrapper, &fdn_handle_wrapper_type_tag);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_peer_options_construct (napi_env env,
                            napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaPeerOptions * handle = NULL;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto propagate_error;

  if (argc == 0)
  {
    handle = frida_peer_options_new ();
  }
  else
  {
    bool is_instance;

    if (napi_check_object_type_tag (env, args[0], &fdn_handle_wrapper_type_tag, &is_instance) != napi_ok || !is_instance)
      goto invalid_handle;

    if (napi_get_value_external (env, args[0], (void **) &handle) != napi_ok)
      goto propagate_error;

    g_object_ref (handle);
  }

  if (napi_type_tag_object (env, jsthis, &fdn_peer_options_type_tag) != napi_ok)
    goto propagate_error;

  if (napi_wrap (env, jsthis, handle, NULL, NULL, NULL) != napi_ok)
    goto propagate_error;

  if (napi_add_finalizer (env, jsthis, handle, fdn_object_finalize, NULL, NULL) != napi_ok)
    goto propagate_error;

  return jsthis;

invalid_handle:
  {
    napi_throw_type_error (env, NULL, "expected a PeerOptions handle");
    goto propagate_error;
  }
propagate_error:
  {
    g_clear_object (&handle);
    return NULL;
  }
}

static napi_value
fdn_peer_options_clear_relays (napi_env env,
                               napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaPeerOptions * handle;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  frida_peer_options_clear_relays (handle);

  napi_get_undefined (env, &js_retval);

beach:
  return js_retval;
}

static napi_value
fdn_peer_options_add_relay (napi_env env,
                            napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaPeerOptions * handle;
  FridaRelay * relay = NULL;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_relay_from_value (env, args[0], &relay))
      goto beach;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: relay");
    goto beach;
  }

  frida_peer_options_add_relay (handle, relay);

  napi_get_undefined (env, &js_retval);

beach:
  g_clear_pointer (&relay, frida_unref);
  return js_retval;
}

static napi_value
fdn_peer_options_get_stun_server (napi_env env,
                                  napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaPeerOptions * handle;
  const gchar * retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_peer_options_get_stun_server (handle);

  if (retval != NULL)
    js_retval = fdn_utf8_to_value (env, retval);
  else
    napi_get_null (env, &js_retval);

beach:
  return js_retval;
}

static napi_value
fdn_peer_options_set_stun_server (napi_env env,
                                  napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaPeerOptions * handle;
  gchar * value = NULL;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_utf8_from_value (env, args[0], &value))
      goto beach;
  }
  else
  {
    value = NULL;
  }

  frida_peer_options_set_stun_server (handle, value);

  napi_get_undefined (env, &js_retval);

beach:
  g_clear_pointer (&value, g_free);
  return js_retval;
}

static void
fdn_relay_register (napi_env env,
                    napi_value exports)
{
  napi_property_descriptor properties[] =
  {
    { "address", NULL, NULL, fdn_relay_get_address, NULL, NULL, napi_enumerable | napi_configurable, NULL },
    { "username", NULL, NULL, fdn_relay_get_username, NULL, NULL, napi_enumerable | napi_configurable, NULL },
    { "password", NULL, NULL, fdn_relay_get_password, NULL, NULL, napi_enumerable | napi_configurable, NULL },
    { "kind", NULL, NULL, fdn_relay_get_kind, NULL, NULL, napi_enumerable | napi_configurable, NULL },
  };

  napi_value constructor;
  napi_define_class (env, "Relay", NAPI_AUTO_LENGTH, fdn_relay_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_relay_constructor);

  napi_set_named_property (env, exports, "Relay", constructor);
}

static gboolean
fdn_relay_from_value (napi_env env,
                      napi_value value,
                      FridaRelay ** handle)
{
  bool is_instance;

  if (napi_check_object_type_tag (env, value, &fdn_relay_type_tag, &is_instance) != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of Relay");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) handle);

  g_object_ref (*handle);

  return TRUE;
}

static napi_value
fdn_relay_to_value (napi_env env,
                    FridaRelay * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_relay_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);
  napi_type_tag_object (env, handle_wrapper, &fdn_handle_wrapper_type_tag);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_relay_construct (napi_env env,
                     napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaRelay * handle = NULL;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto propagate_error;

  if (argc == 0)
  {
    napi_throw_error (env, NULL, "type Relay cannot be constructed because it lacks a default constructor");
    return NULL;
  }
  else
  {
    bool is_instance;

    if (napi_check_object_type_tag (env, args[0], &fdn_handle_wrapper_type_tag, &is_instance) != napi_ok || !is_instance)
      goto invalid_handle;

    if (napi_get_value_external (env, args[0], (void **) &handle) != napi_ok)
      goto propagate_error;

    g_object_ref (handle);
  }

  if (napi_type_tag_object (env, jsthis, &fdn_relay_type_tag) != napi_ok)
    goto propagate_error;

  if (napi_wrap (env, jsthis, handle, NULL, NULL, NULL) != napi_ok)
    goto propagate_error;

  if (napi_add_finalizer (env, jsthis, handle, fdn_object_finalize, NULL, NULL) != napi_ok)
    goto propagate_error;

  return jsthis;

invalid_handle:
  {
    napi_throw_type_error (env, NULL, "expected a Relay handle");
    goto propagate_error;
  }
propagate_error:
  {
    g_clear_object (&handle);
    return NULL;
  }
}

static napi_value
fdn_relay_get_address (napi_env env,
                       napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaRelay * handle;
  const gchar * retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_relay_get_address (handle);

  js_retval = fdn_utf8_to_value (env, retval);

beach:
  return js_retval;
}

static napi_value
fdn_relay_get_username (napi_env env,
                        napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaRelay * handle;
  const gchar * retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_relay_get_username (handle);

  js_retval = fdn_utf8_to_value (env, retval);

beach:
  return js_retval;
}

static napi_value
fdn_relay_get_password (napi_env env,
                        napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaRelay * handle;
  const gchar * retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_relay_get_password (handle);

  js_retval = fdn_utf8_to_value (env, retval);

beach:
  return js_retval;
}

static napi_value
fdn_relay_get_kind (napi_env env,
                    napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaRelay * handle;
  FridaRelayKind retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_relay_get_kind (handle);

  js_retval = fdn_relay_kind_to_value (env, retval);

beach:
  return js_retval;
}

static void
fdn_endpoint_parameters_register (napi_env env,
                                  napi_value exports)
{
  napi_property_descriptor properties[] =
  {
    { "address", NULL, NULL, fdn_endpoint_parameters_get_address, NULL, NULL, napi_enumerable | napi_configurable, NULL },
    { "port", NULL, NULL, fdn_endpoint_parameters_get_port, NULL, NULL, napi_enumerable | napi_configurable, NULL },
    { "certificate", NULL, NULL, fdn_endpoint_parameters_get_certificate, NULL, NULL, napi_enumerable | napi_configurable, NULL },
    { "origin", NULL, NULL, fdn_endpoint_parameters_get_origin, NULL, NULL, napi_enumerable | napi_configurable, NULL },
    { "authService", NULL, NULL, fdn_endpoint_parameters_get_auth_service, NULL, NULL, napi_enumerable | napi_configurable, NULL },
    { "assetRoot", NULL, NULL, fdn_endpoint_parameters_get_asset_root, fdn_endpoint_parameters_set_asset_root, NULL, napi_writable | napi_enumerable | napi_configurable, NULL },
  };

  napi_value constructor;
  napi_define_class (env, "EndpointParameters", NAPI_AUTO_LENGTH, fdn_endpoint_parameters_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_endpoint_parameters_constructor);

  napi_set_named_property (env, exports, "EndpointParameters", constructor);
}

static gboolean
fdn_endpoint_parameters_from_value (napi_env env,
                                    napi_value value,
                                    FridaEndpointParameters ** handle)
{
  bool is_instance;

  if (napi_check_object_type_tag (env, value, &fdn_endpoint_parameters_type_tag, &is_instance) != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of EndpointParameters");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) handle);

  g_object_ref (*handle);

  return TRUE;
}

static napi_value
fdn_endpoint_parameters_to_value (napi_env env,
                                  FridaEndpointParameters * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_endpoint_parameters_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);
  napi_type_tag_object (env, handle_wrapper, &fdn_handle_wrapper_type_tag);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_endpoint_parameters_construct (napi_env env,
                                   napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaEndpointParameters * handle = NULL;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto propagate_error;

  if (argc == 0)
  {
    napi_throw_error (env, NULL, "type EndpointParameters cannot be constructed because it lacks a default constructor");
    return NULL;
  }
  else
  {
    bool is_instance;

    if (napi_check_object_type_tag (env, args[0], &fdn_handle_wrapper_type_tag, &is_instance) != napi_ok || !is_instance)
      goto invalid_handle;

    if (napi_get_value_external (env, args[0], (void **) &handle) != napi_ok)
      goto propagate_error;

    g_object_ref (handle);
  }

  if (napi_type_tag_object (env, jsthis, &fdn_endpoint_parameters_type_tag) != napi_ok)
    goto propagate_error;

  if (napi_wrap (env, jsthis, handle, NULL, NULL, NULL) != napi_ok)
    goto propagate_error;

  if (napi_add_finalizer (env, jsthis, handle, fdn_object_finalize, NULL, NULL) != napi_ok)
    goto propagate_error;

  return jsthis;

invalid_handle:
  {
    napi_throw_type_error (env, NULL, "expected a EndpointParameters handle");
    goto propagate_error;
  }
propagate_error:
  {
    g_clear_object (&handle);
    return NULL;
  }
}

static napi_value
fdn_endpoint_parameters_get_address (napi_env env,
                                     napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaEndpointParameters * handle;
  const gchar * retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_endpoint_parameters_get_address (handle);

  if (retval != NULL)
    js_retval = fdn_utf8_to_value (env, retval);
  else
    napi_get_null (env, &js_retval);

beach:
  return js_retval;
}

static napi_value
fdn_endpoint_parameters_get_port (napi_env env,
                                  napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaEndpointParameters * handle;
  guint16 retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_endpoint_parameters_get_port (handle);

  js_retval = fdn_uint16_to_value (env, retval);

beach:
  return js_retval;
}

static napi_value
fdn_endpoint_parameters_get_certificate (napi_env env,
                                         napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaEndpointParameters * handle;
  GTlsCertificate * retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_endpoint_parameters_get_certificate (handle);

  if (retval != NULL)
    js_retval = fdn_tls_certificate_to_value (env, retval);
  else
    napi_get_null (env, &js_retval);

beach:
  return js_retval;
}

static napi_value
fdn_endpoint_parameters_get_origin (napi_env env,
                                    napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaEndpointParameters * handle;
  const gchar * retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_endpoint_parameters_get_origin (handle);

  if (retval != NULL)
    js_retval = fdn_utf8_to_value (env, retval);
  else
    napi_get_null (env, &js_retval);

beach:
  return js_retval;
}

static napi_value
fdn_endpoint_parameters_get_auth_service (napi_env env,
                                          napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaEndpointParameters * handle;
  FridaAuthenticationService * retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_endpoint_parameters_get_auth_service (handle);

  if (retval != NULL)
    js_retval = fdn_authentication_service_to_value (env, retval);
  else
    napi_get_null (env, &js_retval);

beach:
  return js_retval;
}

static napi_value
fdn_endpoint_parameters_get_asset_root (napi_env env,
                                        napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaEndpointParameters * handle;
  GFile * retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_endpoint_parameters_get_asset_root (handle);

  if (retval != NULL)
    js_retval = fdn_file_to_value (env, retval);
  else
    napi_get_null (env, &js_retval);

beach:
  return js_retval;
}

static napi_value
fdn_endpoint_parameters_set_asset_root (napi_env env,
                                        napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaEndpointParameters * handle;
  GFile * value = NULL;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_file_from_value (env, args[0], &value))
      goto beach;
  }
  else
  {
    value = NULL;
  }

  frida_endpoint_parameters_set_asset_root (handle, value);

  napi_get_undefined (env, &js_retval);

beach:
  g_clear_pointer (&value, g_object_unref);
  return js_retval;
}

static void
fdn_service_register (napi_env env,
                      napi_value exports)
{
  napi_property_descriptor properties[] =
  {
    { "isClosed", NULL, fdn_service_is_closed, NULL, NULL, NULL, napi_default, NULL },
    { "activate", NULL, fdn_service_activate, NULL, NULL, NULL, napi_default, NULL },
    { "cancel", NULL, fdn_service_cancel, NULL, NULL, NULL, napi_default, NULL },
    { "request", NULL, fdn_service_request, NULL, NULL, NULL, napi_default, NULL },
    { "close", NULL, NULL, fdn_service_get_close_signal, NULL, NULL, napi_default, NULL },
    { "message", NULL, NULL, fdn_service_get_message_signal, NULL, NULL, napi_default, NULL },
  };

  napi_value constructor;
  napi_define_class (env, "Service", NAPI_AUTO_LENGTH, fdn_service_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_service_constructor);

  napi_set_named_property (env, exports, "Service", constructor);

  napi_value resource_name;

  napi_create_string_utf8 (env, "activate", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_service_activate_deliver, &fdn_service_activate_tsfn);
  napi_unref_threadsafe_function (env, fdn_service_activate_tsfn);

  napi_create_string_utf8 (env, "cancel", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_service_cancel_deliver, &fdn_service_cancel_tsfn);
  napi_unref_threadsafe_function (env, fdn_service_cancel_tsfn);

  napi_create_string_utf8 (env, "request", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_service_request_deliver, &fdn_service_request_tsfn);
  napi_unref_threadsafe_function (env, fdn_service_request_tsfn);
}

static gboolean
fdn_service_from_value (napi_env env,
                        napi_value value,
                        FridaService ** handle)
{
  bool is_instance;

  if (napi_check_object_type_tag (env, value, &fdn_service_type_tag, &is_instance) != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of Service");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) handle);

  g_object_ref (*handle);

  return TRUE;
}

static napi_value
fdn_service_to_value (napi_env env,
                      FridaService * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_service_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);
  napi_type_tag_object (env, handle_wrapper, &fdn_handle_wrapper_type_tag);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_service_construct (napi_env env,
                       napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaService * handle = NULL;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto propagate_error;

  if (argc == 0)
  {
    napi_throw_error (env, NULL, "type Service cannot be constructed because it lacks a default constructor");
    return NULL;
  }
  else
  {
    bool is_instance;

    if (napi_check_object_type_tag (env, args[0], &fdn_handle_wrapper_type_tag, &is_instance) != napi_ok || !is_instance)
      goto invalid_handle;

    if (napi_get_value_external (env, args[0], (void **) &handle) != napi_ok)
      goto propagate_error;

    g_object_ref (handle);
  }

  if (napi_type_tag_object (env, jsthis, &fdn_service_type_tag) != napi_ok)
    goto propagate_error;

  if (napi_wrap (env, jsthis, handle, NULL, NULL, NULL) != napi_ok)
    goto propagate_error;

  if (napi_add_finalizer (env, jsthis, handle, fdn_object_finalize, NULL, NULL) != napi_ok)
    goto propagate_error;

  return jsthis;

invalid_handle:
  {
    napi_throw_type_error (env, NULL, "expected a Service handle");
    goto propagate_error;
  }
propagate_error:
  {
    g_clear_object (&handle);
    return NULL;
  }
}

static napi_value
fdn_service_is_closed (napi_env env,
                       napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  FridaService * handle;
  gboolean retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = frida_service_is_closed (handle);

  js_retval = fdn_boolean_to_value (env, retval);

beach:
  return js_retval;
}

static napi_value
fdn_service_activate (napi_env env,
                      napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaService * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnServiceActivateOperation * operation;
  GSource * source;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    return NULL;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    return NULL;

  napi_create_promise (env, &deferred, &promise);

  operation = g_slice_new0 (FdnServiceActivateOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_cancellable_from_value (env, args[0], &operation->cancellable))
      goto invalid_argument;
  }
  else
  {
    operation->cancellable = NULL;
  }

  source = g_idle_source_new ();
  g_source_set_callback (source, fdn_service_activate_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, fdn_service_activate_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    fdn_service_activate_operation_free (operation);
    return NULL;
  }
}

static gboolean
fdn_service_activate_begin (gpointer user_data)
{
  FdnServiceActivateOperation * operation = user_data;

  frida_service_activate (operation->handle,
      operation->cancellable,
      fdn_service_activate_end, operation);

  return G_SOURCE_REMOVE;
}

static void
fdn_service_activate_end (GObject * source_object,
                          GAsyncResult * res,
                          gpointer user_data)
{
  FdnServiceActivateOperation * operation = user_data;

  frida_service_activate_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (fdn_service_activate_tsfn, operation, napi_tsfn_blocking);
}

static void
fdn_service_activate_deliver (napi_env env,
                              napi_value js_cb,
                              void * context,
                              void * data)
{
  FdnServiceActivateOperation * operation = data;

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
    napi_value js_retval;
    napi_get_undefined (env, &js_retval);
    napi_resolve_deferred (env, operation->deferred, js_retval);
  }

  fdn_service_activate_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_service_activate_tsfn);
}

static void
fdn_service_activate_operation_free (FdnServiceActivateOperation * operation)
{
  g_clear_pointer (&operation->cancellable, g_object_unref);
  g_slice_free (FdnServiceActivateOperation, operation);
}

static napi_value
fdn_service_cancel (napi_env env,
                    napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaService * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnServiceCancelOperation * operation;
  GSource * source;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    return NULL;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    return NULL;

  napi_create_promise (env, &deferred, &promise);

  operation = g_slice_new0 (FdnServiceCancelOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_cancellable_from_value (env, args[0], &operation->cancellable))
      goto invalid_argument;
  }
  else
  {
    operation->cancellable = NULL;
  }

  source = g_idle_source_new ();
  g_source_set_callback (source, fdn_service_cancel_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, fdn_service_cancel_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    fdn_service_cancel_operation_free (operation);
    return NULL;
  }
}

static gboolean
fdn_service_cancel_begin (gpointer user_data)
{
  FdnServiceCancelOperation * operation = user_data;

  frida_service_cancel (operation->handle,
      operation->cancellable,
      fdn_service_cancel_end, operation);

  return G_SOURCE_REMOVE;
}

static void
fdn_service_cancel_end (GObject * source_object,
                        GAsyncResult * res,
                        gpointer user_data)
{
  FdnServiceCancelOperation * operation = user_data;

  frida_service_cancel_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (fdn_service_cancel_tsfn, operation, napi_tsfn_blocking);
}

static void
fdn_service_cancel_deliver (napi_env env,
                            napi_value js_cb,
                            void * context,
                            void * data)
{
  FdnServiceCancelOperation * operation = data;

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
    napi_value js_retval;
    napi_get_undefined (env, &js_retval);
    napi_resolve_deferred (env, operation->deferred, js_retval);
  }

  fdn_service_cancel_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_service_cancel_tsfn);
}

static void
fdn_service_cancel_operation_free (FdnServiceCancelOperation * operation)
{
  g_clear_pointer (&operation->cancellable, g_object_unref);
  g_slice_free (FdnServiceCancelOperation, operation);
}

static napi_value
fdn_service_request (napi_env env,
                     napi_callback_info info)
{
  size_t argc = 2;
  napi_value args[2];
  napi_value jsthis;
  FridaService * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnServiceRequestOperation * operation;
  GSource * source;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    return NULL;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    return NULL;

  napi_create_promise (env, &deferred, &promise);

  operation = g_slice_new0 (FdnServiceRequestOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_variant_from_value (env, args[0], &operation->parameters))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: parameters");
    goto invalid_argument;
  }

  if (argc > 1 && !fdn_is_undefined_or_null (env, args[1]))
  {
    if (!fdn_cancellable_from_value (env, args[1], &operation->cancellable))
      goto invalid_argument;
  }
  else
  {
    operation->cancellable = NULL;
  }

  source = g_idle_source_new ();
  g_source_set_callback (source, fdn_service_request_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, fdn_service_request_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    fdn_service_request_operation_free (operation);
    return NULL;
  }
}

static gboolean
fdn_service_request_begin (gpointer user_data)
{
  FdnServiceRequestOperation * operation = user_data;

  frida_service_request (operation->handle,
      operation->parameters, operation->cancellable,
      fdn_service_request_end, operation);

  return G_SOURCE_REMOVE;
}

static void
fdn_service_request_end (GObject * source_object,
                         GAsyncResult * res,
                         gpointer user_data)
{
  FdnServiceRequestOperation * operation = user_data;

  

  operation->retval = frida_service_request_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (fdn_service_request_tsfn, operation, napi_tsfn_blocking);
}

static void
fdn_service_request_deliver (napi_env env,
                             napi_value js_cb,
                             void * context,
                             void * data)
{
  FdnServiceRequestOperation * operation = data;

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
    napi_value js_retval;
    js_retval = fdn_variant_to_value (env, operation->retval);
    napi_resolve_deferred (env, operation->deferred, js_retval);
  }

  fdn_service_request_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_service_request_tsfn);
}

static void
fdn_service_request_operation_free (FdnServiceRequestOperation * operation)
{
  g_clear_pointer (&operation->parameters, g_variant_unref);
  g_clear_pointer (&operation->cancellable, g_object_unref);
  g_clear_pointer (&operation->retval, g_variant_unref);
  g_slice_free (FdnServiceRequestOperation, operation);
}

static napi_value
fdn_service_get_close_signal (napi_env env,
                              napi_callback_info info)
{
  return fdn_object_get_signal (env, info, "close", "_close");
}

static napi_value
fdn_service_get_message_signal (napi_env env,
                                napi_callback_info info)
{
  return fdn_object_get_signal (env, info, "message", "_message");
}

static void
fdn_injector_register (napi_env env,
                       napi_value exports)
{
  napi_property_descriptor properties[] =
  {
    { "close", NULL, fdn_injector_close, NULL, NULL, NULL, napi_default, NULL },
    { "injectLibraryFile", NULL, fdn_injector_inject_library_file, NULL, NULL, NULL, napi_default, NULL },
    { "injectLibraryBlob", NULL, fdn_injector_inject_library_blob, NULL, NULL, NULL, napi_default, NULL },
    { "demonitor", NULL, fdn_injector_demonitor, NULL, NULL, NULL, napi_default, NULL },
    { "demonitorAndCloneState", NULL, fdn_injector_demonitor_and_clone_state, NULL, NULL, NULL, napi_default, NULL },
    { "recreateThread", NULL, fdn_injector_recreate_thread, NULL, NULL, NULL, napi_default, NULL },
    { "uninjected", NULL, NULL, fdn_injector_get_uninjected_signal, NULL, NULL, napi_default, NULL },
  };

  napi_value constructor;
  napi_define_class (env, "Injector", NAPI_AUTO_LENGTH, fdn_injector_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_injector_constructor);

  napi_set_named_property (env, exports, "Injector", constructor);

  napi_value resource_name;

  napi_create_string_utf8 (env, "close", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_injector_close_deliver, &fdn_injector_close_tsfn);
  napi_unref_threadsafe_function (env, fdn_injector_close_tsfn);

  napi_create_string_utf8 (env, "injectLibraryFile", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_injector_inject_library_file_deliver, &fdn_injector_inject_library_file_tsfn);
  napi_unref_threadsafe_function (env, fdn_injector_inject_library_file_tsfn);

  napi_create_string_utf8 (env, "injectLibraryBlob", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_injector_inject_library_blob_deliver, &fdn_injector_inject_library_blob_tsfn);
  napi_unref_threadsafe_function (env, fdn_injector_inject_library_blob_tsfn);

  napi_create_string_utf8 (env, "demonitor", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_injector_demonitor_deliver, &fdn_injector_demonitor_tsfn);
  napi_unref_threadsafe_function (env, fdn_injector_demonitor_tsfn);

  napi_create_string_utf8 (env, "demonitorAndCloneState", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_injector_demonitor_and_clone_state_deliver, &fdn_injector_demonitor_and_clone_state_tsfn);
  napi_unref_threadsafe_function (env, fdn_injector_demonitor_and_clone_state_tsfn);

  napi_create_string_utf8 (env, "recreateThread", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_injector_recreate_thread_deliver, &fdn_injector_recreate_thread_tsfn);
  napi_unref_threadsafe_function (env, fdn_injector_recreate_thread_tsfn);
}

static gboolean
fdn_injector_from_value (napi_env env,
                         napi_value value,
                         FridaInjector ** handle)
{
  bool is_instance;

  if (napi_check_object_type_tag (env, value, &fdn_injector_type_tag, &is_instance) != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of Injector");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) handle);

  g_object_ref (*handle);

  return TRUE;
}

static napi_value
fdn_injector_to_value (napi_env env,
                       FridaInjector * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_injector_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);
  napi_type_tag_object (env, handle_wrapper, &fdn_handle_wrapper_type_tag);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_injector_construct (napi_env env,
                        napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaInjector * handle = NULL;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto propagate_error;

  if (argc == 0)
  {
    napi_throw_error (env, NULL, "type Injector cannot be constructed because it lacks a default constructor");
    return NULL;
  }
  else
  {
    bool is_instance;

    if (napi_check_object_type_tag (env, args[0], &fdn_handle_wrapper_type_tag, &is_instance) != napi_ok || !is_instance)
      goto invalid_handle;

    if (napi_get_value_external (env, args[0], (void **) &handle) != napi_ok)
      goto propagate_error;

    g_object_ref (handle);
  }

  if (napi_type_tag_object (env, jsthis, &fdn_injector_type_tag) != napi_ok)
    goto propagate_error;

  if (napi_wrap (env, jsthis, handle, NULL, NULL, NULL) != napi_ok)
    goto propagate_error;

  if (napi_add_finalizer (env, jsthis, handle, fdn_object_finalize, NULL, NULL) != napi_ok)
    goto propagate_error;

  return jsthis;

invalid_handle:
  {
    napi_throw_type_error (env, NULL, "expected a Injector handle");
    goto propagate_error;
  }
propagate_error:
  {
    g_clear_object (&handle);
    return NULL;
  }
}

static napi_value
fdn_injector_close (napi_env env,
                    napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaInjector * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnInjectorCloseOperation * operation;
  GSource * source;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    return NULL;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    return NULL;

  napi_create_promise (env, &deferred, &promise);

  operation = g_slice_new0 (FdnInjectorCloseOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_cancellable_from_value (env, args[0], &operation->cancellable))
      goto invalid_argument;
  }
  else
  {
    operation->cancellable = NULL;
  }

  source = g_idle_source_new ();
  g_source_set_callback (source, fdn_injector_close_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, fdn_injector_close_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    fdn_injector_close_operation_free (operation);
    return NULL;
  }
}

static gboolean
fdn_injector_close_begin (gpointer user_data)
{
  FdnInjectorCloseOperation * operation = user_data;

  frida_injector_close (operation->handle,
      operation->cancellable,
      fdn_injector_close_end, operation);

  return G_SOURCE_REMOVE;
}

static void
fdn_injector_close_end (GObject * source_object,
                        GAsyncResult * res,
                        gpointer user_data)
{
  FdnInjectorCloseOperation * operation = user_data;

  frida_injector_close_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (fdn_injector_close_tsfn, operation, napi_tsfn_blocking);
}

static void
fdn_injector_close_deliver (napi_env env,
                            napi_value js_cb,
                            void * context,
                            void * data)
{
  FdnInjectorCloseOperation * operation = data;

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
    napi_value js_retval;
    napi_get_undefined (env, &js_retval);
    napi_resolve_deferred (env, operation->deferred, js_retval);
  }

  fdn_injector_close_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_injector_close_tsfn);
}

static void
fdn_injector_close_operation_free (FdnInjectorCloseOperation * operation)
{
  g_clear_pointer (&operation->cancellable, g_object_unref);
  g_slice_free (FdnInjectorCloseOperation, operation);
}

static napi_value
fdn_injector_inject_library_file (napi_env env,
                                  napi_callback_info info)
{
  size_t argc = 5;
  napi_value args[5];
  napi_value jsthis;
  FridaInjector * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnInjectorInjectLibraryFileOperation * operation;
  GSource * source;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    return NULL;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    return NULL;

  napi_create_promise (env, &deferred, &promise);

  operation = g_slice_new0 (FdnInjectorInjectLibraryFileOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_uint_from_value (env, args[0], &operation->pid))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: pid");
    goto invalid_argument;
  }

  if (argc > 1 && !fdn_is_undefined_or_null (env, args[1]))
  {
    if (!fdn_utf8_from_value (env, args[1], &operation->path))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: path");
    goto invalid_argument;
  }

  if (argc > 2 && !fdn_is_undefined_or_null (env, args[2]))
  {
    if (!fdn_utf8_from_value (env, args[2], &operation->entrypoint))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: entrypoint");
    goto invalid_argument;
  }

  if (argc > 3 && !fdn_is_undefined_or_null (env, args[3]))
  {
    if (!fdn_utf8_from_value (env, args[3], &operation->data))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: data");
    goto invalid_argument;
  }

  if (argc > 4 && !fdn_is_undefined_or_null (env, args[4]))
  {
    if (!fdn_cancellable_from_value (env, args[4], &operation->cancellable))
      goto invalid_argument;
  }
  else
  {
    operation->cancellable = NULL;
  }

  source = g_idle_source_new ();
  g_source_set_callback (source, fdn_injector_inject_library_file_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, fdn_injector_inject_library_file_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    fdn_injector_inject_library_file_operation_free (operation);
    return NULL;
  }
}

static gboolean
fdn_injector_inject_library_file_begin (gpointer user_data)
{
  FdnInjectorInjectLibraryFileOperation * operation = user_data;

  frida_injector_inject_library_file (operation->handle,
      operation->pid, operation->path, operation->entrypoint, operation->data, operation->cancellable,
      fdn_injector_inject_library_file_end, operation);

  return G_SOURCE_REMOVE;
}

static void
fdn_injector_inject_library_file_end (GObject * source_object,
                                      GAsyncResult * res,
                                      gpointer user_data)
{
  FdnInjectorInjectLibraryFileOperation * operation = user_data;

  

  operation->retval = frida_injector_inject_library_file_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (fdn_injector_inject_library_file_tsfn, operation, napi_tsfn_blocking);
}

static void
fdn_injector_inject_library_file_deliver (napi_env env,
                                          napi_value js_cb,
                                          void * context,
                                          void * data)
{
  FdnInjectorInjectLibraryFileOperation * operation = data;

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
    napi_value js_retval;
    js_retval = fdn_uint_to_value (env, operation->retval);
    napi_resolve_deferred (env, operation->deferred, js_retval);
  }

  fdn_injector_inject_library_file_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_injector_inject_library_file_tsfn);
}

static void
fdn_injector_inject_library_file_operation_free (FdnInjectorInjectLibraryFileOperation * operation)
{
  g_clear_pointer (&operation->path, g_free);
  g_clear_pointer (&operation->entrypoint, g_free);
  g_clear_pointer (&operation->data, g_free);
  g_clear_pointer (&operation->cancellable, g_object_unref);
  g_slice_free (FdnInjectorInjectLibraryFileOperation, operation);
}

static napi_value
fdn_injector_inject_library_blob (napi_env env,
                                  napi_callback_info info)
{
  size_t argc = 5;
  napi_value args[5];
  napi_value jsthis;
  FridaInjector * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnInjectorInjectLibraryBlobOperation * operation;
  GSource * source;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    return NULL;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    return NULL;

  napi_create_promise (env, &deferred, &promise);

  operation = g_slice_new0 (FdnInjectorInjectLibraryBlobOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_uint_from_value (env, args[0], &operation->pid))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: pid");
    goto invalid_argument;
  }

  if (argc > 1 && !fdn_is_undefined_or_null (env, args[1]))
  {
    if (!fdn_bytes_from_value (env, args[1], &operation->blob))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: blob");
    goto invalid_argument;
  }

  if (argc > 2 && !fdn_is_undefined_or_null (env, args[2]))
  {
    if (!fdn_utf8_from_value (env, args[2], &operation->entrypoint))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: entrypoint");
    goto invalid_argument;
  }

  if (argc > 3 && !fdn_is_undefined_or_null (env, args[3]))
  {
    if (!fdn_utf8_from_value (env, args[3], &operation->data))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: data");
    goto invalid_argument;
  }

  if (argc > 4 && !fdn_is_undefined_or_null (env, args[4]))
  {
    if (!fdn_cancellable_from_value (env, args[4], &operation->cancellable))
      goto invalid_argument;
  }
  else
  {
    operation->cancellable = NULL;
  }

  source = g_idle_source_new ();
  g_source_set_callback (source, fdn_injector_inject_library_blob_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, fdn_injector_inject_library_blob_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    fdn_injector_inject_library_blob_operation_free (operation);
    return NULL;
  }
}

static gboolean
fdn_injector_inject_library_blob_begin (gpointer user_data)
{
  FdnInjectorInjectLibraryBlobOperation * operation = user_data;

  frida_injector_inject_library_blob (operation->handle,
      operation->pid, operation->blob, operation->entrypoint, operation->data, operation->cancellable,
      fdn_injector_inject_library_blob_end, operation);

  return G_SOURCE_REMOVE;
}

static void
fdn_injector_inject_library_blob_end (GObject * source_object,
                                      GAsyncResult * res,
                                      gpointer user_data)
{
  FdnInjectorInjectLibraryBlobOperation * operation = user_data;

  

  operation->retval = frida_injector_inject_library_blob_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (fdn_injector_inject_library_blob_tsfn, operation, napi_tsfn_blocking);
}

static void
fdn_injector_inject_library_blob_deliver (napi_env env,
                                          napi_value js_cb,
                                          void * context,
                                          void * data)
{
  FdnInjectorInjectLibraryBlobOperation * operation = data;

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
    napi_value js_retval;
    js_retval = fdn_uint_to_value (env, operation->retval);
    napi_resolve_deferred (env, operation->deferred, js_retval);
  }

  fdn_injector_inject_library_blob_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_injector_inject_library_blob_tsfn);
}

static void
fdn_injector_inject_library_blob_operation_free (FdnInjectorInjectLibraryBlobOperation * operation)
{
  g_clear_pointer (&operation->blob, g_bytes_unref);
  g_clear_pointer (&operation->entrypoint, g_free);
  g_clear_pointer (&operation->data, g_free);
  g_clear_pointer (&operation->cancellable, g_object_unref);
  g_slice_free (FdnInjectorInjectLibraryBlobOperation, operation);
}

static napi_value
fdn_injector_demonitor (napi_env env,
                        napi_callback_info info)
{
  size_t argc = 2;
  napi_value args[2];
  napi_value jsthis;
  FridaInjector * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnInjectorDemonitorOperation * operation;
  GSource * source;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    return NULL;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    return NULL;

  napi_create_promise (env, &deferred, &promise);

  operation = g_slice_new0 (FdnInjectorDemonitorOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_uint_from_value (env, args[0], &operation->id))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: id");
    goto invalid_argument;
  }

  if (argc > 1 && !fdn_is_undefined_or_null (env, args[1]))
  {
    if (!fdn_cancellable_from_value (env, args[1], &operation->cancellable))
      goto invalid_argument;
  }
  else
  {
    operation->cancellable = NULL;
  }

  source = g_idle_source_new ();
  g_source_set_callback (source, fdn_injector_demonitor_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, fdn_injector_demonitor_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    fdn_injector_demonitor_operation_free (operation);
    return NULL;
  }
}

static gboolean
fdn_injector_demonitor_begin (gpointer user_data)
{
  FdnInjectorDemonitorOperation * operation = user_data;

  frida_injector_demonitor (operation->handle,
      operation->id, operation->cancellable,
      fdn_injector_demonitor_end, operation);

  return G_SOURCE_REMOVE;
}

static void
fdn_injector_demonitor_end (GObject * source_object,
                            GAsyncResult * res,
                            gpointer user_data)
{
  FdnInjectorDemonitorOperation * operation = user_data;

  frida_injector_demonitor_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (fdn_injector_demonitor_tsfn, operation, napi_tsfn_blocking);
}

static void
fdn_injector_demonitor_deliver (napi_env env,
                                napi_value js_cb,
                                void * context,
                                void * data)
{
  FdnInjectorDemonitorOperation * operation = data;

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
    napi_value js_retval;
    napi_get_undefined (env, &js_retval);
    napi_resolve_deferred (env, operation->deferred, js_retval);
  }

  fdn_injector_demonitor_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_injector_demonitor_tsfn);
}

static void
fdn_injector_demonitor_operation_free (FdnInjectorDemonitorOperation * operation)
{
  g_clear_pointer (&operation->cancellable, g_object_unref);
  g_slice_free (FdnInjectorDemonitorOperation, operation);
}

static napi_value
fdn_injector_demonitor_and_clone_state (napi_env env,
                                        napi_callback_info info)
{
  size_t argc = 2;
  napi_value args[2];
  napi_value jsthis;
  FridaInjector * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnInjectorDemonitorAndCloneStateOperation * operation;
  GSource * source;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    return NULL;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    return NULL;

  napi_create_promise (env, &deferred, &promise);

  operation = g_slice_new0 (FdnInjectorDemonitorAndCloneStateOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_uint_from_value (env, args[0], &operation->id))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: id");
    goto invalid_argument;
  }

  if (argc > 1 && !fdn_is_undefined_or_null (env, args[1]))
  {
    if (!fdn_cancellable_from_value (env, args[1], &operation->cancellable))
      goto invalid_argument;
  }
  else
  {
    operation->cancellable = NULL;
  }

  source = g_idle_source_new ();
  g_source_set_callback (source, fdn_injector_demonitor_and_clone_state_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, fdn_injector_demonitor_and_clone_state_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    fdn_injector_demonitor_and_clone_state_operation_free (operation);
    return NULL;
  }
}

static gboolean
fdn_injector_demonitor_and_clone_state_begin (gpointer user_data)
{
  FdnInjectorDemonitorAndCloneStateOperation * operation = user_data;

  frida_injector_demonitor_and_clone_state (operation->handle,
      operation->id, operation->cancellable,
      fdn_injector_demonitor_and_clone_state_end, operation);

  return G_SOURCE_REMOVE;
}

static void
fdn_injector_demonitor_and_clone_state_end (GObject * source_object,
                                            GAsyncResult * res,
                                            gpointer user_data)
{
  FdnInjectorDemonitorAndCloneStateOperation * operation = user_data;

  

  operation->retval = frida_injector_demonitor_and_clone_state_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (fdn_injector_demonitor_and_clone_state_tsfn, operation, napi_tsfn_blocking);
}

static void
fdn_injector_demonitor_and_clone_state_deliver (napi_env env,
                                                napi_value js_cb,
                                                void * context,
                                                void * data)
{
  FdnInjectorDemonitorAndCloneStateOperation * operation = data;

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
    napi_value js_retval;
    js_retval = fdn_uint_to_value (env, operation->retval);
    napi_resolve_deferred (env, operation->deferred, js_retval);
  }

  fdn_injector_demonitor_and_clone_state_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_injector_demonitor_and_clone_state_tsfn);
}

static void
fdn_injector_demonitor_and_clone_state_operation_free (FdnInjectorDemonitorAndCloneStateOperation * operation)
{
  g_clear_pointer (&operation->cancellable, g_object_unref);
  g_slice_free (FdnInjectorDemonitorAndCloneStateOperation, operation);
}

static napi_value
fdn_injector_recreate_thread (napi_env env,
                              napi_callback_info info)
{
  size_t argc = 3;
  napi_value args[3];
  napi_value jsthis;
  FridaInjector * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnInjectorRecreateThreadOperation * operation;
  GSource * source;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    return NULL;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    return NULL;

  napi_create_promise (env, &deferred, &promise);

  operation = g_slice_new0 (FdnInjectorRecreateThreadOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_uint_from_value (env, args[0], &operation->pid))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: pid");
    goto invalid_argument;
  }

  if (argc > 1 && !fdn_is_undefined_or_null (env, args[1]))
  {
    if (!fdn_uint_from_value (env, args[1], &operation->id))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: id");
    goto invalid_argument;
  }

  if (argc > 2 && !fdn_is_undefined_or_null (env, args[2]))
  {
    if (!fdn_cancellable_from_value (env, args[2], &operation->cancellable))
      goto invalid_argument;
  }
  else
  {
    operation->cancellable = NULL;
  }

  source = g_idle_source_new ();
  g_source_set_callback (source, fdn_injector_recreate_thread_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, fdn_injector_recreate_thread_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    fdn_injector_recreate_thread_operation_free (operation);
    return NULL;
  }
}

static gboolean
fdn_injector_recreate_thread_begin (gpointer user_data)
{
  FdnInjectorRecreateThreadOperation * operation = user_data;

  frida_injector_recreate_thread (operation->handle,
      operation->pid, operation->id, operation->cancellable,
      fdn_injector_recreate_thread_end, operation);

  return G_SOURCE_REMOVE;
}

static void
fdn_injector_recreate_thread_end (GObject * source_object,
                                  GAsyncResult * res,
                                  gpointer user_data)
{
  FdnInjectorRecreateThreadOperation * operation = user_data;

  frida_injector_recreate_thread_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (fdn_injector_recreate_thread_tsfn, operation, napi_tsfn_blocking);
}

static void
fdn_injector_recreate_thread_deliver (napi_env env,
                                      napi_value js_cb,
                                      void * context,
                                      void * data)
{
  FdnInjectorRecreateThreadOperation * operation = data;

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
    napi_value js_retval;
    napi_get_undefined (env, &js_retval);
    napi_resolve_deferred (env, operation->deferred, js_retval);
  }

  fdn_injector_recreate_thread_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_injector_recreate_thread_tsfn);
}

static void
fdn_injector_recreate_thread_operation_free (FdnInjectorRecreateThreadOperation * operation)
{
  g_clear_pointer (&operation->cancellable, g_object_unref);
  g_slice_free (FdnInjectorRecreateThreadOperation, operation);
}

static napi_value
fdn_injector_get_uninjected_signal (napi_env env,
                                    napi_callback_info info)
{
  return fdn_object_get_signal (env, info, "uninjected", "_uninjected");
}

static void
fdn_authentication_service_register (napi_env env,
                                     napi_value exports)
{
  napi_property_descriptor properties[] =
  {
    { "authenticate", NULL, fdn_authentication_service_authenticate, NULL, NULL, NULL, napi_default, NULL },
  };

  napi_value constructor;
  napi_define_class (env, "AuthenticationService", NAPI_AUTO_LENGTH, fdn_authentication_service_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_authentication_service_constructor);

  napi_set_named_property (env, exports, "AuthenticationService", constructor);

  napi_value resource_name;

  napi_create_string_utf8 (env, "authenticate", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, fdn_authentication_service_authenticate_deliver, &fdn_authentication_service_authenticate_tsfn);
  napi_unref_threadsafe_function (env, fdn_authentication_service_authenticate_tsfn);
}

static gboolean
fdn_authentication_service_from_value (napi_env env,
                                       napi_value value,
                                       FridaAuthenticationService ** handle)
{
  bool is_instance;

  if (napi_check_object_type_tag (env, value, &fdn_authentication_service_type_tag, &is_instance) != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of AuthenticationService");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) handle);

  g_object_ref (*handle);

  return TRUE;
}

static napi_value
fdn_authentication_service_to_value (napi_env env,
                                     FridaAuthenticationService * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_authentication_service_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);
  napi_type_tag_object (env, handle_wrapper, &fdn_handle_wrapper_type_tag);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_authentication_service_construct (napi_env env,
                                      napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  FridaAuthenticationService * handle = NULL;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto propagate_error;

  if (argc == 0)
  {
    napi_throw_error (env, NULL, "type AuthenticationService cannot be constructed because it lacks a default constructor");
    return NULL;
  }
  else
  {
    bool is_instance;

    if (napi_check_object_type_tag (env, args[0], &fdn_handle_wrapper_type_tag, &is_instance) != napi_ok || !is_instance)
      goto invalid_handle;

    if (napi_get_value_external (env, args[0], (void **) &handle) != napi_ok)
      goto propagate_error;

    g_object_ref (handle);
  }

  if (napi_type_tag_object (env, jsthis, &fdn_authentication_service_type_tag) != napi_ok)
    goto propagate_error;

  if (napi_wrap (env, jsthis, handle, NULL, NULL, NULL) != napi_ok)
    goto propagate_error;

  if (napi_add_finalizer (env, jsthis, handle, fdn_object_finalize, NULL, NULL) != napi_ok)
    goto propagate_error;

  return jsthis;

invalid_handle:
  {
    napi_throw_type_error (env, NULL, "expected a AuthenticationService handle");
    goto propagate_error;
  }
propagate_error:
  {
    g_clear_object (&handle);
    return NULL;
  }
}

static napi_value
fdn_authentication_service_authenticate (napi_env env,
                                         napi_callback_info info)
{
  size_t argc = 2;
  napi_value args[2];
  napi_value jsthis;
  FridaAuthenticationService * handle;
  napi_deferred deferred;
  napi_value promise;
  FdnAuthenticationServiceAuthenticateOperation * operation;
  GSource * source;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    return NULL;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    return NULL;

  napi_create_promise (env, &deferred, &promise);

  operation = g_slice_new0 (FdnAuthenticationServiceAuthenticateOperation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_utf8_from_value (env, args[0], &operation->token))
      goto invalid_argument;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: token");
    goto invalid_argument;
  }

  if (argc > 1 && !fdn_is_undefined_or_null (env, args[1]))
  {
    if (!fdn_cancellable_from_value (env, args[1], &operation->cancellable))
      goto invalid_argument;
  }
  else
  {
    operation->cancellable = NULL;
  }

  source = g_idle_source_new ();
  g_source_set_callback (source, fdn_authentication_service_authenticate_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, fdn_authentication_service_authenticate_tsfn);

  return promise;

invalid_argument:
  {
    napi_reject_deferred (env, deferred, NULL);
    fdn_authentication_service_authenticate_operation_free (operation);
    return NULL;
  }
}

static gboolean
fdn_authentication_service_authenticate_begin (gpointer user_data)
{
  FdnAuthenticationServiceAuthenticateOperation * operation = user_data;

  frida_authentication_service_authenticate (operation->handle,
      operation->token, operation->cancellable,
      fdn_authentication_service_authenticate_end, operation);

  return G_SOURCE_REMOVE;
}

static void
fdn_authentication_service_authenticate_end (GObject * source_object,
                                             GAsyncResult * res,
                                             gpointer user_data)
{
  FdnAuthenticationServiceAuthenticateOperation * operation = user_data;

  

  operation->retval = frida_authentication_service_authenticate_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function (fdn_authentication_service_authenticate_tsfn, operation, napi_tsfn_blocking);
}

static void
fdn_authentication_service_authenticate_deliver (napi_env env,
                                                 napi_value js_cb,
                                                 void * context,
                                                 void * data)
{
  FdnAuthenticationServiceAuthenticateOperation * operation = data;

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
    napi_value js_retval;
    js_retval = fdn_utf8_to_value (env, operation->retval);
    napi_resolve_deferred (env, operation->deferred, js_retval);
  }

  fdn_authentication_service_authenticate_operation_free (operation);

  napi_unref_threadsafe_function (env, fdn_authentication_service_authenticate_tsfn);
}

static void
fdn_authentication_service_authenticate_operation_free (FdnAuthenticationServiceAuthenticateOperation * operation)
{
  g_clear_pointer (&operation->token, g_free);
  g_clear_pointer (&operation->cancellable, g_object_unref);
  g_clear_pointer (&operation->retval, g_free);
  g_slice_free (FdnAuthenticationServiceAuthenticateOperation, operation);
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
    { "cancelled", NULL, NULL, fdn_cancellable_get_cancelled_signal, NULL, NULL, napi_default, NULL },
  };

  napi_value constructor;
  napi_define_class (env, "Cancellable", NAPI_AUTO_LENGTH, fdn_cancellable_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_cancellable_constructor);

  napi_set_named_property (env, exports, "Cancellable", constructor);
}

static gboolean
fdn_cancellable_from_value (napi_env env,
                            napi_value value,
                            GCancellable ** handle)
{
  bool is_instance;

  if (napi_check_object_type_tag (env, value, &fdn_cancellable_type_tag, &is_instance) != napi_ok || !is_instance)
  {
    napi_throw_type_error (env, NULL, "expected an instance of Cancellable");
    return FALSE;
  }

  napi_unwrap (env, value, (void **) handle);

  g_object_ref (*handle);

  return TRUE;
}

static napi_value
fdn_cancellable_to_value (napi_env env,
                          GCancellable * handle)
{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, fdn_cancellable_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);
  napi_type_tag_object (env, handle_wrapper, &fdn_handle_wrapper_type_tag);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}

static napi_value
fdn_cancellable_construct (napi_env env,
                           napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  GCancellable * handle = NULL;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto propagate_error;

  if (argc == 0)
  {
    handle = g_cancellable_new ();
  }
  else
  {
    bool is_instance;

    if (napi_check_object_type_tag (env, args[0], &fdn_handle_wrapper_type_tag, &is_instance) != napi_ok || !is_instance)
      goto invalid_handle;

    if (napi_get_value_external (env, args[0], (void **) &handle) != napi_ok)
      goto propagate_error;

    g_object_ref (handle);
  }

  if (napi_type_tag_object (env, jsthis, &fdn_cancellable_type_tag) != napi_ok)
    goto propagate_error;

  if (napi_wrap (env, jsthis, handle, NULL, NULL, NULL) != napi_ok)
    goto propagate_error;

  if (napi_add_finalizer (env, jsthis, handle, fdn_object_finalize, NULL, NULL) != napi_ok)
    goto propagate_error;

  return jsthis;

invalid_handle:
  {
    napi_throw_type_error (env, NULL, "expected a Cancellable handle");
    goto propagate_error;
  }
propagate_error:
  {
    g_clear_object (&handle);
    return NULL;
  }
}

static napi_value
fdn_cancellable_cancel (napi_env env,
                        napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  GCancellable * handle;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  g_cancellable_cancel (handle);

  napi_get_undefined (env, &js_retval);

beach:
  return js_retval;
}

static napi_value
fdn_cancellable_disconnect (napi_env env,
                            napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  GCancellable * handle;
  gulong handler_id;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  if (argc > 0 && !fdn_is_undefined_or_null (env, args[0]))
  {
    if (!fdn_ulong_from_value (env, args[0], &handler_id))
      goto beach;
  }
  else
  {
    napi_throw_type_error (env, NULL, "missing argument: handlerId");
    goto beach;
  }

  g_cancellable_disconnect (handle, handler_id);

  napi_get_undefined (env, &js_retval);

beach:
  return js_retval;
}

static napi_value
fdn_cancellable_get_fd (napi_env env,
                        napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  GCancellable * handle;
  int retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = g_cancellable_get_fd (handle);

  js_retval = fdn_int_to_value (env, retval);

beach:
  return js_retval;
}

static napi_value
fdn_cancellable_is_cancelled (napi_env env,
                              napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  GCancellable * handle;
  gboolean retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = g_cancellable_is_cancelled (handle);

  js_retval = fdn_boolean_to_value (env, retval);

beach:
  return js_retval;
}

static napi_value
fdn_cancellable_pop_current (napi_env env,
                             napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  GCancellable * handle;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  g_cancellable_pop_current (handle);

  napi_get_undefined (env, &js_retval);

beach:
  return js_retval;
}

static napi_value
fdn_cancellable_push_current (napi_env env,
                              napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  GCancellable * handle;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  g_cancellable_push_current (handle);

  napi_get_undefined (env, &js_retval);

beach:
  return js_retval;
}

static napi_value
fdn_cancellable_reset (napi_env env,
                       napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  GCancellable * handle;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  g_cancellable_reset (handle);

  napi_get_undefined (env, &js_retval);

beach:
  return js_retval;
}

static napi_value
fdn_cancellable_throw_if_cancelled (napi_env env,
                                    napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 0;
  napi_value args[0];
  napi_value jsthis;
  GCancellable * handle;
  GError * error = NULL;
  gboolean retval;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  retval = g_cancellable_set_error_if_cancelled (handle, &error);

  if (error != NULL)
  {
    napi_throw_error (env, NULL, error->message);
    g_error_free (error);
    return NULL;
  }

  js_retval = fdn_boolean_to_value (env, retval);

beach:
  return js_retval;
}

static napi_value
fdn_cancellable_get_cancelled_signal (napi_env env,
                                      napi_callback_info info)
{
  return fdn_object_get_signal (env, info, "cancelled", "_cancelled");
}

static gboolean
fdn_runtime_from_value (napi_env env,
                        napi_value value,
                        FridaRuntime * e)
{
  return fdn_enum_from_value (env, frida_runtime_get_type (), value, (gint *) e);
}

static napi_value
fdn_runtime_to_value (napi_env env,
                      FridaRuntime e)
{
  return fdn_enum_to_value (env, frida_runtime_get_type (), e);
}

static gboolean
fdn_device_type_from_value (napi_env env,
                            napi_value value,
                            FridaDeviceType * e)
{
  return fdn_enum_from_value (env, frida_device_type_get_type (), value, (gint *) e);
}

static napi_value
fdn_device_type_to_value (napi_env env,
                          FridaDeviceType e)
{
  return fdn_enum_to_value (env, frida_device_type_get_type (), e);
}

static gboolean
fdn_source_maps_from_value (napi_env env,
                            napi_value value,
                            FridaSourceMaps * e)
{
  return fdn_enum_from_value (env, frida_source_maps_get_type (), value, (gint *) e);
}

static napi_value
fdn_source_maps_to_value (napi_env env,
                          FridaSourceMaps e)
{
  return fdn_enum_to_value (env, frida_source_maps_get_type (), e);
}

static gboolean
fdn_js_compression_from_value (napi_env env,
                               napi_value value,
                               FridaJsCompression * e)
{
  return fdn_enum_from_value (env, frida_js_compression_get_type (), value, (gint *) e);
}

static napi_value
fdn_js_compression_to_value (napi_env env,
                             FridaJsCompression e)
{
  return fdn_enum_to_value (env, frida_js_compression_get_type (), e);
}

static gboolean
fdn_agent_message_kind_from_value (napi_env env,
                                   napi_value value,
                                   FridaAgentMessageKind * e)
{
  return fdn_enum_from_value (env, frida_agent_message_kind_get_type (), value, (gint *) e);
}

static napi_value
fdn_agent_message_kind_to_value (napi_env env,
                                 FridaAgentMessageKind e)
{
  return fdn_enum_to_value (env, frida_agent_message_kind_get_type (), e);
}

static gboolean
fdn_realm_from_value (napi_env env,
                      napi_value value,
                      FridaRealm * e)
{
  return fdn_enum_from_value (env, frida_realm_get_type (), value, (gint *) e);
}

static napi_value
fdn_realm_to_value (napi_env env,
                    FridaRealm e)
{
  return fdn_enum_to_value (env, frida_realm_get_type (), e);
}

static gboolean
fdn_unload_policy_from_value (napi_env env,
                              napi_value value,
                              FridaUnloadPolicy * e)
{
  return fdn_enum_from_value (env, frida_unload_policy_get_type (), value, (gint *) e);
}

static napi_value
fdn_unload_policy_to_value (napi_env env,
                            FridaUnloadPolicy e)
{
  return fdn_enum_to_value (env, frida_unload_policy_get_type (), e);
}

static gboolean
fdn_session_detach_reason_from_value (napi_env env,
                                      napi_value value,
                                      FridaSessionDetachReason * e)
{
  return fdn_enum_from_value (env, frida_session_detach_reason_get_type (), value, (gint *) e);
}

static napi_value
fdn_session_detach_reason_to_value (napi_env env,
                                    FridaSessionDetachReason e)
{
  return fdn_enum_to_value (env, frida_session_detach_reason_get_type (), e);
}

static gboolean
fdn_scope_from_value (napi_env env,
                      napi_value value,
                      FridaScope * e)
{
  return fdn_enum_from_value (env, frida_scope_get_type (), value, (gint *) e);
}

static napi_value
fdn_scope_to_value (napi_env env,
                    FridaScope e)
{
  return fdn_enum_to_value (env, frida_scope_get_type (), e);
}

static gboolean
fdn_stdio_from_value (napi_env env,
                      napi_value value,
                      FridaStdio * e)
{
  return fdn_enum_from_value (env, frida_stdio_get_type (), value, (gint *) e);
}

static napi_value
fdn_stdio_to_value (napi_env env,
                    FridaStdio e)
{
  return fdn_enum_to_value (env, frida_stdio_get_type (), e);
}

static gboolean
fdn_child_origin_from_value (napi_env env,
                             napi_value value,
                             FridaChildOrigin * e)
{
  return fdn_enum_from_value (env, frida_child_origin_get_type (), value, (gint *) e);
}

static napi_value
fdn_child_origin_to_value (napi_env env,
                           FridaChildOrigin e)
{
  return fdn_enum_to_value (env, frida_child_origin_get_type (), e);
}

static gboolean
fdn_snapshot_transport_from_value (napi_env env,
                                   napi_value value,
                                   FridaSnapshotTransport * e)
{
  return fdn_enum_from_value (env, frida_snapshot_transport_get_type (), value, (gint *) e);
}

static napi_value
fdn_snapshot_transport_to_value (napi_env env,
                                 FridaSnapshotTransport e)
{
  return fdn_enum_to_value (env, frida_snapshot_transport_get_type (), e);
}

static gboolean
fdn_script_runtime_from_value (napi_env env,
                               napi_value value,
                               FridaScriptRuntime * e)
{
  return fdn_enum_from_value (env, frida_script_runtime_get_type (), value, (gint *) e);
}

static napi_value
fdn_script_runtime_to_value (napi_env env,
                             FridaScriptRuntime e)
{
  return fdn_enum_to_value (env, frida_script_runtime_get_type (), e);
}

static gboolean
fdn_relay_kind_from_value (napi_env env,
                           napi_value value,
                           FridaRelayKind * e)
{
  return fdn_enum_from_value (env, frida_relay_kind_get_type (), value, (gint *) e);
}

static napi_value
fdn_relay_kind_to_value (napi_env env,
                         FridaRelayKind e)
{
  return fdn_enum_to_value (env, frida_relay_kind_get_type (), e);
}

static gboolean
fdn_peer_setup_from_value (napi_env env,
                           napi_value value,
                           FridaPeerSetup * e)
{
  return fdn_enum_from_value (env, frida_peer_setup_get_type (), value, (gint *) e);
}

static napi_value
fdn_peer_setup_to_value (napi_env env,
                         FridaPeerSetup e)
{
  return fdn_enum_to_value (env, frida_peer_setup_get_type (), e);
}

static gboolean
fdn_web_service_transport_from_value (napi_env env,
                                      napi_value value,
                                      FridaWebServiceTransport * e)
{
  return fdn_enum_from_value (env, frida_web_service_transport_get_type (), value, (gint *) e);
}

static napi_value
fdn_web_service_transport_to_value (napi_env env,
                                    FridaWebServiceTransport e)
{
  return fdn_enum_to_value (env, frida_web_service_transport_get_type (), e);
}

static gboolean
fdn_web_service_flavor_from_value (napi_env env,
                                   napi_value value,
                                   FridaWebServiceFlavor * e)
{
  return fdn_enum_from_value (env, frida_web_service_flavor_get_type (), value, (gint *) e);
}

static napi_value
fdn_web_service_flavor_to_value (napi_env env,
                                 FridaWebServiceFlavor e)
{
  return fdn_enum_to_value (env, frida_web_service_flavor_get_type (), e);
}

static gboolean
fdn_port_conflict_behavior_from_value (napi_env env,
                                       napi_value value,
                                       FridaPortConflictBehavior * e)
{
  return fdn_enum_from_value (env, frida_port_conflict_behavior_get_type (), value, (gint *) e);
}

static napi_value
fdn_port_conflict_behavior_to_value (napi_env env,
                                     FridaPortConflictBehavior e)
{
  return fdn_enum_to_value (env, frida_port_conflict_behavior_get_type (), e);
}

static gboolean
fdn_string_terminator_from_value (napi_env env,
                                  napi_value value,
                                  FridaStringTerminator * e)
{
  return fdn_enum_from_value (env, frida_string_terminator_get_type (), value, (gint *) e);
}

static napi_value
fdn_string_terminator_to_value (napi_env env,
                                FridaStringTerminator e)
{
  return fdn_enum_to_value (env, frida_string_terminator_get_type (), e);
}

static gboolean
fdn_is_undefined_or_null (napi_env env,
                          napi_value value)
{
  napi_valuetype type;

  napi_typeof (env, value, &type);

  return type == napi_undefined || type == napi_null;
}

static gboolean
fdn_boolean_from_value (napi_env env,
                        napi_value value,
                        gboolean * b)
{
  bool napi_b;

  if (napi_get_value_bool (env, value, &napi_b) != napi_ok)
    goto invalid_argument;

  *b = napi_b;
  return TRUE;

invalid_argument:
  {
    napi_throw_error (env, NULL, "expected a boolean");
    return FALSE;
  }
}

static napi_value
fdn_boolean_to_value (napi_env env,
                      gboolean b)
{
  napi_value result;
  napi_get_boolean (env, b, &result);
  return result;
}

static gboolean
fdn_int_from_value (napi_env env,
                    napi_value value,
                    gint * i)
{
  int32_t napi_i;

  if (napi_get_value_int32 (env, value, &napi_i) != napi_ok)
    goto invalid_argument;

  *i = napi_i;
  return TRUE;

invalid_argument:
  {
    napi_throw_error (env, NULL, "expected an integer");
    return FALSE;
  }
}

static napi_value
fdn_int_to_value (napi_env env,
                  gint i)
{
  napi_value result;
  napi_create_int32 (env, i, &result);
  return result;
}

static gboolean
fdn_uint_from_value (napi_env env,
                     napi_value value,
                     guint * u)
{
  uint32_t napi_u;

  if (napi_get_value_uint32 (env, value, &napi_u) != napi_ok)
    goto invalid_argument;

  *u = napi_u;
  return TRUE;

invalid_argument:
  {
    napi_throw_error (env, NULL, "expected an unsigned integer");
    return FALSE;
  }
}

static napi_value
fdn_uint_to_value (napi_env env,
                   guint u)
{
  napi_value result;
  napi_create_uint32 (env, u, &result);
  return result;
}

static gboolean
fdn_uint16_from_value (napi_env env,
                       napi_value value,
                       guint16 * u)
{
  uint32_t napi_u;
  
  if (napi_get_value_uint32 (env, value, &napi_u) != napi_ok)
    goto invalid_argument;
    
  if (napi_u > G_MAXUINT16)
    goto invalid_argument;

  *u = napi_u;
  return TRUE;

invalid_argument:
  {
    napi_throw_error (env, NULL, "expected an unsigned 16-bit integer");
    return FALSE;
  }
}

static napi_value
fdn_uint16_to_value (napi_env env,
                     guint16 u)
{
  napi_value result;
  napi_create_uint32 (env, u, &result);
  return result;
}

static gboolean
fdn_int64_from_value (napi_env env,
                      napi_value value,
                      gint64 * i)
{
  int64_t napi_i;

  if (napi_get_value_int64 (env, value, &napi_i) != napi_ok)
    goto invalid_argument;

  *i = napi_i;
  return TRUE;

invalid_argument:
  {
    napi_throw_error (env, NULL, "expected an integer");
    return FALSE;
  }
}

static napi_value
fdn_int64_to_value (napi_env env,
                    gint64 i)
{
  napi_value result;
  napi_create_int64 (env, i, &result);
  return result;
}

static napi_value
fdn_uint64_to_value (napi_env env,
                     guint64 u)
{
  napi_value result;
  napi_create_double (env, u, &result);
  return result;
}

static gboolean
fdn_ulong_from_value (napi_env env,
                      napi_value value,
                      gulong * u)
{
  double d;

  if (napi_get_value_double (env, value, &d) != napi_ok)
    goto invalid_argument;

  if (d < 0 || d > G_MAXULONG)
    goto invalid_argument;

  *u = d;
  return TRUE;

invalid_argument:
  {
    napi_throw_error (env, NULL, "expected an unsigned integer");
    return FALSE;
  }
}

static napi_value
fdn_double_to_value (napi_env env,
                     gdouble d)
{
  napi_value result;
  napi_create_double (env, d, &result);
  return result;
}

static gboolean
fdn_enum_from_value (napi_env env,
                     GType enum_type,
                     napi_value value,
                     gint * e)
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
      *e = enum_value->value;
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
                   gint e)
{
  napi_value result;
  GEnumClass * enum_class;
  GEnumValue * enum_value;

  enum_class = G_ENUM_CLASS (g_type_class_ref (enum_type));

  enum_value = g_enum_get_value (enum_class, e);
  g_assert (enum_value != NULL);

  napi_create_string_utf8 (env, enum_value->value_nick, NAPI_AUTO_LENGTH, &result);

  g_type_class_unref (enum_class);

  return result;
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
fdn_strv_from_value (napi_env env,
                     napi_value value,
                     gchar *** strv)
{
  uint32_t length, i;
  gchar ** vector = NULL;

  if (napi_get_array_length (env, value, &length) != napi_ok)
    goto invalid_argument;

  vector = g_new0 (gchar *, length + 1);

  for (i = 0; i != length; i++)
  {
    napi_value js_str;

    if (napi_get_element (env, value, i, &js_str) != napi_ok)
      goto invalid_argument;

    if (!fdn_utf8_from_value (env, js_str, &vector[i]))
      goto invalid_argument;
  }

  *strv = vector;
  return TRUE;

invalid_argument:
  {
    napi_throw_error (env, NULL, "expected an array of strings");
    g_strfreev (vector);
    return FALSE;
  }
}

static napi_value
fdn_strv_to_value (napi_env env,
                   gchar ** strv)
{
  napi_value result;
  uint32_t length, i;

  length = g_strv_length (strv);

  napi_create_array_with_length (env, length, &result);

  for (i = 0; i != length; i++)
    napi_set_element (env, result, i, fdn_utf8_to_value (env, strv[i]));

  return result;
}

static napi_value
fdn_buffer_to_value (napi_env env,
                     const guint8 * data,
                     gsize size)
{
  napi_value result;
  napi_create_buffer_copy (env, size, data, NULL, &result);
  return result;
}

static gboolean
fdn_bytes_from_value (napi_env env,
                      napi_value value,
                      GBytes ** bytes)
{
  void * data;
  size_t size;

  if (napi_get_buffer_info (env, value, &data, &size) != napi_ok)
    goto invalid_argument;

  *bytes = g_bytes_new (data, size);
  return TRUE;

invalid_argument:
  {
    napi_throw_error (env, NULL, "expected a buffer");
    return FALSE;
  }
}

static napi_value
fdn_bytes_to_value (napi_env env,
                    GBytes * bytes)
{
  const guint8 * data;
  gsize size;

  data = g_bytes_get_data (bytes, &size);

  return fdn_buffer_to_value (env, data, size);
}

static gboolean
fdn_vardict_from_value (napi_env env,
                        napi_value value,
                        GHashTable ** vardict)
{
  napi_value keys;
  uint32_t length, i;
  GHashTable * dict = NULL;
  gchar * key = NULL;

  if (napi_get_property_names (env, value, &keys) != napi_ok)
    goto invalid_argument;
  if (napi_get_array_length (env, keys, &length) != napi_ok)
    goto propagate_error;

  dict = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, (GDestroyNotify) g_variant_unref);

  for (i = 0; i != length; i++)
  {
    napi_value js_key, js_val;
    GVariant * val;

    if (napi_get_element (env, keys, i, &js_key) != napi_ok)
      goto propagate_error;
    if (!fdn_utf8_from_value (env, js_key, &key))
      goto invalid_argument;

    if (napi_get_property (env, value, js_key, &js_val) != napi_ok)
      goto propagate_error;
    if (!fdn_variant_from_value (env, js_val, &val))
      goto propagate_error;

    g_hash_table_insert (dict, g_steal_pointer (&key), g_variant_ref_sink (val));
  }

  *vardict = dict;
  return TRUE;

invalid_argument:
  {
    napi_throw_error (env, NULL, "expected a vardict");
    goto propagate_error;
  }
propagate_error:
  {
    g_free (key);
    g_clear_pointer (&dict, g_hash_table_unref);
    return FALSE;
  }
}

static napi_value
fdn_vardict_to_value (napi_env env,
                      GHashTable * vardict)
{
  napi_value result;
  GHashTableIter iter;
  gpointer key, value;

  napi_create_object (env, &result);

  g_hash_table_iter_init (&iter, vardict);
  while (g_hash_table_iter_next (&iter, &key, &value))
  {
    napi_value js_key, js_value;

    js_key = fdn_utf8_to_value (env, key);
    js_value = fdn_variant_to_value (env, value);

    napi_set_property (env, result, js_key, js_value);
  }

  return result;
}

static gboolean
fdn_variant_from_value (napi_env env,
                        napi_value value,
                        GVariant ** variant)
{
  napi_valuetype type;

  napi_typeof (env, value, &type);

  switch (type)
  {
    case napi_boolean:
    {
      gboolean b;

      if (!fdn_boolean_from_value (env, value, &b))
        return FALSE;

      *variant = g_variant_new_boolean (b);
      return TRUE;
    }
    case napi_number:
    {
      gint64 i;

      if (!fdn_int64_from_value (env, value, &i))
        return FALSE;

      *variant = g_variant_new_int64 (i);
      return TRUE;
    }
    case napi_string:
    {
      gchar * str;

      if (!fdn_utf8_from_value (env, value, &str))
        return FALSE;

      *variant = g_variant_new_take_string (str);
      return TRUE;
    }
    case napi_object:
    {
      bool is_buffer, is_array;
      GVariantBuilder builder;
      napi_value keys;
      uint32_t length, i;

      if (napi_is_buffer (env, value, &is_buffer) != napi_ok)
        return FALSE;
      if (is_buffer)
      {
        void * data;
        size_t size;
        gpointer copy;

        if (napi_get_buffer_info (env, value, &data, &size) != napi_ok)
          return FALSE;

        copy = g_memdup2 (data, size);
        *variant = g_variant_new_from_data (G_VARIANT_TYPE_BYTESTRING, copy, size, TRUE, g_free, copy);
        return TRUE;
      }

      if (napi_is_array (env, value, &is_array) != napi_ok)
        return FALSE;
      if (is_array)
      {
        uint32_t length;

        if (napi_get_array_length (env, value, &length) != napi_ok)
          return FALSE;

        if (length == 2)
        {
          napi_value first;
          napi_valuetype first_type;

          if (napi_get_element (env, value, 0, &first) != napi_ok)
            return FALSE;

          napi_typeof (env, first, &first_type);

          if (first_type == napi_symbol)
          {
            napi_value second;
            GVariant * val;
            napi_value desc;
            gchar * type;
            GVariant * t[2];

            if (napi_get_element (env, value, 1, &second) != napi_ok)
              return FALSE;

            if (!fdn_variant_from_value (env, second, &val))
              return FALSE;

            napi_coerce_to_string (env, first, &desc);
            fdn_utf8_from_value (env, desc, &type);

            t[0] = g_variant_new_take_string (type);
            t[1] = val;

            *variant = g_variant_new_tuple (t, G_N_ELEMENTS (t));
            return TRUE;
          }
        }

        g_variant_builder_init (&builder, G_VARIANT_TYPE ("av"));

        for (i = 0; i != length; i++)
        {
          napi_value element;
          GVariant * v;

          if (napi_get_element (env, value, i, &element) != napi_ok)
          {
            g_variant_builder_clear (&builder);
            return FALSE;
          }

          if (!fdn_variant_from_value (env, element, &v))
          {
            g_variant_builder_clear (&builder);
            return FALSE;
          }

          g_variant_builder_add (&builder, "v", v);
        }

        *variant = g_variant_builder_end (&builder);
        return TRUE;
      }

      g_variant_builder_init (&builder, G_VARIANT_TYPE_VARDICT);

      if (napi_get_property_names (env, value, &keys) != napi_ok)
        return FALSE;

      if (napi_get_array_length (env, keys, &length) != napi_ok)
        return FALSE;

      for (i = 0; i != length; i++)
      {
        napi_value key;
        gchar * key_str;
        napi_value val;
        GVariant * v;

        if (napi_get_element (env, keys, i, &key) != napi_ok)
          return FALSE;

        if (!fdn_utf8_from_value (env, key, &key_str))
          return FALSE;

        if (napi_get_property (env, value, key, &val) != napi_ok)
        {
          g_free (key_str);
          return FALSE;
        }

        if (!fdn_variant_from_value (env, val, &v))
        {
          g_free (key_str);
          return FALSE;
        }

        g_variant_builder_add (&builder, "{sv}", key_str, v);
        g_free (key_str);
      }

      *variant = g_variant_builder_end (&builder);
      return TRUE;
    }
    default:
      break;
  }

  napi_throw_type_error (env, NULL, "expected value serializable to GVariant");
  return FALSE;
}

static napi_value
fdn_variant_to_value (napi_env env,
                      GVariant * variant)
{
  napi_value result;

  switch (g_variant_classify (variant))
  {
    case G_VARIANT_CLASS_STRING:
    {
      const gchar * str = g_variant_get_string (variant, NULL);
      return fdn_utf8_to_value (env, str);
    }
    case G_VARIANT_CLASS_INT64:
      return fdn_int64_to_value (env, g_variant_get_int64 (variant));
    case G_VARIANT_CLASS_UINT64:
      return fdn_uint64_to_value (env, g_variant_get_uint64 (variant));
    case G_VARIANT_CLASS_DOUBLE:
      return fdn_double_to_value (env, g_variant_get_double (variant));
    case G_VARIANT_CLASS_BOOLEAN:
      return fdn_boolean_to_value (env, g_variant_get_boolean (variant));
    case G_VARIANT_CLASS_ARRAY:
      if (g_variant_is_of_type (variant, G_VARIANT_TYPE ("ay")))
      {
        gsize size;
        g_variant_get_fixed_array (variant, &size, sizeof (guint8));
        return fdn_buffer_to_value (env, g_variant_get_data (variant), size);
      }

      if (g_variant_is_of_type (variant, G_VARIANT_TYPE_VARDICT))
      {
        napi_value dict;
        GVariantIter iter;
        gchar * key;
        GVariant * value;

        napi_create_object (env, &dict);

        g_variant_iter_init (&iter, variant);
        while (g_variant_iter_next (&iter, "{sv}", &key, &value))
        {
          napi_value js_key, js_value;

          js_key = fdn_utf8_to_value (env, key);
          js_value = fdn_variant_to_value (env, value);

          napi_set_property (env, dict, js_key, js_value);

          g_variant_unref (value);
          g_free (key);
        }

        return dict;
      }

      if (g_variant_is_of_type (variant, G_VARIANT_TYPE_ARRAY))
      {
        napi_value array;
        GVariantIter iter;
        uint32_t i;
        GVariant * child;

        napi_create_array (env, &array);

        g_variant_iter_init (&iter, variant);
        i = 0;
        while ((child = g_variant_iter_next_value (&iter)) != NULL)
        {
          napi_value element = fdn_variant_to_value (env, child);
          napi_set_element (env, array, i++, element);
          g_variant_unref (child);
        }

        return array;
      }

      break;
    case G_VARIANT_CLASS_TUPLE:
      napi_get_undefined (env, &result);
      return result;
    default:
      break;
  }

  napi_get_null (env, &result);
  return result;
}

static gboolean
fdn_file_from_value (napi_env env,
                     napi_value value,
                     GFile ** file)
{
  gchar * path;

  if (!fdn_utf8_from_value (env, value, &path))
    return FALSE;
  *file = g_file_new_for_path (path);
  g_free (path);

  return TRUE;
}

static napi_value
fdn_file_to_value (napi_env env,
                   GFile * file)
{
  napi_value result;
  gchar * path;

  path = g_file_get_path (file);
  result = fdn_utf8_to_value (env, path);
  g_free (path);

  return result;
}

static gboolean
fdn_tls_certificate_from_value (napi_env env,
                                napi_value value,
                                GTlsCertificate ** certificate)
{
  gchar * str;
  GError * error = NULL;

  if (!fdn_utf8_from_value (env, value, &str))
    return FALSE;

  if (strchr (str, '\n') != NULL)
    *certificate = g_tls_certificate_new_from_pem (str, -1, &error);
  else
    *certificate = g_tls_certificate_new_from_file (str, &error);

  g_free (str);

  if (error != NULL)
    goto invalid_argument;
  return TRUE;

invalid_argument:
  {
    napi_throw_error (env, NULL, error->message);
    g_error_free (error);
    return FALSE;
  }
}

static napi_value
fdn_tls_certificate_to_value (napi_env env,
                              GTlsCertificate * certificate)
{
  napi_value result;
  gchar * pem;

  g_object_get (certificate, "certificate-pem", &pem, NULL);
  result = fdn_utf8_to_value (env, pem);
  g_free (pem);

  return result;
}

static napi_value
fdn_io_stream_to_value (napi_env env,
                        GIOStream * stream)
{
  napi_value result;

  napi_create_external (env, stream, NULL, NULL, &result);

  return result;
}

static void
fdn_object_finalize (napi_env env,
                     void * finalize_data,
                     void * finalize_hint)
{
  g_object_unref (finalize_data);
}

static napi_value
fdn_object_get_signal (napi_env env,
                       napi_callback_info info,
                       const gchar * name,
                       const gchar * js_storage_name)
{
  napi_value result, jsthis, js_storage_name_value;
  napi_valuetype type;

  if (napi_get_cb_info (env, info, NULL, NULL, &jsthis, NULL) != napi_ok)
    return NULL;

  js_storage_name_value = fdn_utf8_to_value (env, js_storage_name);

  if (napi_get_property (env, jsthis, js_storage_name_value, &result) != napi_ok)
    return NULL;

  if (napi_typeof (env, result, &type) != napi_ok)
    return NULL;

  if (type == napi_undefined)
  {{
    GObject * handle;

    if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
      return NULL;

    result = fdn_signal_new (env, handle, name);
    napi_set_property (env, jsthis, js_storage_name_value, result);
  }}

  return result;
}

static napi_value
fdn_signal_new (napi_env env,
                GObject * handle,
                const gchar * name)
{
  napi_value result, constructor, handle_wrapper;
  napi_value args[2];

  napi_get_reference_value (env, fdn_signal_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);
  napi_type_tag_object (env, handle_wrapper, &fdn_handle_wrapper_type_tag);

  args[0] = handle_wrapper;
  args[1] = fdn_utf8_to_value (env, name);

  napi_new_instance (env, constructor, G_N_ELEMENTS (args), args, &result);

  return result;
}

static void
fdn_signal_register (napi_env env,
                     napi_value exports)
{
  napi_property_descriptor properties[] =
  {
    { "connect", NULL, fdn_signal_connect, NULL, NULL, NULL, napi_default, NULL },
    { "disconnect", NULL, fdn_signal_disconnect, NULL, NULL, NULL, napi_default, NULL },
  };
  napi_value constructor;

  napi_define_class (env, "Signal", NAPI_AUTO_LENGTH, fdn_signal_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &fdn_signal_constructor);

  napi_set_named_property (env, exports, "Signal", constructor);
}

static napi_value
fdn_signal_construct (napi_env env,
                      napi_callback_info info)
{
  size_t argc = 2;
  napi_value args[2];
  napi_value jsthis;
  bool is_instance;
  GObject * handle = NULL;
  gchar * name = NULL;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto propagate_error;

  if (argc != 2)
    goto missing_argument;

  if (napi_check_object_type_tag (env, args[0], &fdn_handle_wrapper_type_tag, &is_instance) != napi_ok || !is_instance)
    goto invalid_handle;

  if (napi_get_value_external (env, args[0], (void **) &handle) != napi_ok)
    goto propagate_error;

  if (!fdn_utf8_from_value (env, args[1], &name))
    goto propagate_error;

  g_object_ref (handle);

  if (napi_wrap (env, jsthis, handle, NULL, NULL, NULL) != napi_ok)
    goto propagate_error;

  if (napi_add_finalizer (env, jsthis, handle, fdn_object_finalize, NULL, NULL) != napi_ok)
    goto propagate_error;

  handle = NULL;
  g_free (name);

  return jsthis;

missing_argument:
  {
    napi_throw_error (env, NULL, "missing argument");
    goto propagate_error;
  }
invalid_handle:
  {
    napi_throw_type_error (env, NULL, "expected an object handle");
    goto propagate_error;
  }
propagate_error:
  {
    g_free (name);
    g_clear_object (&handle);
    return NULL;
  }
}

static napi_value
fdn_signal_connect (napi_env env,
                    napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 1;
  napi_value handler, jsthis;
  GObject * handle;

  if (napi_get_cb_info (env, info, &argc, &handler, &jsthis, NULL) != napi_ok)
    goto beach;

  if (argc != 1)
    goto missing_argument;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  napi_get_undefined (env, &js_retval);

beach:
  return js_retval;

missing_argument:
  {
    napi_throw_error (env, NULL, "missing argument: handler");
    return NULL;
  }
}

static napi_value
fdn_signal_disconnect (napi_env env,
                       napi_callback_info info)
{
  napi_value js_retval = NULL;
  size_t argc = 1;
  napi_value handler, jsthis;
  GObject * handle;

  if (napi_get_cb_info (env, info, &argc, &handler, &jsthis, NULL) != napi_ok)
    goto beach;

  if (argc != 1)
    goto missing_argument;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;

  napi_get_undefined (env, &js_retval);

beach:
  return js_retval;

missing_argument:
  {
    napi_throw_error (env, NULL, "missing argument: handler");
    return NULL;
  }
}
