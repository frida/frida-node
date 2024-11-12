import xml.etree.ElementTree as ET
from typing import List, Dict
from dataclasses import dataclass

@dataclass
class Parameter:
    name: str
    param_type: str
    c_type: str
    napi_type: str

@dataclass
class Method:
    name: str
    c_identifier: str
    return_type: str
    parameters: List[Parameter]
    is_async: bool

@dataclass
class Class:
    name: str
    c_type: str
    methods: List[Method]

    @property
    def c_cast_macro(self):
        return to_macro_case(self.c_type)

node_api_types: Dict[str, str] = {
    "gboolean": "bool",
    "gint": "int32",
    "guint": "uint32",
    "gint64": "int64",
    "guint64": "uint64",
    "gfloat": "float",
    "gdouble": "double",
    "utf8": "string_utf8",
    "Gio.Cancellable": "object",
}

def generate_code(file_path: str) -> str:
    klass = parse_gir(file_path)

    code = generate_includes()

    for method in klass.methods:
        code += generate_method_code(klass, method)

    code += generate_registration_code(klass)

    return code

def parse_gir(file_path: str) -> Class:
    tree = ET.parse(file_path)
    root = tree.getroot()
    ns = {"": "http://www.gtk.org/introspection/core/1.0"}

    c_ns = "http://www.gtk.org/introspection/c/1.0"

    klass_element = root.find(".//class[@name='DeviceManager']", ns)
    class_name = klass_element.get("name")
    class_c_type = klass_element.get(f"{{{c_ns}}}type")
    methods = []

    for method_element in klass_element.findall(".//method", ns):
        method_name = method_element.get("name")
        if method_name.startswith("_") or method_name.endswith("_sync") or method_name.endswith("_finish"):
            continue

        c_identifier = method_element.get(f"{{{c_ns}}}identifier")
        return_value = method_element.find(".//return-value/type", ns)
        return_type = return_value.get("name") if return_value is not None else "void"
        parameters = method_element.findall("./parameters/parameter", ns)
        is_async = any(param.find("type", ns).get("name") == "Gio.AsyncReadyCallback" for param in parameters)

        param_list = []
        for param in parameters:
            param_name = param.get("name")
            if param_name.startswith("_"):
                continue
            type_element = param.find("type", ns)
            param_type = type_element.get("name")
            c_type = type_element.get(f"{{{c_ns}}}type")
            napi_type = node_api_types.get(param_type, "unknown")
            param_list.append(Parameter(param_name, param_type, c_type, napi_type))

        methods.append(Method(method_name, c_identifier, return_type, param_list, is_async))

    return Class(class_name, class_c_type, methods)

def generate_includes() -> str:
    return """\
#include <frida-core.h>
#include <node_api.h>

"""

def generate_method_code(klass: Class, method: Method) -> str:
    method_name_pascal = to_pascal_case(method.name)
    class_name = klass.name
    class_name_snake = to_snake_case(class_name)

    param_declarations = [f"{param.c_type} {param.name};" for param in method.parameters]
    param_initializations = [f"operation->{param.name} = {param.name};" for param in method.parameters]
    param_names = [f"operation->{param.name}" for param in method.parameters]
    param_conversions = [generate_parameter_conversion_code(param.name, param.param_type, param.napi_type, i) for i, param in enumerate(method.parameters)]
    param_frees = [f"g_free (operation->{param.name});" for param in method.parameters if param.napi_type == "string_utf8"]

    param_declarations_str = "\n  ".join(param_declarations)
    param_frees_str = "\n  ".join(param_frees)

    def calculate_indent(suffix: str) -> str:
        return " " * (len(class_name_snake) + 1 + len(method.name) + len(suffix) + 2)

    if method.is_async:
        prototypes = f"""\
static gboolean {class_name_snake}_{method.name}_begin (gpointer user_data);
static void {class_name_snake}_{method.name}_end (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void {class_name_snake}_{method.name}_deliver (napi_env env, napi_value js_cb, void * context, void * data);
static void {class_name_snake}_{method.name}_operation_free ({class_name}{method_name_pascal}Operation * operation);"""

        param_conversions_str = "\n\n".join(param_conversions)
        operation_free_function = f"""
static void
{class_name_snake}_{method.name}_operation_free ({class_name}{method_name_pascal}Operation * operation)
{{
  {param_frees_str}
  g_slice_free ({class_name}{method_name_pascal}Operation, operation);
}}
"""

        code = f"""
typedef struct {{
  napi_env env;
  napi_deferred deferred;
  {klass.c_type} * handle;
  napi_threadsafe_function tsfn;
  GError * error;
  {param_declarations_str}
}} {class_name}{method_name_pascal}Operation;

{prototypes}

static napi_value
{class_name_snake}_{method.name} (napi_env env,
{calculate_indent('')}napi_callback_info info)
{{
  size_t argc = {len(method.parameters)};
  napi_value args[{len(method.parameters)}];
  napi_status status;
  napi_value jsthis;
  {klass.c_type} * handle;
  napi_deferred deferred;
  napi_value promise;
  {class_name}{method_name_pascal}Operation * operation;
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

  operation = g_slice_new0 ({class_name}{method_name_pascal}Operation);
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;

{param_conversions_str}

  status = napi_create_threadsafe_function (env, NULL, NULL,
      napi_create_string_utf8 (env, "{method.name}",
      NAPI_AUTO_LENGTH, NULL), 0, 1, NULL, NULL, NULL,
      {class_name_snake}_{method.name}_deliver, &operation->tsfn);
  if (status != napi_ok)
    return NULL;

  source = g_idle_source_new ();
  g_source_set_callback (source, {class_name_snake}_{method.name}_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  return promise;

invalid_argument:
  {{
    napi_reject_deferred (env, deferred, NULL);
    {class_name_snake}_{method.name}_operation_free (operation);
    return NULL;
  }}
}}

static gboolean
{class_name_snake}_{method.name}_begin (gpointer user_data)
{{
  {class_name}{method_name_pascal}Operation * operation = user_data;

  {method.c_identifier} (operation->device->handle_,
      {", ".join([f"operation->{param.name}" for param in method.parameters])},
      {class_name_snake}_{method.name}_end, operation);

  return G_SOURCE_REMOVE;
}}

static void
{class_name_snake}_{method.name}_end (GObject * source_object,
{calculate_indent('_end')}GAsyncResult * res,
{calculate_indent('_end')}gpointer user_data)
{{
  {class_name}{method_name_pascal}Operation * operation = user_data;

  operation->parameters = {method.c_identifier}_finish (
      {klass.c_cast_macro} (source_object), res, &operation->error);

  napi_call_threadsafe_function (operation->tsfn, operation, napi_tsfn_blocking);
  napi_release_threadsafe_function (operation->tsfn, napi_tsfn_release);
}}

static void
{class_name_snake}_{method.name}_deliver (napi_env env,
{calculate_indent('_deliver')}napi_value js_cb,
{calculate_indent('_deliver')}void * context,
{calculate_indent('_deliver')}void * data)
{{
  {class_name}{method_name_pascal}Operation * operation = data;
  napi_value result;

  if (operation->error != NULL)
  {{
    napi_value message;
    napi_create_string_utf8 (env, operation->error->message, NAPI_AUTO_LENGTH,
        &message);
    napi_value error_obj;
    napi_create_error (env, NULL, message, &error_obj);
    napi_reject_deferred (env, operation->deferred, error_obj);
    g_error_free (operation->error);
  }}
  else
  {{
    result = Runtime_ValueFromParametersDict (env, operation->parameters);
    g_hash_table_unref (operation->parameters);
    napi_resolve_deferred (env, operation->deferred, result);
  }}

  {class_name_snake}_{method.name}_operation_free (operation);
}}

{operation_free_function}
"""
    else:
        param_conversions_str_sync = "\n".join([
            line.replace("operation->", "")
            for line in param_conversions
        ])

        if method.parameters:
            param_call_str = ", " + ", ".join([param.name for param in method.parameters])
        else:
            param_call_str = ""

        code = f"""
static napi_value
{class_name_snake}_{method.name} (napi_env env,
{calculate_indent('')}napi_callback_info info)
{{
  size_t argc = {len(method.parameters)};
  napi_value args[{len(method.parameters)}];
  napi_status status;
  napi_value jsthis;
  {class_name} * obj;
  napi_value result;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &obj);
  if (status != napi_ok)
    return NULL;

  {param_conversions_str_sync}

  {method.return_type} ret = {method.c_identifier} (obj->handle_{param_call_str});

  result = Runtime_ValueFrom{to_pascal_case(method.return_type)} (env, ret);

  {param_frees_str}

  return result;

invalid_argument:
  {param_frees_str}
  return NULL;
}}
"""
    return code

def generate_parameter_conversion_code(param_name: str, param_type: str, napi_type: str, index: int) -> str:
    if param_type == "Gio.Cancellable":
        return f"""\
  if (argc > {index})
  {{
    status = napi_get_value_{napi_type} (env, args[{index}], &{param_name});
    if (status != napi_ok)
    {{
      napi_throw_error (env, NULL, "failed to get argument value");
      goto invalid_argument;
    }}
    else
    {{
      {param_name} = NULL;
    }}
  }}"""
    elif napi_type == "string_utf8":
        return f"""\
  size_t {param_name}_length;
  status = napi_get_value_string_utf8 (env, args[{index}], NULL, 0, &{param_name}_length);
  if (status != napi_ok)
  {{
    napi_throw_error (env, NULL, "failed to get string length");
    goto invalid_argument;
  }}
  {param_name} = g_malloc ({param_name}_length + 1);
  status = napi_get_value_string_utf8 (env, args[{index}], {param_name}, {param_name}_length + 1, &{param_name}_length);
  if (status != napi_ok)
  {{
    napi_throw_error (env, NULL, "failed to get string value");
    goto invalid_argument;
  }}"""
    else:
        return f"""\
  if (argc <= {index})
  {{
    napi_throw_type_error (env, NULL, "missing argument: {param_name}");
    goto invalid_argument;
  }}
  status = napi_get_value_{napi_type} (env, args[{index}], &{param_name});
  if (status != napi_ok)
  {{
    napi_throw_error (env, NULL, "failed to get argument value");
    goto invalid_argument;
  }}"""

def generate_registration_code(klass: Class) -> str:
    class_name_snake = to_snake_case(klass.name)
    method_registrations = []

    for method in klass.methods:
        method_name_camel = to_camel_case(method.name)
        method_registrations.append(f"""{{ "{method_name_camel}", 0, {class_name_snake}_{method.name}, 0, 0, 0, napi_default, 0 }},""")

    method_registrations_str = "\n    ".join(method_registrations)

    return f"""
static napi_value
Init (napi_env env,
      napi_value exports)
{{
  napi_status status;
  napi_property_descriptor properties[] =
  {{
    {method_registrations_str}
  }};

  napi_value constructor;
  status = napi_define_class (env, "{klass.name}", NAPI_AUTO_LENGTH, {class_name_snake}_constructor, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  if (status != napi_ok)
    return NULL;

  status = napi_set_named_property (env, exports, "{klass.name}", constructor);
  if (status != napi_ok)
    return NULL;

  return exports;
}}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
"""

def to_snake_case(name: str) -> str:
    return "".join(["_" + c.lower() if c.isupper() else c for c in name]).lstrip("_")

def to_pascal_case(name: str) -> str:
    return "".join(word.capitalize() for word in name.split("_"))

def to_camel_case(name: str) -> str:
    words = name.split("_")
    return words[0] + "".join(word.capitalize() for word in words[1:])

def to_macro_case(identifier: str) -> str:
    result = []
    for i, char in enumerate(identifier):
        if char.isupper() and i != 0:
            result.append('_')
        result.append(char)
    return "".join(result).upper()

if __name__ == "__main__":
    file_path = "frida-core.gir"
    code = generate_code(file_path)
    print(code)