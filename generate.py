from __future__ import annotations
from collections import OrderedDict
from dataclasses import dataclass
from functools import cached_property
from pathlib import Path
from typing import Callable, List, Optional
import uuid
import xml.etree.ElementTree as ET

CORE_NAMESPACE = "http://www.gtk.org/introspection/core/1.0"
C_NAMESPACE = "http://www.gtk.org/introspection/c/1.0"
GLIB_NAMESPACE = "http://www.gtk.org/introspection/glib/1.0"
GIR_NAMESPACES = {"": CORE_NAMESPACE}

@dataclass
class Model:
    classes: OrderedDict[str, Class]
    enumerations: OrderedDict[str, Enumeration]

@dataclass
class Class:
    name: str
    c_type: str
    _constructors: List[ET.Element]
    _methods: List[ET.Element]
    method_filter: Optional[MethodFilter]
    method_name_transformer: Optional[MethodNameTransformer]

    @cached_property
    def c_symbol_prefix(self):
        return f"fdn_{to_snake_case(self.name)}"

    @cached_property
    def c_cast_macro(self):
        return to_macro_case(self.c_type)

    @cached_property
    def constructors(self) -> List[Constructor]:
        constructors = []
        for constructor_element in self._constructors:
            constructor_name = constructor_element.get("name")
            c_identifier = constructor_element.get(f"{{{C_NAMESPACE}}}identifier")
            parameters = constructor_element.findall("./parameters/parameter", GIR_NAMESPACES)

            throws = constructor_element.get("throws") == "1"

            param_list = []
            for param in parameters:
                param_name = param.get("name")
                type = extract_type_from_entity(param)
                nullable = param.get("nullable") == "1"
                param_list.append(Parameter(param_name, type, nullable))

            constructors.append(Constructor(constructor_name, c_identifier, param_list, throws))
        return constructors

    @cached_property
    def methods(self) -> List[Method]:
        methods = []
        for method_element in self._methods:
            method_name = method_element.get("name")
            if self.method_filter is not None and not self.method_filter(self.name, method_name):
                continue
            if method_name.startswith("_") or method_name.endswith("_sync") or method_name.endswith("_finish"):
                continue
            transformed_method_name = self.method_name_transformer(self.name, method_name) if self.method_name_transformer is not None else method_name

            c_identifier = method_element.get(f"{{{C_NAMESPACE}}}identifier")
            parameters = method_element.findall("./parameters/parameter", GIR_NAMESPACES)
            has_closure_param = any((param.get("closure") == "1" for param in parameters))
            if has_closure_param:
                continue

            throws = method_element.get("throws") == "1"
            is_async = any(param[0].get("name") == "Gio.AsyncReadyCallback" for param in parameters)

            result_element = next((m for m in self._methods if m.get("name") == f"{method_name}_finish")) if is_async else method_element
            return_type = extract_type_from_entity(result_element.find(".//return-value", GIR_NAMESPACES))

            param_list = []
            for param in parameters:
                param_name = param.get("name")
                if param_name.startswith("_"):
                    continue
                type = extract_type_from_entity(param)
                nullable = param.get("nullable") == "1"
                param_list.append(Parameter(param_name, type, nullable))

            methods.append(Method(transformed_method_name, c_identifier, return_type, param_list, throws, is_async, self))
        return methods

@dataclass
class Constructor:
    name: str
    c_identifier: str
    parameters: List[Parameter]
    throws: bool

@dataclass
class Method:
    name: str
    c_identifier: str
    return_type: Optional[Type]
    parameters: List[Parameter]
    throws: bool
    is_async: bool

    klass: Class

    @cached_property
    def operation_type_name(self) -> str:
        return f"Fdn{self.klass.name}{to_pascal_case(self.name)}Operation"

@dataclass
class Parameter:
    name: str
    type: Type
    nullable: bool

@dataclass
class Type:
    name: str
    nick: str
    c: str
    default_value: Optional[str]

@dataclass
class Enumeration:
    name: str
    c_type: str
    get_type: str

MethodFilter = Callable[[str, str], bool]
MethodNameTransformer = Callable[[str, str], str]

def parse_gir(file_path: str,
              method_filter: Optional[MethodFilter] = None,
              method_name_transformer: Optional[MethodNameTransformer] = None) -> Model:
    tree = ET.parse(file_path)

    classes = OrderedDict()
    for klass_element in tree.getroot().findall(".//class", GIR_NAMESPACES):
        class_name = klass_element.get("name")
        class_c_type = klass_element.get(f"{{{C_NAMESPACE}}}type")
        constructors = klass_element.findall(".//constructor", GIR_NAMESPACES)
        methods = klass_element.findall(".//method", GIR_NAMESPACES)

        classes[class_name] = Class(class_name, class_c_type, constructors, methods, method_filter, method_name_transformer)

    enumerations = OrderedDict()
    for enum_element in tree.getroot().findall(".//enumeration", GIR_NAMESPACES):
        if enum_element.get(f"{{{GLIB_NAMESPACE}}}error-domain") is not None:
            continue
        enum_name = enum_element.get("name")
        enum_c_type = enum_element.get(f"{{{C_NAMESPACE}}}type")
        get_type = enum_element.get(f"{{{GLIB_NAMESPACE}}}get-type")
        enumerations[enum_name] = Enumeration(enum_name, enum_c_type, get_type)

    return Model(classes, enumerations)

def extract_type_from_entity(parent_element: ET.Element) -> Optional[Type]:
    child = parent_element.find("type", GIR_NAMESPACES)
    if child is None:
        child = parent_element.find("array", GIR_NAMESPACES)
        assert child is not None
        element_type = extract_type_from_entity(child)
        assert element_type.name == "utf8", "only string arrays are supported for now"
        return Type("utf8[]", "strv", "gchar **", "NULL")
    return parse_type(child)

def parse_type(element: ET.Element) -> Optional[Type]:
    name = element.get("name")
    if name == "none":
        return None
    nick = type_nick_from_name(name, element)
    c = element.get(f"{{{C_NAMESPACE}}}type").replace("const ", "").replace("*", " *")
    return Type(name, nick, c, "NULL" if "*" in c else None)

def type_nick_from_name(name: str, element: ET.Element) -> str:
    if name == "GLib.PollFD":
        return "pollfd"

    tokens = name.split(".", maxsplit=1)
    if len(tokens) == 1:
        result = tokens[0]
        if result.startswith("g"):
            result = result[1:]
    else:
        result = to_snake_case(tokens[1])

    if result == "hash_table":
        key_type = parse_type(element[0])
        value_type = parse_type(element[1])
        assert key_type.name == "utf8" and value_type.name == "GLib.Variant", "only GHashTable<string, Variant> is supported for now"
        result = "vardict"

    return result

def generate_code() -> str:
    srcroot = Path(__file__).parent
    frida = parse_gir(srcroot / "Frida-1.0.gir")

    gio = parse_gir(srcroot / "Gio-2.0.gir",
                    method_filter=filter_gio_methods,
                    method_name_transformer=transform_gio_method_name)

    classes = [klass for name, klass in frida.classes.items() if name not in {"ControlService", "RpcClient", "RpcPeer"}]
    classes.append(gio.classes["Cancellable"])

    enumerations = frida.enumerations.values()

    code = generate_includes()
    code += generate_operation_structs(classes)
    code += generate_prototypes(classes, enumerations)
    code += generate_type_tags(classes)
    code += generate_constructor_declarations(classes)
    code += generate_tsfn_declarations(classes)
    code += generate_init_function(classes)

    for klass in classes:
        code += generate_registration_code(klass)
        code += generate_class_conversion_functions(klass)
        code += generate_constructor(klass)

        for method in klass.methods:
            code += generate_method_code(klass, method)

    for enum in enumerations:
        code += generate_enum_conversion_functions(enum)

    code += generate_builtin_conversion_helpers()

    return code

def filter_gio_methods(klass: str, method: str) -> bool:
    if klass == "Cancellable" and method in {"make_pollfd", "release_fd", "source_new"}:
        return False
    return True

def transform_gio_method_name(klass: str, name: str) -> str:
    if klass == "Cancellable" and name == "set_error_if_cancelled":
        return "throw_if_cancelled"
    return name

def generate_includes() -> str:
    return """\
#include <frida-core.h>
#include <node_api.h>

"""

def generate_operation_structs(classes: List[Class]) -> str:
    structs = []
    for klass in classes:
        for method in klass.methods:
            if method.is_async:
                param_declarations = [f"{param.type.c} {param.name};" for param in method.parameters]
                param_declarations_str = "\n  ".join(param_declarations)
                return_declaration = f"\n  {method.return_type.c} return_value;" if method.return_type is not None else ""
                structs.append(f"""\
typedef struct {{
  napi_env env;
  napi_deferred deferred;
  {klass.c_type} * handle;
  GError * error;
  {param_declarations_str}{return_declaration}
}} {method.operation_type_name};
""")
    return "\n".join(structs) + "\n"

def generate_prototypes(classes: List[Class], enumerations: List[Enumeration]) -> str:
    prototypes = []

    for klass in classes:
        class_cprefix = klass.c_symbol_prefix
        prototypes += [
            "",
            f"static void {class_cprefix}_register (napi_env env, napi_value exports);",
            f"G_GNUC_UNUSED static gboolean {class_cprefix}_from_value (napi_env env, napi_value value, {klass.c_type} ** result);",
            f"G_GNUC_UNUSED static napi_value {class_cprefix}_to_value (napi_env env, {klass.c_type} * handle);",
            f"static napi_value {class_cprefix}_construct (napi_env env, napi_callback_info info);",
        ]

        for method in klass.methods:
            method_cprefix = f"{class_cprefix}_{method.name}"
            prototypes += [
                "",
                f"static napi_value {method_cprefix} (napi_env env, napi_callback_info info);",
            ]
            if method.is_async:
                prototypes += [
                    f"static gboolean {method_cprefix}_begin (gpointer user_data);",
                    f"static void {method_cprefix}_end (GObject * source_object, GAsyncResult * res, gpointer user_data);",
                    f"static void {method_cprefix}_deliver (napi_env env, napi_value js_cb, void * context, void * data);",
                    f"static void {method_cprefix}_operation_free ({method.operation_type_name} * operation);",
                ]

    for enum in enumerations:
        enum_name_snake = to_snake_case(enum.name)
        prototypes += [
            "",
            f"G_GNUC_UNUSED static gboolean fdn_{enum_name_snake}_from_value (napi_env env, napi_value value, {enum.c_type} * result);",
            f"G_GNUC_UNUSED static napi_value fdn_{enum_name_snake}_to_value (napi_env env, {enum.c_type} value);",
        ]

    prototypes += [
        "",
        "static napi_value fdn_boolean_to_value (napi_env env, gboolean value);",
        "static gboolean fdn_int_from_value (napi_env env, napi_value value, gint * result);",
        "static napi_value fdn_int_to_value (napi_env env, gint value);",
        "static gboolean fdn_uint_from_value (napi_env env, napi_value value, guint * result);",
        "static napi_value fdn_uint_to_value (napi_env env, guint value);",
        "static gboolean fdn_int64_from_value (napi_env env, napi_value value, gint64 * result);",
        "static napi_value fdn_int64_to_value (napi_env env, gint64 value);",
        "static gboolean fdn_uint64_from_value (napi_env env, napi_value value, guint64 * result);",
        "static napi_value fdn_uint64_to_value (napi_env env, guint64 value);",
        "static gboolean fdn_ulong_from_value (napi_env env, napi_value value, gulong * result);",
        "static napi_value fdn_double_to_value (napi_env env, gdouble value);",
        "static gboolean fdn_utf8_from_value (napi_env env, napi_value value, gchar ** str);",
        "static napi_value fdn_utf8_to_value (napi_env env, const gchar * str);",
        "static gboolean fdn_enum_from_value (napi_env env, GType enum_type, napi_value value, gint * result);",
        "static napi_value fdn_enum_to_value (napi_env env, GType enum_type, gint value);",
        "static gboolean fdn_vardict_from_value (napi_env env, napi_value value, GHashTable ** result);",
        "static napi_value fdn_vardict_to_value (napi_env env, GHashTable * vardict);",
        "static gboolean fdn_variant_from_value (napi_env env, napi_value value, GVariant ** result);",
        "static napi_value fdn_variant_to_value (napi_env env, GVariant * variant);",
    ]

    return "\n".join(prototypes) + "\n\n"

def generate_type_tags(classes: List[Class]) -> str:
    type_tags = []
    for klass in classes:
        uuid_str = uuid.uuid4().hex
        uuid_formatted = f"0x{uuid_str[:16]}, 0x{uuid_str[16:]}"
        type_tags.append(f"static napi_type_tag {klass.c_symbol_prefix}_type_tag = {{ {uuid_formatted} }};")
    return "\n".join(type_tags) + "\n"

def generate_constructor_declarations(classes: List[Class]) -> str:
    declarations = []
    for klass in classes:
        declarations.append(f"static napi_ref {klass.c_symbol_prefix}_constructor;")
    return "\n" + "\n".join(declarations) + "\n"

def generate_tsfn_declarations(classes: List[Class]) -> str:
    declarations = []
    for klass in classes:
        async_methods = [method for method in klass.methods if method.is_async]
        if async_methods:
            declarations.append("")
            for method in async_methods:
                declarations.append(f"static napi_threadsafe_function {klass.c_symbol_prefix}_{method.name}_tsfn;")
    return "\n".join(declarations) + "\n"

def generate_init_function(classes: List[Class]) -> str:
    registration_calls = "\n  ".join([f"{klass.c_symbol_prefix}_register (env, exports);" for klass in classes])
    return f"""
static napi_value
Init (napi_env env,
      napi_value exports)
{{
  {registration_calls}
  return exports;
}}

NAPI_MODULE (NODE_GYP_MODULE_NAME, Init)
"""

def generate_registration_code(klass: Class) -> str:
    class_cprefix = klass.c_symbol_prefix

    method_registrations = []
    tsfn_initializations = []

    for method in klass.methods:
        method_name_camel = to_camel_case(method.name)
        method_registrations.append(f"""{{ "{method_name_camel}", NULL, {class_cprefix}_{method.name}, NULL, NULL, NULL, napi_default, NULL }},""")
        if method.is_async:
            tsfn_initializations.append(f"""\
napi_create_string_utf8 (env, "{method_name_camel}", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, {class_cprefix}_{method.name}_deliver, &{class_cprefix}_{method.name}_tsfn);""")

    method_registrations_str = "\n    ".join(method_registrations)
    resource_name_declaration = "\n\n  napi_value resource_name;" if tsfn_initializations else ""
    tsfn_initializations_str = "\n\n  " + "\n\n  ".join(tsfn_initializations) if tsfn_initializations else ""

    def calculate_indent(suffix: str) -> str:
        return " " * (len(class_cprefix) + len(suffix) + 2)

    return f"""
static void
{class_cprefix}_register (napi_env env,
{calculate_indent("_register")}napi_value exports)
{{
  napi_property_descriptor properties[] =
  {{
    {method_registrations_str}
  }};

  napi_value constructor;
  napi_define_class (env, "{klass.name}", NAPI_AUTO_LENGTH, {class_cprefix}_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);
  napi_create_reference (env, constructor, 1, &{class_cprefix}_constructor);

  napi_set_named_property (env, exports, "{klass.name}", constructor);{resource_name_declaration}{tsfn_initializations_str}
}}
"""

def generate_class_conversion_functions(klass: Class) -> str:
    class_cprefix = klass.c_symbol_prefix

    def calculate_indent(suffix: str) -> str:
        return " " * (len(class_cprefix) + len(suffix) + 2)

    from_value_function = f"""
static gboolean
{class_cprefix}_from_value (napi_env env,
{calculate_indent("_from_value")}napi_value value,
{calculate_indent("_from_value")}{klass.c_type} ** result)
{{
  napi_status status;
  bool is_instance;
  {klass.c_type} * handle;

  status = napi_check_object_type_tag (env, value, &{class_cprefix}_type_tag, &is_instance);
  if (status != napi_ok || !is_instance)
  {{
    napi_throw_type_error (env, NULL, "expected an instance of {klass.name}");
    return FALSE;
  }}

  napi_unwrap (env, value, (void **) &handle);

  g_object_ref (handle);
  *result = handle;

  return TRUE;
}}
"""

    to_value_function = f"""
static napi_value
{class_cprefix}_to_value (napi_env env,
{calculate_indent("_to_value")}{klass.c_type} * handle)
{{
  napi_value result, constructor, handle_wrapper;

  napi_get_reference_value (env, {class_cprefix}_constructor, &constructor);

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}}
"""

    return from_value_function + to_value_function

def generate_constructor(klass: Class) -> str:
    class_cprefix = klass.c_symbol_prefix

    def calculate_indent(suffix: str) -> str:
        return " " * (len(class_cprefix) + len(suffix) + 2)

    default_constructor = next((ctor for ctor in klass.constructors if not ctor.parameters), None)
    if default_constructor is not None:
        return f"""
static napi_value
{class_cprefix}_construct (napi_env env,
{calculate_indent("_construct")}napi_callback_info info)
{{
  size_t argc = 0;
  napi_value jsthis;
  napi_status status;
  {klass.c_type} * handle;

  status = napi_get_cb_info (env, info, &argc, NULL, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  handle = {default_constructor.c_identifier} ();

  status = napi_type_tag_object (env, jsthis, &{class_cprefix}_type_tag);
  if (status != napi_ok)
    return NULL;

  status = napi_wrap (env, jsthis, handle, NULL, NULL, NULL);
  if (status != napi_ok)
    return NULL;

  return jsthis;
}}
"""
    else:
        return f"""
static napi_value
{class_cprefix}_construct (napi_env env,
{calculate_indent("_construct")}napi_callback_info info)
{{
  napi_throw_error (env, NULL, "class {klass.name} cannot be constructed because it lacks a default constructor");
  return NULL;
}}
"""

def generate_method_code(klass: Class, method: Method) -> str:
    operation_type_name = method.operation_type_name
    class_cprefix = klass.c_symbol_prefix

    invalid_arg_label = "invalid_argument" if method.is_async else "beach"
    param_conversions = [generate_parameter_conversion_code(param, i, invalid_arg_label) for i, param in enumerate(method.parameters)]
    param_frees = [f"g_free (operation->{param.name});" for param in method.parameters if param.type.name == "utf8"]
    param_frees_str = "\n  " + "\n  ".join(param_frees) if param_frees else ""

    return_assignment = f"\n\n  operation->return_value = " if method.return_type is not None else ""
    if method.return_type is not None:
        return_conversion = f"result = fdn_{method.return_type.nick}_to_value (env, operation->return_value);"
    else:
        return_conversion = "napi_get_undefined (env, &result);"
    return_frees_str = f"\n  g_free (operation->return_value);" if method.return_type is not None and method.return_type.name == "utf8" else ""

    def calculate_indent(suffix: str) -> str:
        return " " * (len(class_cprefix) + 1 + len(method.name) + len(suffix) + 2)

    if method.is_async:
        param_conversions_str = "\n\n" + "\n\n".join(param_conversions)
        operation_free_function = f"""\
static void
{class_cprefix}_{method.name}_operation_free ({operation_type_name} * operation)
{{{param_frees_str}{return_frees_str}
  g_slice_free ({operation_type_name}, operation);
}}"""

        code = f"""
static napi_value
{class_cprefix}_{method.name} (napi_env env,
{calculate_indent('')}napi_callback_info info)
{{
  size_t argc = {len(method.parameters)};
  napi_value args[{len(method.parameters)}];
  napi_status status;
  napi_value jsthis;
  {klass.c_type} * handle;
  napi_deferred deferred;
  napi_value promise;
  {operation_type_name} * operation;
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

  operation = g_slice_new0 ({operation_type_name});
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;{param_conversions_str}

  source = g_idle_source_new ();
  g_source_set_callback (source, {class_cprefix}_{method.name}_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, {class_cprefix}_{method.name}_tsfn);

  return promise;

invalid_argument:
  {{
    napi_reject_deferred (env, deferred, NULL);
    {class_cprefix}_{method.name}_operation_free (operation);
    return NULL;
  }}
}}

static gboolean
{class_cprefix}_{method.name}_begin (gpointer user_data)
{{
  {operation_type_name} * operation = user_data;

  {method.c_identifier} (operation->handle,
      {", ".join([f"operation->{param.name}" for param in method.parameters])},
      {class_cprefix}_{method.name}_end, operation);

  return G_SOURCE_REMOVE;
}}

static void
{class_cprefix}_{method.name}_end (GObject * source_object,
{calculate_indent("_end")}GAsyncResult * res,
{calculate_indent("_end")}gpointer user_data)
{{
  {operation_type_name} * operation = user_data;

  {return_assignment}{method.c_identifier}_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function ({class_cprefix}_{method.name}_tsfn, operation, napi_tsfn_blocking);
}}

static void
{class_cprefix}_{method.name}_deliver (napi_env env,
{calculate_indent("_deliver")}napi_value js_cb,
{calculate_indent("_deliver")}void * context,
{calculate_indent("_deliver")}void * data)
{{
  {operation_type_name} * operation = data;

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
    napi_value result;
    {return_conversion}
    napi_resolve_deferred (env, operation->deferred, result);
  }}

  {class_cprefix}_{method.name}_operation_free (operation);

  napi_unref_threadsafe_function (env, {class_cprefix}_{method.name}_tsfn);
}}

{operation_free_function}
"""
    else:
        param_declarations = [f"{param.type.c} {param.name}{" = " + param.type.default_value if param.type.default_value is not None else ""};"
                              for param in method.parameters]
        if method.throws:
            param_declarations.append("GError * error = NULL;")
        param_declarations_str = "\n  " + "\n  ".join(param_declarations) if param_declarations else ""

        if param_conversions:
            param_conversions_str_sync = "\n\n" + "\n".join([
                line.replace("operation->", "")
                for line in param_conversions
            ])
        else:
            param_conversions_str_sync = ""

        param_frees_str = param_frees_str.replace("operation->", "")

        param_call_names = [param.name for param in method.parameters]
        if method.throws:
            param_call_names.append("&error")
        param_call_str = ", " + ", ".join(param_call_names) if param_call_names else ""

        if method.throws:
            error_check = """if (error != NULL)
  {
    napi_throw_error (env, NULL, error->message);
    g_error_free (error);
    return NULL;
  }

  """
        else:
            error_check = ""

        return_variable_declaration = f"\n  {method.return_type.c} return_value;" if method.return_type is not None else ""
        return_assignment = return_assignment.replace("operation->", "").lstrip()
        return_conversion = return_conversion.replace("operation->", "")

        code = f"""
static napi_value
{class_cprefix}_{method.name} (napi_env env,
{calculate_indent('')}napi_callback_info info)
{{
  napi_value result = NULL;
  size_t argc = {len(method.parameters)};
  napi_value args[{len(method.parameters)}];
  napi_status status;
  napi_value jsthis;
  {klass.c_type} * handle;{param_declarations_str}{return_variable_declaration}

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    goto beach;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    goto beach;{param_conversions_str_sync}

  {return_assignment}{method.c_identifier} (handle{param_call_str});

  {error_check}{return_conversion}

beach:{param_frees_str}
  return result;
}}
"""
    return code

def generate_parameter_conversion_code(param: Parameter, index: int, invalid_arg_label: str) -> str:
    code = f"""\
  if (argc > {index})
  {{
    if (!fdn_{param.type.nick}_from_value (env, args[{index}], &operation->{param.name}))
      goto {invalid_arg_label};
  }}
  else
  {{
"""

    if param.nullable:
        code += f"    operation->{param.name} = NULL;"
    else:
        code += f"""    napi_throw_type_error (env, NULL, "missing argument: {to_camel_case(param.name)}");
    goto {invalid_arg_label};"""

    code += "\n  }"

    return code

def generate_enum_conversion_functions(enum: Enumeration) -> str:
    enum_name_snake = to_snake_case(enum.name)

    def calculate_indent(suffix: str) -> str:
        return " " * (4 + len(enum_name_snake) + len(suffix) + 2)

    return f"""
static gboolean
fdn_{enum_name_snake}_from_value (napi_env env,
{calculate_indent("_from_value")}napi_value value,
{calculate_indent("_from_value")}{enum.c_type} * result)
{{
  return fdn_enum_from_value (env, {enum.get_type} (), value, (gint *) result);
}}

static napi_value
fdn_{enum_name_snake}_to_value (napi_env env,
{calculate_indent("_to_value")}{enum.c_type} value)
{{
  return fdn_enum_to_value (env, {enum.get_type} (), value);
}}
"""

def generate_builtin_conversion_helpers() -> str:
    return """
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
fdn_int64_from_value (napi_env env,
                      napi_value value,
                      gint64 * result)
{
  int64_t number;

  if (napi_get_value_int64 (env, value, &number) != napi_ok)
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
fdn_int64_to_value (napi_env env,
                    gint64 value)
{
  napi_value result;
  napi_create_int64 (env, value, &result);
  return result;
}

static gboolean
fdn_uint64_from_value (napi_env env,
                       napi_value value,
                       guint64 * result)
{
  double number;

  if (napi_get_value_double (env, value, &number) != napi_ok)
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
fdn_uint64_to_value (napi_env env,
                     guint64 value)
{
  napi_value result;
  napi_create_double (env, value, &result);
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

static napi_value
fdn_double_to_value (napi_env env,
                     gdouble value)
{
  napi_value result;
  napi_create_double (env, value, &result);
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

static gboolean
fdn_vardict_from_value (napi_env env,
                        napi_value value,
                        GHashTable ** result)
{
  napi_value keys;
  uint32_t length, i;
  GHashTable * vardict = NULL;
  gchar * key = NULL;

  if (napi_get_property_names (env, value, &keys) != napi_ok)
    goto invalid_argument;
  if (napi_get_array_length (env, keys, &length) != napi_ok)
    goto propagate_error;

  vardict = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, (GDestroyNotify) g_variant_unref);

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

    g_hash_table_insert (vardict, g_steal_pointer (&key), val);
  }

  *result = vardict;
  return TRUE;

invalid_argument:
  {
    napi_throw_error (env, NULL, "expected a vardict");
    goto propagate_error;
  }
propagate_error:
  {
    g_free (key);
    g_clear_pointer (&vardict, g_hash_table_unref);
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
                        GVariant ** result)
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

      *result = g_variant_new_boolean (b);
      return TRUE;
    }
    case napi_number:
    {
      gint64 i;

      if (!fdn_int64_from_value (env, value, &i))
        return FALSE;

      *result = g_variant_new_int64 (i);
      return TRUE;
    }
    case napi_string:
    {
      gchar * str;

      if (!fdn_utf8_from_value (env, value, &str))
        return FALSE;

      *result = g_variant_new_take_string (str);
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
        *result = g_variant_new_from_data (G_VARIANT_TYPE_BYTESTRING, copy, size, TRUE, g_free, copy);
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

            *result = g_variant_new_tuple (t, G_N_ELEMENTS (t));
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

        *result = g_variant_builder_end (&builder);
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

      *result = g_variant_builder_end (&builder);
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
"""

def to_snake_case(name: str) -> str:
    result = []
    i = 0
    n = len(name)
    while i < n:
        if name[i].isupper():
            if i > 0:
                result.append('_')
            start = i
            if i + 1 < n and name[i + 1].islower():
                while i + 1 < n and name[i + 1].islower():
                    i += 1
            else:
                while i + 1 < n and name[i + 1].isupper():
                    i += 1
                if i + 1 < n:
                    i -= 1
            result.append(name[start:i + 1].lower())
        else:
            result.append(name[i])
        i += 1
    return "".join(result)

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
    code = generate_code()
    print(code)
