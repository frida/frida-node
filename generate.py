from __future__ import annotations
from collections import OrderedDict
from dataclasses import dataclass
from functools import cached_property
from pathlib import Path
from typing import Callable, List, Optional
import uuid
import xml.etree.ElementTree as ET

GIR_NAMESPACES = {"": "http://www.gtk.org/introspection/core/1.0"}
C_NAMESPACE = "http://www.gtk.org/introspection/c/1.0"

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

            param_list = []
            for param in parameters:
                param_name = param.get("name")
                type = parse_type(param.find("type", ns))
                param_list.append(Parameter(param_name, type))

            constructors.append(Constructor(constructor_name, c_identifier, param_list))
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
            is_async = any(param.find("type", GIR_NAMESPACES).get("name") == "Gio.AsyncReadyCallback" for param in parameters)

            result_element = next((m for m in self._methods if m.get("name") == f"{method_name}_finish")) if is_async else method_element
            return_type = parse_type(result_element.find(".//return-value/type", GIR_NAMESPACES))

            param_list = []
            for param in parameters:
                param_name = param.get("name")
                if param_name.startswith("_"):
                    continue
                type = parse_type(param.find("type", GIR_NAMESPACES))
                nullable = param.get("nullable") == "1"
                param_list.append(Parameter(param_name, type, nullable))

            methods.append(Method(transformed_method_name, c_identifier, return_type, param_list, throws, is_async, self))
        return methods

@dataclass
class Constructor:
    name: str
    c_identifier: str
    parameters: List[Parameter]

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

MethodFilter = Callable[[str, str], bool]
MethodNameTransformer = Callable[[str, str], str]

def parse_gir(file_path: str,
              method_filter: Optional[MethodFilter] = None,
              method_name_transformer: Optional[MethodNameTransformer] = None) -> OrderedDict[str, Class]:
    tree = ET.parse(file_path)

    classes = OrderedDict()

    for klass_element in tree.getroot().findall(".//class", GIR_NAMESPACES):
        class_name = klass_element.get("name")
        class_c_type = klass_element.get(f"{{{C_NAMESPACE}}}type")
        constructors = klass_element.findall(".//constructor", GIR_NAMESPACES)
        methods = klass_element.findall(".//method", GIR_NAMESPACES)

        classes[class_name] = Class(class_name, class_c_type, constructors, methods, method_filter, method_name_transformer)

    return classes

def parse_type(type_element: ET.Element) -> Optional[Type]:
    name = type_element.get("name")
    if name == "none":
        return None
    nick = type_nick_from_name(name)
    c = type_element.get(f"{{{C_NAMESPACE}}}type").replace("const ", "").replace("*", " *")
    return Type(name, nick, c)

def type_nick_from_name(name: str) -> str:
    if name == "GLib.PollFD":
        return "pollfd"
    tokens = name.split(".", maxsplit=1)
    if len(tokens) == 1:
        result = tokens[0]
        if result.startswith("g"):
            result = result[1:]
        return result
    return to_snake_case(tokens[1])

def generate_code() -> str:
    srcroot = Path(__file__).parent
    frida_classes = parse_gir(srcroot / "frida-core.gir")

    gio_classes = parse_gir(srcroot / "Gio-2.0.gir",
                            method_filter=filter_gio_methods,
                            method_name_transformer=transform_gio_method_name)

    classes = [
        frida_classes["DeviceManager"],
        frida_classes["Device"],
        gio_classes["Cancellable"],
    ]

    code = generate_includes()
    code += generate_operation_structs(classes)
    code += generate_prototypes(classes)
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

def generate_prototypes(classes: List[Class]) -> str:
    prototypes = []
    for klass in classes:
        class_cprefix = klass.c_symbol_prefix
        prototypes += [
            "",
            f"static void {class_cprefix}_register (napi_env env, napi_value exports);",
            f"static gboolean {class_cprefix}_from_value (napi_env env, napi_value value, {klass.c_type} ** result);",
            f"static napi_value {class_cprefix}_to_value (napi_env env, {klass.c_type} * handle);",
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

    prototypes += [
        "",
        "static napi_value fdn_boolean_to_value (napi_env env, gboolean value);",
        "static gboolean fdn_int_from_value (napi_env env, napi_value value, gint * result);",
        "static napi_value fdn_int_to_value (napi_env env, gint value);",
        "static gboolean fdn_ulong_from_value (napi_env env, napi_value value, gulong * result);",
        "static gboolean fdn_utf8_from_value (napi_env env, napi_value value, gchar ** str);",
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
{calculate_indent('_register')}napi_value exports)
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
{calculate_indent('_construct')}napi_callback_info info)
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
{calculate_indent('_construct')}napi_callback_info info)
{{
  napi_throw_error (env, NULL, "class {klass.name} cannot be constructed because it lacks a default constructor");
  return NULL;
}}
"""

def generate_method_code(klass: Class, method: Method) -> str:
    operation_type_name = method.operation_type_name
    class_cprefix = klass.c_symbol_prefix

    param_conversions = [generate_parameter_conversion_code(param, i) for i, param in enumerate(method.parameters)]
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
{calculate_indent('_end')}GAsyncResult * res,
{calculate_indent('_end')}gpointer user_data)
{{
  {operation_type_name} * operation = user_data;

  {return_assignment}{method.c_identifier}_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function ({class_cprefix}_{method.name}_tsfn, operation, napi_tsfn_blocking);
}}

static void
{class_cprefix}_{method.name}_deliver (napi_env env,
{calculate_indent('_deliver')}napi_value js_cb,
{calculate_indent('_deliver')}void * context,
{calculate_indent('_deliver')}void * data)
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
        param_declarations = [f"{param.type.c} {param.name};" for param in method.parameters]
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

        param_call_names = [param.name for param in method.parameters]
        if method.throws:
            param_call_names.append("&error")
        param_call_str = ", " + ", ".join(param_call_names) if param_call_names else ""

        if method.parameters:
            invalid_argument_label = f"""

invalid_argument:
  {{
    {param_frees_str}return NULL;
  }}"""
        else:
            invalid_argument_label = ""

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
  napi_value result;
  size_t argc = {len(method.parameters)};
  napi_value args[{len(method.parameters)}];
  napi_status status;
  napi_value jsthis;
  {klass.c_type} * handle;{param_declarations_str}{return_variable_declaration}

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;{param_conversions_str_sync}

  {return_assignment}{method.c_identifier} (handle{param_call_str});

  {param_frees_str}{error_check}{return_conversion}

  return result;{invalid_argument_label}
}}
"""
    return code

def generate_parameter_conversion_code(param: Parameter, index: int) -> str:
    code = f"""\
  if (argc > {index})
  {{
    if (!fdn_{param.type.nick}_from_value (env, args[{index}], &operation->{param.name}))
      goto invalid_argument;
  }}
  else
  {{
"""

    if param.nullable:
        code += f"    operation->{param.name} = NULL;"
    else:
        code += f"""    napi_throw_type_error (env, NULL, "missing argument: {to_camel_case(param.name)}");
    goto invalid_argument;"""
        
    code += "\n  }"

    return code

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
}"""

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
    code = generate_code()
    print(code)