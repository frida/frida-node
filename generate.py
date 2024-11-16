from __future__ import annotations
from collections import OrderedDict
from dataclasses import dataclass
from functools import cached_property
from pathlib import Path
from typing import Dict, List, Optional
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

    @property
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
            if method_name.startswith("_") or method_name.endswith("_sync") or method_name.endswith("_finish"):
                continue

            c_identifier = method_element.get(f"{{{C_NAMESPACE}}}identifier")
            parameters = method_element.findall("./parameters/parameter", GIR_NAMESPACES)
            has_closure_param = any((param.get("closure") == "1" for param in parameters))
            if has_closure_param:
                continue
            is_async = any(param.find("type", GIR_NAMESPACES).get("name") == "Gio.AsyncReadyCallback" for param in parameters)

            result_element = next((m for m in self._methods if m.get("name") == f"{method_name}_finish")) if is_async else method_element
            return_type = parse_type(result_element.find(".//return-value/type", GIR_NAMESPACES))

            param_list = []
            for param in parameters:
                param_name = param.get("name")
                if param_name.startswith("_"):
                    continue
                type = parse_type(param.find("type", GIR_NAMESPACES))
                param_list.append(Parameter(param_name, type))

            methods.append(Method(method_name, c_identifier, return_type, param_list, is_async))
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
    is_async: bool

@dataclass
class Parameter:
    name: str
    type: Type

@dataclass
class Type:
    name: str
    c: str
    napi: str

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

def parse_gir(file_path: str) -> OrderedDict[str, Class]:
    tree = ET.parse(file_path)

    classes = OrderedDict()

    for klass_element in tree.getroot().findall(".//class", GIR_NAMESPACES):
        class_name = klass_element.get("name")
        class_c_type = klass_element.get(f"{{{C_NAMESPACE}}}type")
        constructors = klass_element.findall(".//constructor", GIR_NAMESPACES)
        methods = klass_element.findall(".//method", GIR_NAMESPACES)

        classes[class_name] = Class(class_name, class_c_type, constructors, methods)

    return classes

def parse_type(type_element: ET.Element) -> Optional[Type]:
    name = type_element.get("name")
    if name == "none":
        return None
    c = type_element.get(f"{{{C_NAMESPACE}}}type").replace("*", " *")
    napi = node_api_types.get(name, "unknown")
    return Type(name, c, napi)

def generate_code() -> str:
    code = generate_includes()

    srcroot = Path(__file__).parent
    gio_classes = parse_gir(srcroot / "Gio-2.0.gir")

    classes = [gio_classes["Cancellable"]]
    classes += [klass for klass in parse_gir(srcroot / "frida-core.gir").values() if klass.name in {"DeviceManager"}]

    code += generate_operation_structs(classes)

    code += generate_prototypes(classes)

    code += generate_type_tags(classes)

    code += generate_tsfn_declarations(classes)

    code += generate_init_function(classes)

    for klass in classes:
        code += generate_registration_code(klass)
        code += generate_constructor(klass)

        for method in klass.methods:
            code += generate_method_code(klass, method)

    return code

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
}} {klass.name}{to_pascal_case(method.name)}Operation;
""")
    return "\n".join(structs) + "\n"

def generate_prototypes(classes: List[Class]) -> str:
    prototypes = []
    for klass in classes:
        class_cprefix = to_snake_case(klass.name)
        prototypes += [
            "",
            f"static void {class_cprefix}_register (napi_env env, napi_value exports);",
            f"static napi_value {class_cprefix}_constructor (napi_env env, napi_callback_info info);",
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
                    f"static void {method_cprefix}_operation_free ({klass.name}{to_pascal_case(method.name)}Operation * operation);",
                ]

    return "\n".join(prototypes) + "\n\n"

def generate_type_tags(classes: List[Class]) -> str:
    type_tags = []
    for klass in classes:
        class_name_snake = to_snake_case(klass.name)
        uuid_str = uuid.uuid4().hex
        uuid_formatted = f"0x{uuid_str[:16]}, 0x{uuid_str[16:]}"
        type_tags.append(f"static napi_type_tag {class_name_snake}_type_tag = {{ {uuid_formatted} }};")
    return "\n".join(type_tags) + "\n"

def generate_tsfn_declarations(classes: List[Class]) -> str:
    declarations = []
    for klass in classes:
        class_name_snake = to_snake_case(klass.name)
        async_methods = [method for method in klass.methods if method.is_async]
        if async_methods:
            declarations.append("")
            for method in async_methods:
                declarations.append(f"static napi_threadsafe_function {class_name_snake}_{method.name}_tsfn;")
    return "\n".join(declarations) + "\n"

def generate_init_function(classes: List[Class]) -> str:
    registration_calls = "\n  ".join([f"{to_snake_case(klass.name)}_register (env, exports);" for klass in classes])
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
    class_name_snake = to_snake_case(klass.name)

    method_registrations = []
    tsfn_initializations = []

    for method in klass.methods:
        method_name_camel = to_camel_case(method.name)
        method_registrations.append(f"""{{ "{method_name_camel}", 0, {class_name_snake}_{method.name}, 0, 0, 0, napi_default, 0 }},""")
        if method.is_async:
            tsfn_initializations.append(f"""\
napi_create_string_utf8 (env, "{method_name_camel}", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, {class_name_snake}_{method.name}_deliver, &{class_name_snake}_{method.name}_tsfn);""")

    method_registrations_str = "\n    ".join(method_registrations)
    resource_name_declaration = "\n\n  napi_value resource_name;" if tsfn_initializations else ""
    tsfn_initializations_str = "\n\n  " + "\n\n  ".join(tsfn_initializations) if tsfn_initializations else ""

    def calculate_indent(suffix: str) -> str:
        return " " * (len(class_name_snake) + len(suffix) + 2)

    return f"""\
static void
{class_name_snake}_register (napi_env env,
{calculate_indent('_register')}napi_value exports)
{{
  napi_property_descriptor properties[] =
  {{
    {method_registrations_str}
  }};

  napi_value constructor;
  napi_define_class (env, "{klass.name}", NAPI_AUTO_LENGTH, {class_name_snake}_constructor, NULL, G_N_ELEMENTS (properties), properties, &constructor);

  napi_set_named_property (env, exports, "{klass.name}", constructor);{resource_name_declaration}{tsfn_initializations_str}
}}
"""

def generate_constructor(klass: Class) -> str:
    class_name_snake = to_snake_case(klass.name)

    def calculate_indent(suffix: str) -> str:
        return " " * (len(class_name_snake) + len(suffix) + 2)

    default_constructor = next((ctor for ctor in klass.constructors if not ctor.parameters), None)
    if default_constructor is not None:
        return f"""
static napi_value
{class_name_snake}_constructor (napi_env env,
{calculate_indent('_constructor')}napi_callback_info info)
{{
  size_t argc = 0;
  napi_value jsthis;
  napi_status status;
  {klass.c_type} * handle;

  status = napi_get_cb_info (env, info, &argc, NULL, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  handle = {default_constructor.c_identifier} ();

  status = napi_type_tag_object (env, jsthis, &{class_name_snake}_type_tag);
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
{class_name_snake}_constructor (napi_env env,
{calculate_indent('_constructor')}napi_callback_info info)
{{
  napi_throw_error (env, NULL, "class {klass.name} cannot be constructed because it lacks a default constructor");
  return NULL;
}}
"""

def generate_method_code(klass: Class, method: Method) -> str:
    method_name_pascal = to_pascal_case(method.name)
    class_name = klass.name
    class_name_snake = to_snake_case(class_name)

    param_conversions = [generate_parameter_conversion_code(param.name, param.type, i) for i, param in enumerate(method.parameters)]
    param_frees = [f"g_free (operation->{param.name});" for param in method.parameters if param.type.name == "utf8"]
    param_frees_str = "\n" + "\n  ".join(param_frees) if param_frees else ""

    return_assignment = f"\n\n  operation->return_value = " if method.return_type is not None else ""
    if method.return_type is not None:
        return_conversion = f"result = Runtime_ValueFrom{to_pascal_case(method.return_type.name)} (env, operation->return_value);"
    else:
        return_conversion = "napi_get_undefined (env, &result);"

    def calculate_indent(suffix: str) -> str:
        return " " * (len(class_name_snake) + 1 + len(method.name) + len(suffix) + 2)

    if method.is_async:
        param_conversions_str = "\n\n".join(param_conversions)
        operation_free_function = f"""\
static void
{class_name_snake}_{method.name}_operation_free ({class_name}{method_name_pascal}Operation * operation)
{{{param_frees_str}{f"\n  g_free (operation->return_value);" if method.return_type is not None and method.return_type.name == "utf8" else ""}
  g_slice_free ({class_name}{method_name_pascal}Operation, operation);
}}"""

        code = f"""
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

  source = g_idle_source_new ();
  g_source_set_callback (source, {class_name_snake}_{method.name}_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, {class_name_snake}_{method.name}_tsfn);

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

  {method.c_identifier} (operation->handle,
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

  {return_assignment}{method.c_identifier}_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function ({class_name_snake}_{method.name}_tsfn, operation, napi_tsfn_blocking);
}}

static void
{class_name_snake}_{method.name}_deliver (napi_env env,
{calculate_indent('_deliver')}napi_value js_cb,
{calculate_indent('_deliver')}void * context,
{calculate_indent('_deliver')}void * data)
{{
  {class_name}{method_name_pascal}Operation * operation = data;

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

  {class_name_snake}_{method.name}_operation_free (operation);

  napi_unref_threadsafe_function (env, {class_name_snake}_{method.name}_tsfn);
}}

{operation_free_function}
"""
    else:
        if param_conversions:
            param_conversions_str_sync = "\n\n" + "\n".join([
                line.replace("operation->", "")
                for line in param_conversions
            ])
        else:
            param_conversions_str_sync = ""

        if method.parameters:
            param_call_str = ", " + ", ".join([param.name for param in method.parameters])
        else:
            param_call_str = ""

        result_assignment = "napi_get_undefined (env, &result);" if method.return_type is None else f"result = Runtime_ValueFrom{to_pascal_case(method.return_type.name)} (env, ret);"

        if method.parameters:
            invalid_argument_label = f"""

invalid_argument:
  {{
    {param_frees_str}return NULL;
  }}
"""
        else:
            invalid_argument_label = ""

        code = f"""
static napi_value
{class_name_snake}_{method.name} (napi_env env,
{calculate_indent('')}napi_callback_info info)
{{
  size_t argc = {len(method.parameters)};
  napi_value args[{len(method.parameters)}];
  napi_status status;
  napi_value jsthis;
  {klass.c_type} * handle;
  napi_value result;

  status = napi_get_cb_info (env, info, &argc, args, &jsthis, NULL);
  if (status != napi_ok)
    return NULL;

  status = napi_unwrap (env, jsthis, (void **) &handle);
  if (status != napi_ok)
    return NULL;

  {param_conversions_str_sync}{return_assignment}{method.c_identifier} (handle{param_call_str});

  {result_assignment}{param_frees_str}

  return result;{invalid_argument_label}
}}
"""
    return code

def generate_parameter_conversion_code(param_name: str, param_type: Type, index: int) -> str:
    if param_type.name == "Gio.Cancellable":
        return f"""\
  if (argc > {index})
  {{
    status = napi_get_value_{param_type.napi} (env, args[{index}], &operation->{param_name});
    if (status != napi_ok)
    {{
      napi_throw_error (env, NULL, "failed to get argument value");
      goto invalid_argument;
    }}
  }}
  else
  {{
    operation->{param_name} = NULL;
  }}"""
    elif param_type.name == "utf8":
        return f"""\
  size_t {param_name}_length;
  status = napi_get_value_string_utf8 (env, args[{index}], NULL, 0, &{param_name}_length);
  if (status != napi_ok)
  {{
    napi_throw_error (env, NULL, "failed to get string length");
    goto invalid_argument;
  }}
  operation->{param_name} = g_malloc ({param_name}_length + 1);
  status = napi_get_value_string_utf8 (env, args[{index}], operation->{param_name}, {param_name}_length + 1, &{param_name}_length);
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
  status = napi_get_value_{param_type.napi} (env, args[{index}], &operation->{param_name});
  if (status != napi_ok)
  {{
    napi_throw_error (env, NULL, "failed to get argument value");
    goto invalid_argument;
  }}"""

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