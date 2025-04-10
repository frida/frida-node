from __future__ import annotations

import argparse
import sys
import uuid
import xml.etree.ElementTree as ET
from collections import defaultdict, OrderedDict
from dataclasses import dataclass, field
from enum import Enum
from functools import cached_property
from io import StringIO
from pathlib import Path
from typing import Callable, List, Mapping, Optional, Tuple, Union

CUSTOMIZATIONS: Mapping[str, ObjectTypeCustomizations] = {}

CORE_NAMESPACE = "http://www.gtk.org/introspection/core/1.0"
C_NAMESPACE = "http://www.gtk.org/introspection/c/1.0"
GLIB_NAMESPACE = "http://www.gtk.org/introspection/glib/1.0"
GIR_NAMESPACES = {"": CORE_NAMESPACE, "glib": GLIB_NAMESPACE}


@dataclass
class Model:
    object_types: OrderedDict[str, ObjectType]
    enumerations: OrderedDict[str, Enumeration]

    @cached_property
    def public_types(self) -> OrderedDict[str, Union[ObjectType, Enumeration]]:
        return OrderedDict(
            [(k, v) for k, v in self.object_types.items() if v.is_public]
            + list(self.enumerations.items())
        )


@dataclass
class ObjectType:
    name: str
    c_type: str
    parent: str
    _constructors: List[ET.Element]
    _methods: List[ET.Element]
    method_filter: Optional[MethodFilter]
    method_name_transformer: Optional[MethodNameTransformer]
    _properties: List[ET.Element]
    _signals: List[ET.Element]

    @cached_property
    def prefixed_name(self):
        return f"_{self.name}" if self.is_customized else self.name

    @property
    def is_public(self) -> bool:
        return not self.is_frida_list

    @cached_property
    def is_frida_list(self) -> bool:
        return self.c_type.startswith("Frida") and self.c_type.endswith("List")

    @property
    def is_customized(self) -> bool:
        return self.name in CUSTOMIZATIONS

    @property
    def customizations(self) -> Optional[ObjectTypeCustomizations]:
        return CUSTOMIZATIONS.get(self.name)

    @cached_property
    def c_symbol_prefix(self) -> str:
        return f"fdn_{to_snake_case(self.name)}"

    @cached_property
    def c_cast_macro(self) -> str:
        return to_macro_case(self.c_type)

    @cached_property
    def constructors(self) -> List[Constructor]:
        constructors = []
        for element in self._constructors:
            name = element.get("name")

            c_identifier, param_list, has_closure_param, throws, is_async = (
                extract_callable_details(element)
            )
            if has_closure_param or throws or is_async:
                continue

            constructors.append(Constructor(name, c_identifier, param_list, throws))
        return constructors

    @cached_property
    def methods(self) -> List[Method]:
        methods = []
        c_prop_names = {prop.c_name for prop in self.properties}
        for element in self._methods:
            name = element.get("name")
            if self.method_filter is not None and not self.method_filter(
                self.name, name
            ):
                continue
            if (
                name.startswith("_")
                or name.endswith("_sync")
                or name.endswith("_finish")
            ):
                continue
            transformed_method_name = (
                self.method_name_transformer(self.name, name)
                if self.method_name_transformer is not None
                else name
            )

            c_identifier, param_list, has_closure_param, throws, is_async = (
                extract_callable_details(element)
            )
            if has_closure_param:
                continue

            result_element = (
                next((m for m in self._methods if m.get("name") == f"{name}_finish"))
                if is_async
                else element
            )
            retval_element = result_element.find(".//return-value", GIR_NAMESPACES)
            rettype = extract_type_from_entity(retval_element)
            if rettype is not None:
                nullable = retval_element.get("nullable") == "1"

                ownership_val = retval_element.get("transfer-ownership")
                transfer_ownership = (
                    TransferOwnership[ownership_val]
                    if ownership_val is not None
                    else TransferOwnership.none
                )

                retval = ReturnValue(rettype, nullable, transfer_ownership)
            else:
                retval = None

            tokens = transformed_method_name.split("_", maxsplit=1)
            is_property_accessor = (
                len(tokens) == 2
                and tokens[0] in {"get", "set"}
                and tokens[1] in c_prop_names
            )

            methods.append(
                Method(
                    transformed_method_name,
                    c_identifier,
                    param_list,
                    retval,
                    throws,
                    is_async,
                    is_property_accessor,
                    self,
                )
            )
        return methods

    @cached_property
    def customized_methods(self) -> List[Method]:
        return [m for m in self.methods if m.is_customized]

    @cached_property
    def properties(self) -> List[Property]:
        properties = []
        for element in self._properties:
            name = element.get("name")
            c_name = name.replace("-", "_")
            properties.append(
                Property(
                    name,
                    c_name,
                    type=extract_type_from_entity(element),
                    writable=element.get("writable") == "1",
                    construct_only=element.get("construct-only") == "1",
                )
            )
        return properties

    @cached_property
    def signals(self) -> List[Signal]:
        signals = []
        for element in self._signals:
            name = element.get("name")
            c_name = name.replace("-", "_")
            param_list = extract_parameters(
                element.findall("./parameters/parameter", GIR_NAMESPACES)
            )
            signals.append(Signal(name, c_name, param_list, self))
        return signals

    @cached_property
    def customized_signals(self) -> List[Signal]:
        return [s for s in self.signals if s.is_customized]


@dataclass
class ObjectTypeCustomizations:
    methods: Mapping[str, MethodCustomizations] = field(default_factory=lambda: defaultdict(dict))
    signals: Mapping[str, SignalCustomizations] = field(default_factory=lambda: defaultdict(dict))


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
    parameters: List[Parameter]
    return_value: Optional[ReturnValue]
    throws: bool
    is_async: bool
    is_property_accessor: bool

    object_type: ObjectType

    @cached_property
    def js_name(self):
        return to_camel_case(self.name)

    @cached_property
    def prefixed_js_name(self):
        return f"_{self.js_name}" if self.is_customized else self.js_name

    @property
    def is_customized(self) -> bool:
        return self.customizations is not None

    @cached_property
    def customizations(self) -> Optional[MethodCustomizations]:
        type_customizations = self.object_type.customizations
        if type_customizations is None:
            return None
        return type_customizations.methods.get(self.name)

    @cached_property
    def operation_type_name(self) -> str:
        return f"Fdn{self.object_type.name}{to_pascal_case(self.name)}Operation"


@dataclass
class MethodCustomizations:
    param_typings: List[str]
    return_typing: str
    custom_logic: Optional[str] = None
    return_wrapper: Optional[str] = None


@dataclass
class Property:
    name: str
    c_name: str
    type: Type
    writable: bool
    construct_only: bool

    @cached_property
    def js_name(self):
        return to_camel_case(self.c_name)


@dataclass
class Signal:
    name: str
    c_name: str
    parameters: List[Parameter]

    object_type: ObjectType

    @cached_property
    def js_name(self):
        return to_camel_case(self.c_name)

    @cached_property
    def prefixed_js_name(self):
        return f"_{self.js_name}" if self.is_customized else self.js_name

    @cached_property
    def handler_type_name(self):
        # XXX: Special-cases to avoid breaking API:
        class_name = self.object_type.name
        if class_name == "DeviceManager":
            prefix = "Device"
        elif class_name == "Device":
            prefix = "Device" if self.name == "lost" else ""
        elif class_name == "PortalService":
            prefix = "Portal"
        elif class_name == "Cancellable":
            prefix = ""
        else:
            prefix = class_name
        return f"{prefix}{to_pascal_case(self.c_name)}Handler"

    @cached_property
    def typing(self):
        params = ", ".join([p.typing for p in self.parameters])
        return f"({params}) => void"

    @property
    def is_customized(self) -> bool:
        return self.customizations is not None

    @cached_property
    def customizations(self) -> Optional[SignalCustomizations]:
        type_customizations = self.object_type.customizations
        if type_customizations is None:
            return None
        return type_customizations.signals.get(self.name)


@dataclass
class SignalCustomizations:
    transform: Optional[Mapping[int, Tuple[str, str]]] = None


TransferOwnership = Enum("TransferOwnership", ["none", "full", "container"])


@dataclass
class Parameter:
    name: str
    type: Type
    nullable: bool
    transfer_ownership: TransferOwnership
    direction: Direction

    @cached_property
    def js_name(self):
        return to_camel_case(self.name)

    @cached_property
    def typing(self):
        t = f"{self.js_name}: {self.type.js}"
        if self.nullable:
            t += " | null"
        return t

    @cached_property
    def destroy_function(self) -> Optional[str]:
        return resolve_destroy_function(self.type)


@dataclass
class ReturnValue:
    type: Type
    nullable: bool
    transfer_ownership: TransferOwnership

    @cached_property
    def destroy_function(self) -> Optional[str]:
        if self.transfer_ownership == TransferOwnership.none:
            return None
        return resolve_destroy_function(self.type)


@dataclass
class Type:
    name: str
    nick: str
    c: str
    js: str
    default_value: Optional[str]


class Direction(Enum):
    IN = "in"
    OUT = "out"
    INOUT = "inout"


@dataclass
class Enumeration:
    name: str
    c_type: str
    get_type: str
    members: List[EnumerationMember]

    @property
    def prefixed_name(self):
        return self.name

    @property
    def is_customized(self):
        return False


@dataclass
class EnumerationMember:
    name: str

    @cached_property
    def js_name(self) -> str:
        return to_pascal_case(self.name)

    @cached_property
    def nick(self) -> str:
        return self.name.replace("_", "-")


MethodFilter = Callable[[str, str], bool]
MethodNameTransformer = Callable[[str, str], str]


def main():
    global CUSTOMIZATIONS

    CUSTOMIZATIONS = load_customizations()

    parser = argparse.ArgumentParser(
        description="Generate TypeScript and N-API bindings for Frida."
    )
    parser.add_argument(
        "--frida-gir",
        required=True,
        type=Path,
        help="Path to the Frida .gir file.",
    )
    parser.add_argument(
        "--gio-gir",
        required=True,
        type=Path,
        help="Path to the GIO .gir file.",
    )
    parser.add_argument(
        "--output-ts",
        required=True,
        type=Path,
        help="Path to the output TypeScript file.",
    )
    parser.add_argument(
        "--output-dts",
        required=True,
        type=Path,
        help="Path to the output TypeScript declaration file.",
    )
    parser.add_argument(
        "--output-c",
        required=True,
        type=Path,
        help="Path to the output C file for N-API bindings.",
    )

    args = parser.parse_args()

    model = compute_model(args.frida_gir, args.gio_gir)

    with OutputFile(args.output_ts) as output:
        output.write(generate_ts(model))
    with OutputFile(args.output_dts) as output:
        output.write(generate_napi_dts(model))
    with OutputFile(args.output_c) as output:
        output.write(generate_napi_bindings(model))


def load_customizations() -> Mapping[str, ObjectTypeCustomizations]:
    return {
        "Device": ObjectTypeCustomizations(
            methods={
                "attach": MethodCustomizations(
                    param_typings=[
                        "target: string | number",
                        "options?: SessionOptions",
                        "cancellable?: Cancellable",
                    ],
                    return_typing="Promise<Session>",
                    custom_logic="""
let pid: number;
if (typeof target === "string") {
    const processes = await this.enumerateProcesses(undefined, cancellable);
    const process = processes.find(p => p.name === target);
    if (process === undefined) {
        throw new Error(`Process "${target}" not found`);
    }
    pid = process.pid;
} else {
    pid = target;
}
""",
                ),
                "open_channel": MethodCustomizations(
                    param_typings=[
                        "address: string",
                        "cancellable?: Cancellable",
                    ],
                    return_typing="Promise<NodeJS.ReadableStream>",
                    return_wrapper="new IOStream",
                ),
            },
        ),
        "Bus": ObjectTypeCustomizations(
            methods={
                "post": MethodCustomizations(
                    param_typings=[
                        "message: any",
                        "data?: Buffer",
                    ],
                    return_typing="void",
                    custom_logic="const json = JSON.stringify(message);",
                ),
            },
            signals={
                "message": SignalCustomizations(
                    transform={
                        0: ("message: any", "JSON.parse"),
                    },
                ),
            },
        ),
        "Script": ObjectTypeCustomizations(
            methods={
                "post": MethodCustomizations(
                    param_typings=[
                        "message: any",
                        "data?: Buffer",
                    ],
                    return_typing="void",
                    custom_logic="const json = JSON.stringify(message);",
                ),
            },
            signals={
                "message": SignalCustomizations(
                    transform={
                        0: ("message: any", "JSON.parse"),
                    },
                ),
            },
        ),
        "PortalService": ObjectTypeCustomizations(
            methods={
                "post": MethodCustomizations(
                    param_typings=[
                        "connectionId: number",
                        "message: any",
                        "data?: Buffer",
                    ],
                    return_typing="void",
                    custom_logic="const json = JSON.stringify(message);",
                ),
                "narrowcast": MethodCustomizations(
                    param_typings=[
                        "tag: string",
                        "message: any",
                        "data?: Buffer",
                    ],
                    return_typing="void",
                    custom_logic="const json = JSON.stringify(message);",
                ),
                "broadcast": MethodCustomizations(
                    param_typings=[
                        "message: any",
                        "data?: Buffer",
                    ],
                    return_typing="void",
                    custom_logic="const json = JSON.stringify(message);",
                ),
            },
            signals={
                "message": SignalCustomizations(
                    transform={
                        1: ("message: any", "JSON.parse"),
                    },
                ),
            },
        ),
    }


def generate_ts(model: Model) -> str:
    type_imports = []
    for t in model.public_types.values():
        if not t.is_customized:
            type_imports.append(f"{t.name} as _{t.name}")
        if isinstance(t, ObjectType):
            for s in t.signals:
                type_imports.append(f"{s.handler_type_name} as _{s.handler_type_name}")
                if s.is_customized:
                    type_imports.append(f"_{s.handler_type_name} as __{s.handler_type_name}")

    lines = [
        'import bindings from "bindings";',
        "import type {",
        "    FridaBinding,",
        *[f"    {i}," for i in type_imports],
        "    Signal,",
        "    SignalHandler,",
        '} from "./frida_binding.d.ts";',
        'import { Duplex } from "stream";',
    ]

    lines.append(
        """
const binding: FridaBinding = bindings({
    bindings: "frida_binding",
    try: [
        ["module_root", "bindings"],
        [process.cwd(), "bindings"],
    ]
});

type SignalTransformer<
    Source extends SignalHandler,
    Target extends SignalHandler
> = (...args: Parameters<Source>) => Parameters<Target>;

type SignalFilter<H extends SignalHandler> = (args: Parameters<H>) => boolean;

interface SignalWrapperOptionsNoTransform<H extends SignalHandler> {
    transform?: undefined;
    filter?: SignalFilter<H>;
}

interface SignalWrapperOptionsTransform<
    Source extends SignalHandler,
    Target extends SignalHandler
> {
    transform: SignalTransformer<Source, Target>;
    filter?: SignalFilter<Target>;
}

type SignalWrapperOptions<
    Source extends SignalHandler,
    Target extends SignalHandler
> =
    | SignalWrapperOptionsNoTransform<Source & Target>
    | SignalWrapperOptionsTransform<Source, Target>;

class SignalWrapper<
    SourceHandler extends SignalHandler,
    TargetHandler extends SignalHandler
> {
    #source: Signal<SourceHandler>;

    #transform?: SignalTransformer<SourceHandler, TargetHandler>;

    #filter?: SignalFilter<any>;

    #map = new WeakMap<TargetHandler, SourceHandler>();

    constructor(
        source: Signal<SourceHandler>,
        options?: SignalWrapperOptions<SourceHandler, TargetHandler>
    ) {
        this.#source = source;

        if (options === undefined || options.transform === undefined) {
            this.#filter = options?.filter;
        } else {
            this.#transform = options.transform;
            this.#filter = options.filter;
        }
    }

    connect(targetHandler: TargetHandler): void {
        const transform = this.#transform;
        const filter = this.#filter;

        const wrappedHandler = ((...sourceArgs: Parameters<SourceHandler>) => {
            let targetArgs: Parameters<TargetHandler>;

            if (transform === undefined) {
                targetArgs = sourceArgs as unknown as Parameters<TargetHandler>;
            } else {
                targetArgs = transform(...sourceArgs);
            }

            if (filter !== undefined) {
                if (!filter(targetArgs)) {
                    return;
                }
            }

            targetHandler(...targetArgs);
        }) as SourceHandler;

        this.#map.set(targetHandler, wrappedHandler);
        this.#source.connect(wrappedHandler);
    }

    disconnect(targetHandler: TargetHandler): void {
        const wrappedHandler = this.#map.get(targetHandler);
        if (wrappedHandler !== undefined) {
            this.#source.disconnect(wrappedHandler);
            this.#map.delete(targetHandler);
        }
    }
}

class IOStream extends Duplex {
    #impl: any;
    #pending = new Set<Promise<void>>();

    #cancellable = new Cancellable();

    constructor(impl: any) {
        super({});

        this.#impl = impl;
    }

    async _destroy(error: Error | null, callback: (error: Error | null) => void): Promise<void> {
        this.#cancellable.cancel();

        for (const operation of this.#pending) {
            try {
                await operation;
            } catch (e) {
            }
        }

        try {
            await this.#impl.close();
        } catch (e) {
        }

        callback(error);
    }

    _read(size: number): void {
        const operation = this.#impl.read(size, this.#cancellable)
            .then((data: Buffer): void => {
                const isEof = data.length === 0;
                if (isEof) {
                    this.push(null);
                    return;
                }

                this.push(data);
            })
            .catch((error: Error): void => {
                if (this.#impl.isClosed) {
                    this.push(null);
                }
                this.emit("error", error);
            });
        this.track(operation);
    }

    _write(chunk: any, encoding: BufferEncoding, callback: (error?: Error | null) => void): void {
        let data: Buffer;
        if (Buffer.isBuffer(chunk)) {
            data = chunk;
        } else {
            data = Buffer.from(chunk, encoding);
        }

        const operation = this.#impl.write(data, this.#cancellable)
            .then((): void => {
                callback(null);
            })
            .catch((error: Error): void => {
                callback(error);
            });
        this.track(operation);
    }

    private track(operation: Promise<void>): void {
        this.#pending.add(operation);
        operation
            .catch(_ => {})
            .finally(() => {
                this.#pending.delete(operation);
            });
    }
}"""
    )

    for otype in model.object_types.values():
        if not otype.is_customized:
            continue

        lines += [
            "",
            f"export class {otype.name} extends binding._{otype.name} {{",
        ]

        num_members = 0

        for method in otype.customized_methods:
            custom = method.customizations

            maybe_async = "async " if method.is_async else ""
            maybe_await = "await " if method.is_async else ""

            if num_members != 0:
                lines.append("")
            lines.append(
                f"    {maybe_async}{method.js_name}({', '.join(custom.param_typings)}): {custom.return_typing} {{"
            )

            custom_logic = custom.custom_logic
            if custom_logic is not None:
                indent = " " * 8
                lines += [
                    indent + custom_logic.strip().replace("\n", "\n" + indent),
                    "",
                ]

            lines += [
                f"        const result = {maybe_await}this._{method.js_name}({', '.join(param.js_name for param in method.parameters)});",
                "",
            ]

            return_wrapper = custom.return_wrapper
            if return_wrapper is not None:
                lines.append(f"        return {return_wrapper}(result);")
            else:
                lines.append("        return result;")

            lines.append("    }")

            num_members += 1

        for signal in otype.customized_signals:
            customizations = signal.customizations

            option_lines = []

            transform = customizations.transform
            if transform is not None:
                param_typings = []
                transformed_params = []
                for i, param in enumerate(signal.parameters):
                    if transform is not None and i in transform:
                        transformed_name_and_type, transform_function = transform[i]
                        param_typings.append(transformed_name_and_type)
                        transformed_params.append(f"{transform_function}({param.js_name})")
                    else:
                        param_typings.append(f"{param.js_name}: {param.type.js}")
                        transformed_params.append(param.js_name)

                param_typings_str = ", ".join(param_typings)
                transformed_params_str = ", ".join(transformed_params)

                option_lines += [
                    f"transform({', '.join(p.js_name for p in signal.parameters)}) {{",
                    f"    return [{transformed_params_str}];",
                    f"}},",
                ]

            if num_members != 0:
                lines.append("")
            option_indent = 12 * " "
            lines += [
                f"    get {signal.js_name}(): Signal<_{signal.handler_type_name}> {{",
                f"        return new SignalWrapper<__{signal.handler_type_name}, _{signal.handler_type_name}>(this._{signal.js_name}, {{",
                *[option_indent + line for line in option_lines],
                f"        }});",
                f"    }}",
            ]

            num_members += 1

        lines += [
            "}",
            "",
            f"binding.{otype.name} = {otype.name};",
        ]

    lines += [
        "",
        "export const {",
    ]
    lines += [
        f"    {t.name}," for t in model.public_types.values() if not t.is_customized
    ]
    lines += [
        "} = binding;",
        "",
        "export default {",
    ]
    lines += [f"    {t}," for t in model.public_types.keys()]
    lines += [
        "};",
        "",
    ]
    for t in model.public_types.values():
        if not t.is_customized:
            lines.append(f"export type {t.name} = _{t.name};")
        if isinstance(t, ObjectType):
            lines += [f"export type {s.handler_type_name} = _{s.handler_type_name};" for s in t.signals]

    return "\n".join(lines)


def generate_napi_dts(model: Model) -> str:
    lines = [
        "export interface FridaBinding {",
    ]
    for t in model.public_types.values():
        if t.is_customized:
            lines.append(f"    {t.name}: typeof {t.name};")
        lines.append(f"    {t.prefixed_name}: typeof {t.prefixed_name};")
    lines.append("}")

    for otype in model.object_types.values():
        if not otype.is_public:
            continue

        if otype.is_customized:
            lines += [
                "",
                f"export class {otype.name} extends _{otype.name} {{",
            ]

            for method in otype.customized_methods:
                customizations = method.customizations
                params = ", ".join(customizations.param_typings)
                lines.append(
                    f"    {method.js_name}({params}): {customizations.return_typing};"
                )

            for signal in otype.customized_signals:
                lines.append(
                    f"    readonly {signal.js_name}: Signal<{signal.handler_type_name}>;"
                )

            lines.append("}")

            if otype.customized_signals:
                lines.append("")
                for signal in otype.customized_signals:
                    params = ", ".join(
                        signal.customizations.transform.get(i, (param.typing, ""))[0]
                        for i, param in enumerate(signal.parameters)
                    )
                    lines.append(f"export type {signal.handler_type_name} = ({params}) => void;")

        class_name = f"_{otype.name}" if otype.is_customized else otype.name
        lines += [
            "",
            f"export class {class_name} {{",
        ]

        if otype.constructors:
            constructor = otype.constructors[0]
            params = ", ".join(
                f"{param.js_name}: {param.type.js}" for param in constructor.parameters
            )
            lines.append(f"    constructor({params});")

        for method in otype.methods:
            if method.is_property_accessor:
                continue
            is_customized = method.is_customized
            visibility = "protected " if is_customized else ""
            method_name = f"_{method.js_name}" if is_customized else method.js_name
            params = ", ".join(
                f"{param.js_name}{'?' if param.nullable else ''}: {param.type.js}"
                for param in method.parameters
            )
            return_type = (
                method.return_value.type.js
                if method.return_value is not None
                else "void"
            )
            if method.is_async:
                return_type = f"Promise<{return_type}>"
            lines.append(f"    {visibility}{method_name}({params}): {return_type};")

        for prop in otype.properties:
            readonly = "readonly " if not prop.writable else ""
            lines.append(f"    {readonly}{prop.js_name}: {prop.type.js};")

        for signal in otype.signals:
            is_customized = signal.is_customized
            visibility = "protected " if is_customized else ""
            signal_name = f"_{signal.js_name}" if is_customized else signal.js_name
            handler_type_name = signal.handler_type_name
            if is_customized:
                handler_type_name = f"_{handler_type_name}"
            lines.append(
                f"    {visibility}readonly {signal_name}: Signal<{handler_type_name}>;"
            )

        lines.append("}")

        if otype.signals:
            lines.append("")
            for signal in otype.signals:
                handler_type_name = signal.handler_type_name
                if signal.is_customized:
                    handler_type_name = f"_{handler_type_name}"
                lines.append(f"export type {handler_type_name} = {signal.typing};")

    for enum in model.enumerations.values():
        members = ",\n    ".join(
            f'{member.js_name} = "{member.nick}"' for member in enum.members
        )
        lines += [
            "",
            f"export enum {enum.name} {{",
            f"    {members}",
            "}",
        ]

    lines += [
        "",
        "export class Signal<H extends SignalHandler> {",
        "    connect(handler: H): void;",
        "    disconnect(handler: H): void;",
        "}",
        "",
        "export type SignalHandler = (...args: any[]) => void;",
    ]

    return "\n".join(lines)


def generate_napi_bindings(model: Model) -> str:
    object_types = model.object_types.values()
    enumerations = model.enumerations.values()

    code = generate_includes()
    code += generate_operation_structs(object_types)
    code += generate_internal_types()
    code += generate_exports_ref_variable()
    code += generate_prototypes(object_types, enumerations)
    code += generate_type_tags(object_types)
    code += generate_constructor_declarations(object_types)
    code += generate_tsfn_declarations(object_types)
    code += generate_init_function(object_types, enumerations)

    for otype in object_types:
        if otype.is_frida_list:
            code += generate_list_conversion_functions(otype)
            continue

        code += generate_object_type_registration_code(otype)
        code += generate_object_type_conversion_functions(otype)
        code += generate_object_type_constructor(otype)

        for method in otype.methods:
            code += generate_method_code(otype, method)

        for signal in otype.signals:
            code += generate_signal_getter_code(otype, signal)

    for enum in enumerations:
        code += generate_enum_registration_code(enum)
        code += generate_enum_conversion_functions(enum)

    code += generate_builtin_conversion_helpers()

    return code


def compute_model(frida_gir: Path, gio_gir: Path) -> Model:
    frida = parse_gir(frida_gir)

    gio = parse_gir(
        gio_gir,
        method_filter=filter_gio_methods,
        method_name_transformer=transform_gio_method_name,
    )

    object_types = OrderedDict(
        [
            (name, otype)
            for name, otype in frida.object_types.items()
            if name not in {"ControlService", "RpcClient", "RpcPeer"}
        ]
    )
    # object_types["IOStream"] = gio.object_types["IOStream"]
    object_types["Cancellable"] = gio.object_types["Cancellable"]

    return Model(object_types, frida.enumerations)


def filter_gio_methods(object_type: str, method: str) -> bool:
    if object_type == "Cancellable" and method in {
        "make_pollfd",
        "release_fd",
        "source_new",
    }:
        return False
    return True


def transform_gio_method_name(object_type: str, name: str) -> str:
    if object_type == "Cancellable" and name == "set_error_if_cancelled":
        return "throw_if_cancelled"
    return name


def parse_gir(
    file_path: str,
    method_filter: Optional[MethodFilter] = None,
    method_name_transformer: Optional[MethodNameTransformer] = None,
) -> Model:
    tree = ET.parse(file_path)

    object_types = OrderedDict()

    for element in tree.getroot().findall(".//class", GIR_NAMESPACES):
        name = element.get("name")
        c_type = element.get(f"{{{C_NAMESPACE}}}type")
        parent = element.get("parent")
        constructors = element.findall(".//constructor", GIR_NAMESPACES)
        methods = element.findall(".//method", GIR_NAMESPACES)
        properties = element.findall(".//property", GIR_NAMESPACES)
        signals = element.findall(".//glib:signal", GIR_NAMESPACES)

        object_types[name] = ObjectType(
            name,
            c_type,
            parent,
            constructors,
            methods,
            method_filter,
            method_name_transformer,
            properties,
            signals,
        )

    for element in tree.getroot().findall(".//interface", GIR_NAMESPACES):
        name = element.get("name")
        c_type = element.get(f"{{{C_NAMESPACE}}}type")
        prereq = element.find(".//prerequisite", GIR_NAMESPACES)
        parent = prereq.get("name") if prereq is not None else ""
        constructors = []
        methods = element.findall(".//method", GIR_NAMESPACES)
        properties = element.findall(".//property", GIR_NAMESPACES)
        signals = element.findall(".//glib:signal", GIR_NAMESPACES)

        object_types[name] = ObjectType(
            name,
            c_type,
            parent,
            constructors,
            methods,
            method_filter,
            method_name_transformer,
            properties,
            signals,
        )

    enumerations = OrderedDict()

    for element in tree.getroot().findall(".//enumeration", GIR_NAMESPACES):
        if element.get(f"{{{GLIB_NAMESPACE}}}error-domain") is not None:
            continue
        enum_name = element.get("name")
        enum_c_type = element.get(f"{{{C_NAMESPACE}}}type")
        get_type = element.get(f"{{{GLIB_NAMESPACE}}}get-type")
        members = [
            EnumerationMember(member.get("name"))
            for member in element.findall(".//member", GIR_NAMESPACES)
        ]
        enumerations[enum_name] = Enumeration(enum_name, enum_c_type, get_type, members)

    return Model(object_types, enumerations)


def extract_callable_details(
    element: ET.Element,
) -> Tuple[str, List[Parameter], bool, bool, bool]:
    c_identifier = element.get(f"{{{C_NAMESPACE}}}identifier")

    parameters = element.findall("./parameters/parameter", GIR_NAMESPACES)
    param_list = extract_parameters(parameters)
    has_closure_param = any((param.get("closure") == "1" for param in parameters))

    throws = element.get("throws") == "1"

    is_async = any(
        param[0].get("name") == "Gio.AsyncReadyCallback" for param in parameters
    )

    return (c_identifier, param_list, has_closure_param, throws, is_async)


def extract_parameters(parameter_elements: List[ET.Element]) -> List[Parameter]:
    param_list = []
    for param in parameter_elements:
        param_name = param.get("name")
        if param_name.startswith("_"):
            continue

        type = extract_type_from_entity(param)

        nullable = param.get("nullable") == "1"

        ownership_val = param.get("transfer-ownership")
        transfer_ownership = (
            TransferOwnership[ownership_val]
            if ownership_val is not None
            else TransferOwnership.none
        )

        raw_direction = param.get("direction")
        direction = (
            Direction(raw_direction) if raw_direction is not None else Direction.IN
        )

        param_list.append(
            Parameter(param_name, type, nullable, transfer_ownership, direction)
        )
    return param_list


def extract_type_from_entity(parent_element: ET.Element) -> Optional[Type]:
    child = parent_element.find("type", GIR_NAMESPACES)
    if child is None:
        child = parent_element.find("array", GIR_NAMESPACES)
        assert child is not None
        element_type = extract_type_from_entity(child)
        assert element_type.name == "utf8", "only string arrays are supported for now"
        return Type("utf8[]", "strv", "gchar **", "string", "NULL")
    return parse_type(child)


def parse_type(element: ET.Element) -> Optional[Type]:
    name = element.get("name")
    if name == "none":
        return None
    nick = type_nick_from_name(name, element)
    c = element.get(f"{{{C_NAMESPACE}}}type").replace("*", " *")
    js = js_type_from_gir(name)
    return Type(name, nick, c, js, "NULL" if "*" in c else None)


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
        assert (
            key_type.name == "utf8" and value_type.name == "GLib.Variant"
        ), "only GHashTable<string, Variant> is supported for now"
        result = "vardict"

    return result


def js_type_from_gir(name: str) -> str:
    if name == "gboolean":
        return "boolean"
    if name in {"gint", "guint", "guint16", "gulong"}:
        return "number"
    if name == "utf8":
        return "string"
    if name == "utf8[]":
        return "string[]"
    if name == "GLib.Bytes":
        return "Buffer"
    if name == "GLib.HashTable":
        return "Object"
    if name == "GLib.Variant":
        return "any"
    if name == "Gio.TlsCertificate":
        return "string"
    if name in {"Gio.FileMonitorEvent", "Gio.IOStream", "Gio.SocketAddress"}:
        return "any"
    if name.startswith("Frida.") and name.endswith("List"):
        return name[6:-4] + "[]"
    return name.split(".")[-1]


def generate_includes() -> str:
    return """\
#include <frida-core.h>
#include <node_api.h>
#include <string.h>

"""


def generate_operation_structs(object_types: List[ObjectType]) -> str:
    structs = []
    for otype in object_types:
        for method in otype.methods:
            if method.is_async:
                param_declarations = [
                    f"{param.type.c.replace('const ', '')} {param.name};"
                    for param in method.parameters
                ]
                param_declarations_str = "\n  ".join(param_declarations)
                return_declaration = (
                    f"\n  {method.return_value.type.c} retval;"
                    if method.return_value is not None
                    else ""
                )
                structs.append(
                    f"""\
typedef struct {{
  napi_env env;
  napi_deferred deferred;
  {otype.c_type} * handle;
  GError * error;
  {param_declarations_str}{return_declaration}
}} {method.operation_type_name};
"""
                )
    return "\n".join(structs) + "\n"


def generate_internal_types() -> str:
    return """

typedef struct {
  GObject * handle;
  guint id;
  GSList * closures;
} FdnSignal;

typedef enum {
  FDN_SIGNAL_CLOSURE_OPEN,
  FDN_SIGNAL_CLOSURE_CLOSED,
} FdnSignalClosureState;

typedef struct {
  GClosure closure;
  FdnSignal * sig;
  napi_ref js_sig;
  FdnSignalClosureState state;
  napi_threadsafe_function tsfn;
  napi_ref handler;
  gulong handler_id;
} FdnSignalClosure;

typedef enum {
  FDN_SIGNAL_CLOSURE_MESSAGE_DESTROY,
  FDN_SIGNAL_CLOSURE_MESSAGE_MARSHAL,
} FdnSignalClosureMessageType;

typedef struct {
  napi_ref js_sig;
  napi_threadsafe_function tsfn;
  napi_ref handler;
} FdnSignalClosureMessageDestroy;

typedef struct {
  GArray * args;
} FdnSignalClosureMessageMarshal;

typedef struct {
  FdnSignalClosureMessageType type;
  union {
    FdnSignalClosureMessageDestroy destroy;
    FdnSignalClosureMessageMarshal marshal;
  } payload;
} FdnSignalClosureMessage;
"""


def generate_exports_ref_variable() -> str:
    return "\nstatic napi_ref fdn_exports;\n"


def generate_prototypes(
    object_types: List[ObjectType], enumerations: List[Enumeration]
) -> str:
    prototypes = []

    for otype in object_types:
        otype_cprefix = otype.c_symbol_prefix

        prototypes.append("")

        if not otype.is_frida_list:
            prototypes += [
                f"static void {otype_cprefix}_register (napi_env env, napi_value exports);",
                f"G_GNUC_UNUSED static gboolean {otype_cprefix}_from_value (napi_env env, napi_value value, {otype.c_type} ** handle);",
            ]

        prototypes += [
            f"G_GNUC_UNUSED static napi_value {otype_cprefix}_to_value (napi_env env, {otype.c_type} * handle);",
        ]

        if not otype.is_frida_list:
            prototypes += [
                f"static napi_value {otype_cprefix}_construct (napi_env env, napi_callback_info info);",
            ]

            for method in otype.methods:
                method_cprefix = f"{otype_cprefix}_{method.name}"
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

            for i, signal in enumerate(otype.signals):
                if i == 0:
                    prototypes.append("")
                prototypes.append(
                    f"static napi_value {otype_cprefix}_get_{signal.c_name}_signal (napi_env env, napi_callback_info info);"
                )

    for enum in enumerations:
        enum_name_snake = to_snake_case(enum.name)
        prototypes += [
            "",
            f"static void fdn_{enum_name_snake}_register (napi_env env, napi_value exports);",
            f"G_GNUC_UNUSED static gboolean fdn_{enum_name_snake}_from_value (napi_env env, napi_value value, {enum.c_type} * e);",
            f"G_GNUC_UNUSED static napi_value fdn_{enum_name_snake}_to_value (napi_env env, {enum.c_type} e);",
        ]

    prototypes += [
        "static gboolean fdn_is_undefined_or_null (napi_env env, napi_value value);",
        "static gboolean fdn_is_function (napi_env env, napi_value value);",
        "",
        "static gboolean fdn_boolean_from_value (napi_env env, napi_value value, gboolean * b);",
        "static napi_value fdn_boolean_to_value (napi_env env, gboolean b);",
        "static gboolean fdn_int_from_value (napi_env env, napi_value value, gint * i);",
        "static napi_value fdn_int_to_value (napi_env env, gint i);",
        "static gboolean fdn_uint_from_value (napi_env env, napi_value value, guint * u);",
        "static napi_value fdn_uint_to_value (napi_env env, guint u);",
        "static gboolean fdn_uint16_from_value (napi_env env, napi_value value, guint16 * u);",
        "static napi_value fdn_uint16_to_value (napi_env env, guint16 u);",
        "static gboolean fdn_int64_from_value (napi_env env, napi_value value, gint64 * i);",
        "static napi_value fdn_int64_to_value (napi_env env, gint64 i);",
        "static napi_value fdn_uint64_to_value (napi_env env, guint64 u);",
        "static gboolean fdn_ulong_from_value (napi_env env, napi_value value, gulong * u);",
        "static napi_value fdn_double_to_value (napi_env env, gdouble d);",
        "static gboolean fdn_enum_from_value (napi_env env, GType enum_type, napi_value value, gint * e);",
        "static napi_value fdn_enum_to_value (napi_env env, GType enum_type, gint e);",
        "static gboolean fdn_utf8_from_value (napi_env env, napi_value value, gchar ** str);",
        "static napi_value fdn_utf8_to_value (napi_env env, const gchar * str);",
        "static gboolean fdn_strv_from_value (napi_env env, napi_value value, gchar *** strv);",
        "static napi_value fdn_strv_to_value (napi_env env, gchar ** strv);",
        "static napi_value fdn_buffer_to_value (napi_env env, const guint8 * data, gsize size);",
        "static gboolean fdn_bytes_from_value (napi_env env, napi_value value, GBytes ** bytes);",
        "static napi_value fdn_bytes_to_value (napi_env env, GBytes * bytes);",
        "static gboolean fdn_vardict_from_value (napi_env env, napi_value value, GHashTable ** vardict);",
        "static napi_value fdn_vardict_to_value (napi_env env, GHashTable * vardict);",
        "static gboolean fdn_variant_from_value (napi_env env, napi_value value, GVariant ** variant);",
        "static napi_value fdn_variant_to_value (napi_env env, GVariant * variant);",
        "static napi_value fdn_gvalue_to_value (napi_env env, GValue * val);",
        "static gboolean fdn_file_from_value (napi_env env, napi_value value, GFile ** file);",
        "static napi_value fdn_file_to_value (napi_env env, GFile * file);",
        "static gboolean fdn_tls_certificate_from_value (napi_env env, napi_value value, GTlsCertificate ** certificate);",
        "static napi_value fdn_tls_certificate_to_value (napi_env env, GTlsCertificate * certificate);",
        # Temporary stubs for missing types:
        "static napi_value fdn_io_stream_to_value (napi_env env, GIOStream * stream);",
        "",
        "static void fdn_object_finalize (napi_env env, void * finalize_data, void * finalize_hint);",
        "static napi_value fdn_object_get_signal (napi_env env, napi_callback_info info, const gchar * name, const gchar * js_storage_name);",
        "",
        "static napi_value fdn_signal_new (napi_env env, GObject * handle, const gchar * name);",
        "static void fdn_signal_register (napi_env env, napi_value exports);",
        "static napi_value fdn_signal_construct (napi_env env, napi_callback_info info);",
        "static void fdn_signal_finalize (napi_env env, void * finalize_data, void * finalize_hint);",
        "static napi_value fdn_signal_connect (napi_env env, napi_callback_info info);",
        "static napi_value fdn_signal_disconnect (napi_env env, napi_callback_info info);",
        "static gboolean fdn_signal_parse_arguments (napi_env env, napi_callback_info info, FdnSignal ** self, napi_value * js_self, napi_value * handler);",
        "static FdnSignalClosure * fdn_signal_closure_new (napi_env env, FdnSignal * sig, napi_value js_sig, napi_value handler);",
        "static void fdn_signal_closure_finalize (gpointer data, GClosure * closure);",
        "static void fdn_signal_closure_marshal (GClosure * closure, GValue * return_gvalue, guint n_param_values, const GValue * param_values, gpointer invocation_hint, gpointer marshal_data);",
        "static void fdn_signal_closure_deliver (napi_env env, napi_value js_cb, void * context, void * data);",
    ]

    return "\n".join(prototypes) + "\n\n"


def generate_type_tags(object_types: List[ObjectType]) -> str:
    type_tags = [
        "static napi_type_tag fdn_handle_wrapper_type_tag = { 0xdd596d4f2dad45f9, 0x844585a48e8d05ba };"
    ]
    for otype in object_types:
        if otype.is_frida_list:
            continue
        uuid_str = uuid.uuid4().hex
        uuid_formatted = f"0x{uuid_str[:16]}, 0x{uuid_str[16:]}"
        type_tags.append(
            f"static napi_type_tag {otype.c_symbol_prefix}_type_tag = {{ {uuid_formatted} }};"
        )
    return "\n".join(type_tags) + "\n"


def generate_constructor_declarations(object_types: List[ObjectType]) -> str:
    declarations = []

    for otype in object_types:
        if otype.is_frida_list:
            continue
        declarations.append(f"static napi_ref {otype.c_symbol_prefix}_constructor;")

    declarations += [
        "",
        f"static napi_ref fdn_signal_constructor;",
    ]

    return "\n" + "\n".join(declarations) + "\n"


def generate_tsfn_declarations(object_types: List[ObjectType]) -> str:
    declarations = []
    for otype in object_types:
        async_methods = [method for method in otype.methods if method.is_async]
        if async_methods:
            declarations.append("")
            for method in async_methods:
                declarations.append(
                    f"static napi_threadsafe_function {otype.c_symbol_prefix}_{method.name}_tsfn;"
                )
    return "\n".join(declarations) + "\n"


def generate_init_function(
    object_types: List[ObjectType], enumerations: List[Enumeration]
) -> str:
    object_type_registration_calls = "\n  ".join(
        [
            f"{otype.c_symbol_prefix}_register (env, exports);"
            for otype in object_types
            if not otype.is_frida_list
        ]
    )

    enum_type_registration_calls = "\n  ".join(
        [
            f"fdn_{to_snake_case(enum.name)}_register (env, exports);"
            for enum in enumerations
        ]
    )

    return f"""
static napi_value
fdn_init (napi_env env,
          napi_value exports)
{{
  frida_init ();

  napi_create_reference (env, exports, 1, &fdn_exports);

  {object_type_registration_calls}

  {enum_type_registration_calls}

  fdn_signal_register (env, exports);

  return exports;
}}

NAPI_MODULE (NODE_GYP_MODULE_NAME, fdn_init)
"""


def generate_object_type_registration_code(otype: ObjectType) -> str:
    otype_cprefix = otype.c_symbol_prefix

    ctor_ref_creation = "" if otype.is_customized else f"\n  napi_create_reference (env, constructor, 1, &{otype_cprefix}_constructor);"
    jsprop_registrations = []
    tsfn_initializations = []

    for method in otype.methods:
        if method.is_property_accessor:
            continue
        jsprop_registrations.append(
            f"""{{ "{method.prefixed_js_name}", NULL, {otype_cprefix}_{method.name}, NULL, NULL, NULL, napi_default, NULL }},"""
        )
        if method.is_async:
            tsfn_initializations.append(
                f"""\
napi_create_string_utf8 (env, "{method.js_name}", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, NULL, {otype_cprefix}_{method.name}_deliver, &{otype_cprefix}_{method.name}_tsfn);
  napi_unref_threadsafe_function (env, {otype_cprefix}_{method.name}_tsfn);"""
            )

    for prop in otype.properties:
        has_setter = prop.writable and not prop.construct_only

        setter_str = f"{otype_cprefix}_set_{prop.c_name}" if has_setter else "NULL"

        attrs = ["enumerable", "configurable"]
        if has_setter:
            attrs.insert(0, "writable")
        attrs_str = " | ".join([f"napi_{attr}" for attr in attrs])

        jsprop_registrations.append(
            f"""{{ "{prop.js_name}", NULL, NULL, {otype_cprefix}_get_{prop.c_name}, {setter_str}, NULL, {attrs_str}, NULL }},"""
        )

    for signal in otype.signals:
        jsprop_registrations.append(
            f"""{{ "{signal.prefixed_js_name}", NULL, NULL, {otype_cprefix}_get_{signal.c_name}_signal, NULL, NULL, napi_default, NULL }},"""
        )

    jsprop_registrations_str = "\n    ".join(jsprop_registrations)
    resource_name_declaration = (
        "\n\n  napi_value resource_name;" if tsfn_initializations else ""
    )
    tsfn_initializations_str = (
        "\n\n  " + "\n\n  ".join(tsfn_initializations) if tsfn_initializations else ""
    )

    def calculate_indent(suffix: str) -> str:
        return " " * (len(otype_cprefix) + len(suffix) + 2)

    return f"""
static void
{otype_cprefix}_register (napi_env env,
{calculate_indent("_register")}napi_value exports)
{{
  napi_property_descriptor properties[] =
  {{
    {jsprop_registrations_str}
  }};

  napi_value constructor;
  napi_define_class (env, "{otype.prefixed_name}", NAPI_AUTO_LENGTH, {otype_cprefix}_construct, NULL, G_N_ELEMENTS (properties), properties, &constructor);{ctor_ref_creation}

  napi_set_named_property (env, exports, "{otype.prefixed_name}", constructor);{resource_name_declaration}{tsfn_initializations_str}
}}
"""


def generate_object_type_conversion_functions(otype: ObjectType) -> str:
    otype_cprefix = otype.c_symbol_prefix

    if otype.is_customized:
        ctor_lookup = "\n".join([
            f"if ({otype_cprefix}_constructor != NULL)",
            "  {",
            f"    napi_get_reference_value (env, {otype_cprefix}_constructor, &constructor);",
            "  }",
            "  else",
            "  {",
            "    napi_value exports;",
            "",
            "    napi_get_reference_value (env, fdn_exports, &exports);",
            f"    napi_get_named_property (env, exports, \"{otype.name}\", &constructor);",
            f"    napi_create_reference (env, constructor, 1, &{otype_cprefix}_constructor);",
            "  }",
        ])
    else:
        ctor_lookup = f"napi_get_reference_value (env, {otype_cprefix}_constructor, &constructor);"

    def calculate_indent(suffix: str) -> str:
        return " " * (len(otype_cprefix) + len(suffix) + 2)

    from_value_function = f"""
static gboolean
{otype_cprefix}_from_value (napi_env env,
{calculate_indent("_from_value")}napi_value value,
{calculate_indent("_from_value")}{otype.c_type} ** handle)
{{
  bool is_instance;

  if (napi_check_object_type_tag (env, value, &{otype_cprefix}_type_tag, &is_instance) != napi_ok || !is_instance)
  {{
    napi_throw_type_error (env, NULL, "expected an instance of {otype.name}");
    return FALSE;
  }}

  napi_unwrap (env, value, (void **) handle);

  g_object_ref (*handle);

  return TRUE;
}}
"""

    to_value_function = f"""
static napi_value
{otype_cprefix}_to_value (napi_env env,
{calculate_indent("_to_value")}{otype.c_type} * handle)
{{
  napi_value result, constructor, handle_wrapper;

  {ctor_lookup}

  napi_create_external (env, handle, NULL, NULL, &handle_wrapper);
  napi_type_tag_object (env, handle_wrapper, &fdn_handle_wrapper_type_tag);

  napi_new_instance (env, constructor, 1, &handle_wrapper, &result);

  return result;
}}
"""

    return from_value_function + to_value_function


def generate_object_type_constructor(otype: ObjectType) -> str:
    otype_cprefix = otype.c_symbol_prefix

    def calculate_indent(suffix: str) -> str:
        return " " * (len(otype_cprefix) + len(suffix) + 2)

    default_constructor = next(
        (ctor for ctor in otype.constructors if not ctor.parameters), None
    )

    if default_constructor is not None:
        default_call = f"handle = {default_constructor.c_identifier} ();"
    else:
        default_call = f'napi_throw_error (env, NULL, "type {otype.name} cannot be constructed because it lacks a default constructor");\n    return NULL;'

    return f"""
static napi_value
{otype_cprefix}_construct (napi_env env,
{calculate_indent("_construct")}napi_callback_info info)
{{
  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  {otype.c_type} * handle = NULL;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto propagate_error;

  if (argc == 0)
  {{
    {default_call}
  }}
  else
  {{
    bool is_instance;

    if (napi_check_object_type_tag (env, args[0], &fdn_handle_wrapper_type_tag, &is_instance) != napi_ok || !is_instance)
      goto invalid_handle;

    if (napi_get_value_external (env, args[0], (void **) &handle) != napi_ok)
      goto propagate_error;

    g_object_ref (handle);
  }}

  if (napi_type_tag_object (env, jsthis, &{otype_cprefix}_type_tag) != napi_ok)
    goto propagate_error;

  if (napi_wrap (env, jsthis, handle, NULL, NULL, NULL) != napi_ok)
    goto propagate_error;

  if (napi_add_finalizer (env, jsthis, handle, fdn_object_finalize, NULL, NULL) != napi_ok)
    goto propagate_error;

  return jsthis;

invalid_handle:
  {{
    napi_throw_type_error (env, NULL, "expected a {otype.name} handle");
    goto propagate_error;
  }}
propagate_error:
  {{
    g_clear_object (&handle);
    return NULL;
  }}
}}
"""


def generate_method_code(otype: ObjectType, method: Method) -> str:
    operation_type_name = method.operation_type_name
    otype_cprefix = otype.c_symbol_prefix

    invalid_arg_label = "invalid_argument" if method.is_async else "beach"
    input_params = [
        param for param in method.parameters if param.direction != Direction.OUT
    ]
    param_conversions = [
        generate_parameter_conversion_code(param, i, invalid_arg_label)
        for i, param in enumerate(input_params)
    ]
    param_destruction = [
        f"g_clear_pointer (&operation->{param.name}, {param.destroy_function});"
        for param in method.parameters
        if param.destroy_function is not None
    ]
    param_destruction_str = (
        "\n  " + "\n  ".join(param_destruction) if param_destruction else ""
    )

    return_assignment = (
        f"\n\n  operation->retval = " if method.return_value is not None else ""
    )
    if method.return_value is not None:
        return_conversion = f"js_retval = fdn_{method.return_value.type.nick}_to_value (env, operation->retval);"
        if method.return_value.nullable:
            return_conversion = f"if (operation->retval != NULL)\n    {return_conversion}\n  else\n    napi_get_null (env, &js_retval);"
    else:
        return_conversion = "napi_get_undefined (env, &js_retval);"
    retval = method.return_value
    return_destruction_str = (
        f"\n  g_clear_pointer (&operation->retval, {retval.destroy_function});"
        if retval is not None and retval.destroy_function is not None
        else ""
    )

    def calculate_indent(suffix: str) -> str:
        return " " * (len(otype_cprefix) + 1 + len(method.name) + len(suffix) + 2)

    if method.is_async:
        param_conversions_str = "\n\n" + "\n\n".join(param_conversions)
        return_conversion_str = return_conversion.replace("\n", "\n  ")
        operation_free_function = f"""\
static void
{otype_cprefix}_{method.name}_operation_free ({operation_type_name} * operation)
{{{param_destruction_str}{return_destruction_str}
  g_slice_free ({operation_type_name}, operation);
}}"""

        code = f"""
static napi_value
{otype_cprefix}_{method.name} (napi_env env,
{calculate_indent('')}napi_callback_info info)
{{
  size_t argc = {len(method.parameters)};
  napi_value args[{len(method.parameters)}];
  napi_value jsthis;
  {otype.c_type} * handle;
  napi_deferred deferred;
  napi_value promise;
  {operation_type_name} * operation;
  GSource * source;

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    return NULL;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    return NULL;

  napi_create_promise (env, &deferred, &promise);

  operation = g_slice_new0 ({operation_type_name});
  operation->env = env;
  operation->deferred = deferred;
  operation->handle = handle;
  operation->error = NULL;{param_conversions_str}

  source = g_idle_source_new ();
  g_source_set_callback (source, {otype_cprefix}_{method.name}_begin,
      operation, NULL);
  g_source_attach (source, frida_get_main_context ());
  g_source_unref (source);

  napi_ref_threadsafe_function (env, {otype_cprefix}_{method.name}_tsfn);

  return promise;

invalid_argument:
  {{
    napi_reject_deferred (env, deferred, NULL);
    {otype_cprefix}_{method.name}_operation_free (operation);
    return NULL;
  }}
}}

static gboolean
{otype_cprefix}_{method.name}_begin (gpointer user_data)
{{
  {operation_type_name} * operation = user_data;

  {method.c_identifier} (operation->handle,
      {", ".join([f"operation->{param.name}" for param in method.parameters])},
      {otype_cprefix}_{method.name}_end, operation);

  return G_SOURCE_REMOVE;
}}

static void
{otype_cprefix}_{method.name}_end (GObject * source_object,
{calculate_indent("_end")}GAsyncResult * res,
{calculate_indent("_end")}gpointer user_data)
{{
  {operation_type_name} * operation = user_data;

  {return_assignment}{method.c_identifier}_finish (operation->handle, res,
      &operation->error);

  napi_call_threadsafe_function ({otype_cprefix}_{method.name}_tsfn, operation, napi_tsfn_blocking);
}}

static void
{otype_cprefix}_{method.name}_deliver (napi_env env,
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
    napi_value js_retval;
    {return_conversion_str}
    napi_resolve_deferred (env, operation->deferred, js_retval);
  }}

  {otype_cprefix}_{method.name}_operation_free (operation);

  napi_unref_threadsafe_function (env, {otype_cprefix}_{method.name}_tsfn);
}}

{operation_free_function}
"""
    else:
        param_declarations = [
            f"{param.type.c.replace('const ', '')} {param.name}{' = ' + param.type.default_value if param.type.default_value is not None else ''};"
            for param in method.parameters
        ]
        if method.throws:
            param_declarations.append("GError * error = NULL;")
        param_declarations_str = (
            "\n  " + "\n  ".join(param_declarations) if param_declarations else ""
        )

        if param_conversions:
            param_conversions_str_sync = "\n\n" + "\n".join(
                [line.replace("operation->", "") for line in param_conversions]
            )
        else:
            param_conversions_str_sync = ""

        param_destruction_str = param_destruction_str.replace("operation->", "")

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

        return_variable_declaration = (
            f"\n  {method.return_value.type.c} retval;"
            if method.return_value is not None
            else ""
        )
        return_assignment = return_assignment.replace("operation->", "").lstrip()
        return_conversion = return_conversion.replace("operation->", "")

        code = f"""
static napi_value
{otype_cprefix}_{method.name} (napi_env env,
{calculate_indent('')}napi_callback_info info)
{{
  napi_value js_retval = NULL;
  size_t argc = {len(method.parameters)};
  napi_value args[{len(method.parameters)}];
  napi_value jsthis;
  {otype.c_type} * handle;{param_declarations_str}{return_variable_declaration}

  if (napi_get_cb_info (env, info, &argc, args, &jsthis, NULL) != napi_ok)
    goto beach;

  if (napi_unwrap (env, jsthis, (void **) &handle) != napi_ok)
    goto beach;{param_conversions_str_sync}

  {return_assignment}{method.c_identifier} (handle{param_call_str});

  {error_check}{return_conversion}

beach:{param_destruction_str}
  return js_retval;
}}
"""
    return code


def generate_parameter_conversion_code(
    param: Parameter, index: int, invalid_arg_label: str
) -> str:
    code = f"""\
  if (argc > {index} && !fdn_is_undefined_or_null (env, args[{index}]))
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
        code += f"""    napi_throw_type_error (env, NULL, "missing argument: {param.js_name}");
    goto {invalid_arg_label};"""

    code += "\n  }"

    return code


def generate_signal_getter_code(otype: ObjectType, signal: Signal) -> str:
    cprefix = otype.c_symbol_prefix

    indent = " " * (len(cprefix) + 5 + len(signal.c_name) + 9)

    return f"""
static napi_value
{cprefix}_get_{signal.c_name}_signal (napi_env env,
{indent}napi_callback_info info)
{{
  return fdn_object_get_signal (env, info, "{signal.name}", "_{signal.prefixed_js_name}");
}}
"""


def generate_enum_registration_code(enum: Enumeration) -> str:
    cprefix = f"fdn_{to_snake_case(enum.name)}"

    properties = []
    for member in enum.members:
        properties.append(
            f'{{ "{member.js_name}", NULL, NULL, NULL, NULL, fdn_utf8_to_value (env, "{member.nick}"), napi_enumerable, NULL }}'
        )

    properties_str = ",\n    ".join(properties)

    def calculate_indent(suffix: str) -> str:
        return " " * (len(cprefix) + len(suffix) + 2)

    return f"""
static void
{cprefix}_register (napi_env env,
{calculate_indent("_register")}napi_value exports)
{{
  napi_value enum_object;
  napi_property_descriptor properties[] = {{
    {properties_str}
  }};

  napi_create_object (env, &enum_object);
  napi_define_properties (env, enum_object, G_N_ELEMENTS (properties), properties);

  napi_set_named_property (env, exports, "{enum.name}", enum_object);
}}
"""


def generate_enum_conversion_functions(enum: Enumeration) -> str:
    name = to_snake_case(enum.name)

    def calculate_indent(suffix: str) -> str:
        return " " * (4 + len(name) + len(suffix) + 2)

    return f"""
static gboolean
fdn_{name}_from_value (napi_env env,
{calculate_indent("_from_value")}napi_value value,
{calculate_indent("_from_value")}{enum.c_type} * e)
{{
  return fdn_enum_from_value (env, {enum.get_type} (), value, (gint *) e);
}}

static napi_value
fdn_{name}_to_value (napi_env env,
{calculate_indent("_to_value")}{enum.c_type} e)
{{
  return fdn_enum_to_value (env, {enum.get_type} (), e);
}}
"""


def generate_list_conversion_functions(otype: ObjectType) -> str:
    cprefix = otype.c_symbol_prefix

    size_method = next((method for method in otype.methods if method.name == "size"))
    get_method = next((method for method in otype.methods if method.name == "get"))

    element_type = get_method.return_value.type

    def calculate_indent(suffix: str) -> str:
        return " " * (len(cprefix) + len(suffix) + 2)

    return f"""
static napi_value
{cprefix}_to_value (napi_env env,
{calculate_indent("_to_value")}{otype.c_type} * list)
{{
  napi_value result;
  gint size, i;

  size = {size_method.c_identifier} (list);
  napi_create_array_with_length (env, size, &result);

  for (i = 0; i != size; i++)
  {{
    {element_type.c} handle = {get_method.c_identifier} (list, i);
    napi_set_element (env, result, i, fdn_{element_type.nick}_to_value (env, handle));
    g_object_unref (handle);
  }}

  return result;
}}
"""


def generate_builtin_conversion_helpers() -> str:
    return """
static gboolean
fdn_is_undefined_or_null (napi_env env,
                          napi_value value)
{
  napi_valuetype type;

  napi_typeof (env, value, &type);

  return type == napi_undefined || type == napi_null;
}

static gboolean
fdn_is_function (napi_env env,
                 napi_value value)
{
  napi_valuetype type;

  napi_typeof (env, value, &type);

  return type == napi_function;
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

static napi_value
fdn_gvalue_to_value (napi_env env,
                     GValue * val)
{
  GType gtype;

  gtype = G_VALUE_TYPE (val);

  switch (gtype)
  {
    case G_TYPE_BOOLEAN:
      return fdn_boolean_to_value (env, g_value_get_boolean (val));
    case G_TYPE_INT:
      return fdn_int_to_value (env, g_value_get_int (val));
    case G_TYPE_UINT:
      return fdn_uint_to_value (env, g_value_get_uint (val));
    case G_TYPE_FLOAT:
      return fdn_double_to_value (env, g_value_get_float (val));
    case G_TYPE_DOUBLE:
      return fdn_double_to_value (env, g_value_get_double (val));
    case G_TYPE_STRING:
    {
      const gchar * str;

      str = g_value_get_string (val);
      if (str == NULL)
      {
        napi_value result;
        napi_get_null (env, &result);
        return result;
      }

      return fdn_utf8_to_value (env, str);
    }
    default:
    {
      GBytes * bytes;

      if (G_TYPE_IS_ENUM (gtype))
        return fdn_enum_to_value (env, gtype, g_value_get_enum (val));

      if (g_type_is_a (gtype, G_TYPE_SOCKET_ADDRESS))
      {
        napi_value result;

        /* TODO */
        napi_get_null (env, &result);

        return result;
      }

      g_assert (gtype == G_TYPE_BYTES);
      bytes = g_value_get_boxed (val);
      if (bytes != NULL)
      {
        return fdn_bytes_to_value (env, bytes);
      }
      else
      {
        napi_value result;
        napi_get_null (env, &result);
        return result;
      }
    }
  }
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

  if (strchr (str, '\\n') != NULL)
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
  GObject * handle;
  bool is_instance;
  gchar * name = NULL;
  FdnSignal * sig = NULL;

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

  sig = g_slice_new (FdnSignal);
  sig->handle = g_object_ref (handle);
  sig->id = g_signal_lookup (name, G_OBJECT_TYPE (sig->handle));
  sig->closures = NULL;
  if (sig->id == 0)
    goto invalid_signal_name;

  if (napi_wrap (env, jsthis, sig, NULL, NULL, NULL) != napi_ok)
    goto propagate_error;

  if (napi_add_finalizer (env, jsthis, sig, fdn_signal_finalize, NULL, NULL) != napi_ok)
    goto propagate_error;

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
invalid_signal_name:
  {
    napi_throw_type_error (env, NULL, "bad signal name");
    goto propagate_error;
  }
propagate_error:
  {
    if (sig != NULL)
      fdn_signal_finalize (env, sig, NULL);

    g_free (name);

    return NULL;
  }
}

static void
fdn_signal_finalize (napi_env env,
                     void * finalize_data,
                     void * finalize_hint)
{
  FdnSignal * sig = finalize_data;

  g_assert (sig->closures == NULL);
  g_object_unref (sig->handle);

  g_slice_free (FdnSignal, sig);
}

static napi_value
fdn_signal_connect (napi_env env,
                    napi_callback_info info)
{
  napi_value js_retval;
  FdnSignal * self;
  napi_value js_self, handler;
  FdnSignalClosure * sc;
  GClosure * closure;

  if (!fdn_signal_parse_arguments (env, info, &self, &js_self, &handler))
    return NULL;

  sc = fdn_signal_closure_new (env, self, js_self, handler);

  closure = (GClosure *) sc;
  g_closure_ref (closure);
  g_closure_sink (closure);
  self->closures = g_slist_prepend (self->closures, sc);

  sc->handler_id = g_signal_connect_closure_by_id (self->handle, self->id, 0, closure, TRUE);

  napi_get_undefined (env, &js_retval);

  return js_retval;
}

static napi_value
fdn_signal_disconnect (napi_env env,
                       napi_callback_info info)
{
  napi_value js_retval;
  FdnSignal * self;
  napi_value handler;
  GSList * cur;

  if (!fdn_signal_parse_arguments (env, info, &self, NULL, &handler))
    return NULL;

  for (cur = self->closures; cur != NULL; cur = cur->next)
  {
    FdnSignalClosure * closure = cur->data;
    napi_value candidate_handler;
    bool same_handler;

    napi_get_reference_value (env, closure->handler, &candidate_handler);

    napi_strict_equals (env, candidate_handler, handler, &same_handler);

    if (same_handler)
    {
      g_signal_handler_disconnect (closure->sig->handle, closure->handler_id);
      closure->handler_id = 0;

      closure->state = FDN_SIGNAL_CLOSURE_CLOSED;

      g_closure_unref ((GClosure *) closure);
      self->closures = g_slist_delete_link (self->closures, cur);

      break;
    }
  }

  napi_get_undefined (env, &js_retval);

  return js_retval;
}

static gboolean
fdn_signal_parse_arguments (napi_env env,
                            napi_callback_info info,
                            FdnSignal ** self,
                            napi_value * js_self,
                            napi_value * handler)
{
  size_t argc = 1;
  napi_value jsthis;

  if (napi_get_cb_info (env, info, &argc, handler, &jsthis, NULL) != napi_ok)
    goto propagate_error;

  if (napi_unwrap (env, jsthis, (void **) self) != napi_ok)
    goto propagate_error;

  if (js_self != NULL)
    *js_self = jsthis;

  if (argc != 1)
    goto missing_handler;

  if (!fdn_is_function (env, *handler))
    goto invalid_handler;

  return TRUE;

missing_handler:
  {
    napi_throw_error (env, NULL, "missing argument: handler");
    return FALSE;
  }
invalid_handler:
  {
    napi_throw_error (env, NULL, "expected a function");
    return FALSE;
  }
propagate_error:
  {
    return FALSE;
  }
}

static FdnSignalClosure *
fdn_signal_closure_new (napi_env env,
                        FdnSignal * sig,
                        napi_value js_sig,
                        napi_value handler)
{
  FdnSignalClosure * sc;
  GClosure * closure;
  napi_value resource_name;

  closure = g_closure_new_simple (sizeof (FdnSignalClosure), NULL);
  g_closure_add_finalize_notifier (closure, NULL, fdn_signal_closure_finalize);
  g_closure_set_marshal (closure, fdn_signal_closure_marshal);

  sc = (FdnSignalClosure *) closure;
  sc->sig = sig;
  napi_create_reference (env, js_sig, 1, &sc->js_sig);
  sc->state = FDN_SIGNAL_CLOSURE_OPEN;
  napi_create_string_utf8 (env, g_signal_name (sig->id), NAPI_AUTO_LENGTH, &resource_name);
  napi_create_threadsafe_function (env, NULL, NULL, resource_name, 0, 1, NULL, NULL, sc, fdn_signal_closure_deliver, &sc->tsfn);
  napi_unref_threadsafe_function (env, sc->tsfn);
  napi_create_reference (env, handler, 1, &sc->handler);

  return sc;
}

static void
fdn_signal_closure_finalize (gpointer data,
                             GClosure * closure)
{
  FdnSignalClosure * self = (FdnSignalClosure *) closure;
  FdnSignalClosureMessage * message;
  FdnSignalClosureMessageDestroy * d;

  message = g_slice_new (FdnSignalClosureMessage);
  message->type = FDN_SIGNAL_CLOSURE_MESSAGE_DESTROY;

  d = &message->payload.destroy;
  d->js_sig = self->js_sig;
  d->tsfn = self->tsfn;
  d->handler = self->handler;

  napi_call_threadsafe_function (self->tsfn, message, napi_tsfn_blocking);
}

static void
fdn_signal_closure_marshal (GClosure * closure,
                            GValue * return_gvalue,
                            guint n_param_values,
                            const GValue * param_values,
                            gpointer invocation_hint,
                            gpointer marshal_data)
{
  FdnSignalClosure * self = (FdnSignalClosure *) closure;
  FdnSignalClosureMessage * message;
  GArray * args;
  guint i;

  message = g_slice_new (FdnSignalClosureMessage);
  message->type = FDN_SIGNAL_CLOSURE_MESSAGE_MARSHAL;

  g_assert (n_param_values >= 1);
  args = g_array_sized_new (FALSE, FALSE, sizeof (GValue), n_param_values - 1);
  message->payload.marshal.args = args;

  for (i = 1; i != n_param_values; i++)
  {
    GValue val;

    g_value_init (&val, param_values[i].g_type);
    g_value_copy (&param_values[i], &val);
    g_array_append_val (args, val);
  }

  g_closure_ref (closure);
  napi_call_threadsafe_function (self->tsfn, message, napi_tsfn_blocking);
}

static void
fdn_signal_closure_deliver (napi_env env,
                            napi_value js_cb,
                            void * context,
                            void * data)
{
  FdnSignalClosureMessage * message = data;

  switch (message->type)
  {
    case FDN_SIGNAL_CLOSURE_MESSAGE_DESTROY:
    {
      FdnSignalClosureMessageDestroy * d = &message->payload.destroy;

      napi_delete_reference (env, d->handler);
      napi_delete_reference (env, d->js_sig);
      napi_release_threadsafe_function (d->tsfn, napi_tsfn_abort);

      break;
    }
    case FDN_SIGNAL_CLOSURE_MESSAGE_MARSHAL:
    {
      FdnSignalClosure * self = context;
      GArray * args;
      guint i;

      args = message->payload.marshal.args;

      if (self->state == FDN_SIGNAL_CLOSURE_OPEN)
      {
        napi_value * js_args;
        napi_value global, handler, js_result;

        js_args = g_newa (napi_value, args->len);
        for (i = 0; i != args->len; i++)
          js_args[i] = fdn_gvalue_to_value (env, &g_array_index (args, GValue, i));

        napi_get_global (env, &global);
        napi_get_reference_value (env, self->handler, &handler);

        napi_call_function (env, global, handler, args->len, js_args, &js_result);
      }

      for (i = 0; i != args->len; i++)
        g_value_reset (&g_array_index (args, GValue, i));
      g_array_free (args, TRUE);

      g_closure_unref ((GClosure *) self);

      break;
    }
    default:
      g_assert_not_reached ();
  }

  g_slice_free (FdnSignalClosureMessage, message);
}
"""


def resolve_destroy_function(type: Type) -> Optional[str]:
    name = type.name
    if name in {"gboolean", "gint", "guint", "guint16", "gulong"}:
        return None
    if name == "utf8":
        return "g_free"
    if name == "utf8[]":
        return "g_strfreev"
    if name == "GLib.Bytes":
        return "g_bytes_unref"
    if name == "GLib.HashTable":
        return "g_hash_table_unref"
    if name == "GLib.Variant":
        return "g_variant_unref"
    if name in {"Gio.Cancellable", "Gio.File", "Gio.IOStream", "Gio.TlsCertificate"}:
        return "g_object_unref"
    if name.startswith("Frida.") or name.startswith("FridaBase."):
        if name in {
            "Frida.DeviceType",
            "Frida.JsCompression",
            "Frida.SourceMaps",
            "FridaBase.Realm",
            "FridaBase.Scope",
            "FridaBase.ScriptRuntime",
            "FridaBase.SnapshotTransport",
            "FridaBase.Stdio",
        }:
            return None
        return "frida_unref"
    assert False, f"unable to determine destroy function for {name}"


def to_snake_case(name: str) -> str:
    result = []
    i = 0
    n = len(name)
    while i < n:
        if name[i].isupper():
            if i > 0:
                result.append("_")
            start = i
            if i + 1 < n and name[i + 1].islower():
                while i + 1 < n and name[i + 1].islower():
                    i += 1
            else:
                while i + 1 < n and name[i + 1].isupper():
                    i += 1
                if i + 1 < n:
                    i -= 1
            result.append(name[start : i + 1].lower())
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
            result.append("_")
        result.append(char)
    return "".join(result).upper()


class OutputFile:
    def __init__(self, output_path):
        self._output_path = output_path
        self._io = StringIO()

    def __enter__(self):
        return self._io

    def __exit__(self, *exc):
        result = self._io.getvalue()
        if self._output_path.exists():
            existing_contents = self._output_path.read_text(encoding="utf-8")
            if existing_contents == result:
                return False
        self._output_path.write_text(result, encoding="utf-8")
        return False


if __name__ == "__main__":
    main()
