import { Signals, Signal, SignalHandler, SignalAdapter } from "./signals";

import { inspect } from "util";

export class Script {
    destroyed: Signal<ScriptDestroyedHandler>;
    message: Signal<ScriptMessageHandler>;

    private impl: any;
    private exportsProxy: any;
    private logHandlerImpl: ScriptLogHandler = log;

    constructor(impl: any) {
        this.impl = impl;

        const services = new ScriptServices(this, impl.signals);

        const rpcController: RpcController = services;
        this.exportsProxy = new ScriptExportsProxy(rpcController);

        const signals: Signals = services;
        this.destroyed = new Signal<ScriptDestroyedHandler>(signals, "destroyed");
        this.message = new Signal<ScriptMessageHandler>(signals, "message");
    }

    get exports(): ScriptExports {
        return this.exportsProxy;
    }

    get logHandler(): ScriptLogHandler {
        return this.logHandlerImpl;
    }

    set logHandler(handler: ScriptLogHandler | null) {
        this.logHandlerImpl = (handler !== null) ? handler : log;
    }

    load(): Promise<void> {
        return this.impl.load();
    }

    unload(): Promise<void> {
        return this.impl.unload();
    }

    eternalize(): Promise<void> {
        return this.impl.eternalize();
    }

    post(message: any, data: Buffer | null = null): Promise<void> {
        return this.impl.post(message, data);
    }

    [inspect.custom](depth, options) {
        return "Script {}";
    }
}

export type ScriptDestroyedHandler = () => void;
export type ScriptMessageHandler = (message: Message, data: Buffer | null) => void;
export type ScriptLogHandler = (level: LogLevel, text: string) => void;

export type Message = SendMessage | ErrorMessage;

export enum MessageType {
    Send = "send",
    Error = "error"
}

export interface SendMessage {
    type: MessageType.Send;
    payload: any;
}

export interface ErrorMessage {
    type: MessageType.Error;
    description: string;
    stack?: string;
    fileName?: string;
    lineNumber?: number;
    columnNumber?: number;
}

interface LogMessage {
    type: "log";
    level: LogLevel;
    payload: string;
}

export interface ScriptExports {
    [name: string]: (...args: any[]) => Promise<any>;
}

export enum LogLevel {
    Info = "info",
    Warning = "warning",
    Error = "error"
}

class ScriptServices extends SignalAdapter implements RpcController {
    private script: Script;

    private pendingRequests: { [id: string]: (error: Error | null, result?: any) => void } = {};
    private nextRequestId: number = 1;

    constructor(script: Script, signals: Signals) {
        super(signals);

        this.script = script;

        this.signals.connect("destroyed", this.onDestroyed);
        this.signals.connect("message", this.onMessage);
    }

    protected getProxy(name: string, userHandler: SignalHandler): SignalHandler | null {
        if (name === "message") {
            return (message, data) => {
                if (!isInternalMessage(message)) {
                    userHandler(message, data);
                }
            };
        }

        return null;
    }

    private onDestroyed = () => {
        this.signals.disconnect("destroyed", this.onDestroyed);
        this.signals.disconnect("message", this.onMessage);
    }

    private onMessage = (message: Message, data: Buffer | null) => {
        if (message.type === MessageType.Send && isRpcSendMessage(message)) {
            const [ , id, operation, ...params ] = message.payload;
            this.onRpcMessage(id, operation, params, data);
        } else if (isLogMessage(message)) {
            const opaqueMessage: any = message;
            const logMessage: LogMessage = opaqueMessage;
            this.script.logHandler(logMessage.level, logMessage.payload);
        }
    }

    request(operation: string, ...params: any[]): Promise<any> {
        return new Promise((resolve, reject) => {
            const id = this.nextRequestId++;

            const complete = (error: Error | null, result?: any) => {
                this.signals.disconnect("destroyed", onScriptDestroyed);

                delete this.pendingRequests[id];

                if (error === null) {
                    resolve(result);
                } else {
                    reject(error);
                }
            };

            function onScriptDestroyed() {
                complete(new Error("Script is destroyed"));
            }

            this.pendingRequests[id] = complete;

            this.script.post(["frida:rpc", id, operation].concat(params)).catch(complete);
            this.signals.connect("destroyed", onScriptDestroyed);
        });
    }

    onRpcMessage(id: number, operation: RpcOperation, params: any[], data: Buffer | null) {
        if (operation === RpcOperation.Ok || operation === RpcOperation.Error) {
            const callback = this.pendingRequests[id];

            let value = null;
            let error = null;
            if (operation === RpcOperation.Ok) {
                value = (data !== null) ? data : params[0];
            } else {
                const [message, name, stack, rawErr] = params;
                error = new Error(message);
                error.name = name;
                error.stack = stack;
                Object.assign(error, rawErr);
            }

            callback(error, value);
        }
    }
}

function ScriptExportsProxy(rpcController: RpcController): void {
    return new Proxy(this, {
        has(target, property) {
            return !isReservedMethodName(property);;
        },
        get(target, property, receiver) {
            if (property in target) {
                return target[property];
            }

            if (property === inspect.custom) {
                return inspectProxy;
            }

            if (isReservedMethodName(property)) {
                return undefined;
            }

            return (...args: any[]): Promise<any> => {
                return rpcController.request("call", property, args);
            };
        },
        set(target, property, value, receiver) {
            target[property] = value;
            return true;
        },
        ownKeys(target) {
            return Object.getOwnPropertyNames(target);
        },
        getOwnPropertyDescriptor(target, property) {
            if (property in target) {
                return Object.getOwnPropertyDescriptor(target, property);
            }

            if (isReservedMethodName(property)) {
                return undefined;
            }

            return {
                writable: true,
                configurable: true,
                enumerable: true
            };
        },
    });
}

function inspectProxy() {
    return "ScriptExportsProxy {}";
}

interface RpcController {
    request(operation: string, ...params: any[]): Promise<any>;
}

enum RpcOperation {
    Ok = "ok",
    Error = "error"
}

function isInternalMessage(message: Message): boolean {
    return isRpcMessage(message) || isLogMessage(message);
}

function isRpcMessage(message: Message): boolean {
    return message.type === MessageType.Send && isRpcSendMessage(message);
}

function isRpcSendMessage(message: SendMessage): boolean {
    const payload = message.payload;
    if (!(payload instanceof Array)) {
        return false;
    }

    return payload[0] === "frida:rpc";
}

function isLogMessage(message: Message): boolean {
    return message.type as string === "log";
}

function log(level: LogLevel, text: string): void {
    switch (level) {
        case LogLevel.Info:
            console.log(text);
            break;
        case LogLevel.Warning:
            console.warn(text);
            break;
        case LogLevel.Error:
            console.error(text);
            break;
    }
}

const reservedMethodNames = new Set<string>([
    "then",
    "catch",
    "finally",
]);

function isReservedMethodName(name: string | number | symbol): boolean {
    return reservedMethodNames.has(name.toString());
}
