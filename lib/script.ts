import { Signals, Signal, SignalHandler, SignalAdapter } from "./signals";

export class Script {
    destroyed: Signal<DestroyedHandler>;
    message: Signal<MessageHandler>;

    private impl: any;
    private exportsProxy: any;
    private logHandlerImpl: LogHandler = log;

    constructor(impl: any) {
        this.impl = impl;

        const services = new ScriptServices(this, impl.scripts);

        const rpcController: RpcController = services;
        this.exportsProxy = new ScriptExportsProxy(rpcController);

        const signals: Signals = services;
        this.destroyed = new Signal<DestroyedHandler>(signals, "destroyed");
        this.message = new Signal<MessageHandler>(signals, "message");
    }

    get exports(): ScriptExports {
        return this.exportsProxy;
    }

    get logHandler(): LogHandler {
        return this.logHandlerImpl;
    }

    set logHandler(handler: LogHandler | null) {
        this.logHandlerImpl = (handler !== null) ? handler : log;
    }

    load(): Promise<void> {
        return this.impl.load();
    }

    unload(): Promise<void> {
        return this.impl.unload();
    }

    post(message: any, data: Buffer | null = null): Promise<void> {
        return this.impl.post(message, data);
    }
}

export type DestroyedHandler = () => void;
export type MessageHandler = (message: ScriptMessage, data: Buffer | null) => void;

export interface ScriptMessage {
    type: ScriptMessageType;

    [key: string]: any;
}

export enum ScriptMessageType {
    Send = "send",
    Error = "error",
    Log = "log"
}

export interface ScriptExports {
    [name: string]: (...args: any[]) => Promise<any>;
}

export type LogHandler = (level: LogLevel, text: string) => void;

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

    private onMessage = (message: ScriptMessage, data: Buffer | null) => {
        if (isRpcMessage(message)) {
            const [ , id, operation, ...params ] = message.payload;
            this.onRpcMessage(id, operation, params, data);
        } else if (isLogMessage(message)) {
            this.script.logHandler(message.level, message.payload);
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
                const [message, name, stack] = params;
                error = new Error(message);
                error.name = name;
                error.stack = stack;
            }

            callback(error, value);
        }
    }
}

function ScriptExportsProxy(rpcController: RpcController): void {
    return new Proxy(this, {
        has(target, property) {
            return true;
        },
        get(target, property, receiver) {
            if (property in target) {
                return target[property];
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
            return {
                writable: true,
                configurable: true,
                enumerable: true
            };
        },
    });
}

interface RpcController {
    request(operation: string, ...params: any[]): Promise<any>;
}

enum RpcOperation {
    Ok = "ok",
    Error = "error"
}

function isInternalMessage(message: ScriptMessage): boolean {
    return isRpcMessage(message) || isLogMessage(message);
}

function isLogMessage(message: ScriptMessage): boolean {
    return message.type === ScriptMessageType.Log;
}

function isRpcMessage(message: ScriptMessage): boolean {
    if (message.type !== ScriptMessageType.Send)
        return false;

    const payload = message.payload;
    if (!(payload instanceof Array)) {
        return false;
    }

    return payload[0] === "frida:rpc";
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
