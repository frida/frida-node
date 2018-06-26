import { Events, EventHandler, EventAdapter } from "./events";

export class Script {
    private impl: any;

    private pending: { [id: string]:  };
    private nextRequestId: number = 1;

    private logHandlerImpl: LogHandler = log;

    events: ScriptEvents;

    constructor(impl: any) {
        this.impl = impl;

        this.events = new ScriptEvents(this, impl.events);
    }

    get logHandler() {
        return this.logHandlerImpl;
    }

    set logHandler(handler: LogHandler | null) {
        this.logHandler = (handler !== null) ? handler : log;
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

    async getExports(): Promise<ScriptExports> {
        const methodNames: string[] = await this.rpcRequest("list");
        const proxy = methodNames.reduce((proxy, methodName) => {
            proxy[methodName] = this.makeRpcMethod(methodName);
            return proxy;
        }, {});
        return Object.freeze(proxy);
    }

    private makeRpcMethod(name: string) {
        return (...args: any[]) => {
            return this.rpcRequest("call", name, ...args);
        };
    }

    private rpcRequest(operation: string, ...params: any[]): Promise<any> {
        return new Promise((resolve, reject) => {
            const id = this.nextRequestId++;

            const complete = (error: Error | null, result?: any) => {
                this.events.unlisten("destroyed", onScriptDestroyed);

                delete this.pending[id];

                if (error === null) {
                    resolve(result);
                } else {
                    reject(error);
                }
            };

            function onScriptDestroyed() {
                complete(new Error("Script is destroyed"));
            }

            this.pending[id] = complete;

            this.post(["frida:rpc", id, operation].concat(params)).catch(complete);
            this.events.listen("destroyed", onScriptDestroyed);
        });
    }

    onRpcMessage(id: number, operation: RpcOperation, params: any[], data: Buffer | null) {
        if (operation === RpcOperation.Ok || operation === RpcOperation.Error) {
            var callback = this[pending][id];

            var value = null;
            var error = null;
            if (operation === "ok") {
                value = (data !== null) ? data : params[0];
            } else {
                error = new Error(params[0]);

                var name = params[1];
                if (name)
                    error.name = name;

                var stack = params[2];
                if (stack)
                    error.stack = stack;
            }

            callback(error, value);
        }
    }
}

export interface ScriptMessage {
    type: ScriptMessageType;

    [key: string]: any;
}

export enum ScriptMessageType {
    Send = "send",
    Error = "error",
    Log = "log"
}

class ScriptEvents extends EventAdapter {
    private script: Script;

    constructor(script: Script, events: Events) {
        super(events);

        this.script = script;

        events.listen("destroyed", this.onDestroyed);
        events.listen("message", this.onMessage);
    }

    protected getProxy(signal: string, userHandler: EventHandler): EventHandler | null {
        if (signal === "message") {
            return (message, data) => {
                if (!isInternalMessage(message)) {
                    userHandler(message, data);
                }
            };
        }

        return null;
    }

    private onDestroyed = () => {
        this.events.unlisten("destroyed", this.onDestroyed);
        this.events.unlisten("message", this.onMessage);
    }

    private onMessage = (message: ScriptMessage, data: Buffer | null) => {
        if (isRpcMessage(message)) {
            const [ , id, operation, ...params ] = message.payload;
            this.script.onRpcMessage(id, operation, params, data);
        } else if (isLogMessage(message)) {
            this.script.logHandler(message.level, message.text);
        }
    }
}

interface ScriptExports {
    [name: string]: (...args: any[]) => Promise<any>;
}

enum RpcOperation {
    Ok = "ok",
    Error = "error"
}

type LogHandler = (level: LogLevel, text: string) => void;

enum LogLevel {
    Info = "info",
    Warning = "warning",
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
