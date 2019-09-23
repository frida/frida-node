import { Cancellable } from "./cancellable";
import { Crash } from "./crash";
import { Script, ScriptOptions } from "./script";
import { Signal } from "./signals";

import { inspect } from "util";

export class Session {
    detached: Signal<SessionDetachedHandler>;

    constructor(private impl: any) {
        const { signals } = impl;
        this.detached = new Signal<SessionDetachedHandler>(signals, "detached");
    }

    get pid(): number {
        return this.impl.pid;
    }

    detach(cancellable?: Cancellable): Promise<void> {
        return this.impl.detach(cancellable);
    }

    enableChildGating(cancellable?: Cancellable): Promise<void> {
        return this.impl.enableChildGating(cancellable);
    }

    disableChildGating(cancellable?: Cancellable): Promise<void> {
        return this.impl.disableChildGating(cancellable);
    }

    async createScript(source: string, options: ScriptOptions = {}, cancellable?: Cancellable): Promise<Script> {
        const { name = null, runtime = null } = options;

        return new Script(await this.impl.createScript(source, name, runtime, cancellable));
    }

    async createScriptFromBytes(bytes: Buffer, options: ScriptOptions = {}, cancellable?: Cancellable): Promise<Script> {
        const { name = null, runtime = null } = options;

        return new Script(await this.impl.createScriptFromBytes(bytes, name, runtime, cancellable));
    }

    compileScript(source: string, options: ScriptOptions = {}, cancellable?: Cancellable): Promise<Buffer> {
        const { name = null, runtime = null } = options;

        return this.impl.compileScript(source, name, runtime, cancellable);
    }

    enableDebugger(options: EnableDebuggerOptions = {}, cancellable?: Cancellable): Promise<void> {
        const { port = 0 } = options;

        return this.impl.enableDebugger(port, cancellable);
    }

    disableDebugger(cancellable?: Cancellable): Promise<void> {
        return this.impl.disableDebugger(cancellable);
    }

    enableJit(cancellable?: Cancellable): Promise<void> {
        return this.impl.enableJit(cancellable);
    }

    [inspect.custom](depth, options) {
        return "Session " + inspect({
            pid: this.pid
        }, options);
    }
}

export type SessionDetachedHandler = (reason: SessionDetachReason, crash: Crash | null) => void;

export enum SessionDetachReason {
    ApplicationRequested = "application-requested",
    ProcessReplaced = "process-replaced",
    ProcessTerminated = "process-terminated",
    ServerTerminated = "server-terminated",
    DeviceLost = "device-lost"
}

export interface EnableDebuggerOptions {
    port?: number;
}
