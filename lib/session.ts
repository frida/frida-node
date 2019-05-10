import { Crash } from "./crash";
import { Script, ScriptOptions } from "./script";
import { Signal } from "./signals";

import { inspect } from "util";

export class Session {
    private impl: any;

    detached: Signal<SessionDetachedHandler>;

    constructor(impl: any) {
        this.impl = impl;

        const { signals } = impl;
        this.detached = new Signal<SessionDetachedHandler>(signals, "detached");
    }

    get pid(): number {
        return this.impl.pid;
    }

    detach(): Promise<void> {
        return this.impl.detach();
    }

    enableChildGating(): Promise<void> {
        return this.impl.enableChildGating();
    }

    disableChildGating(): Promise<void> {
        return this.impl.disableChildGating();
    }

    async createScript(source: string, options: ScriptOptions = {}): Promise<Script> {
        const { name = null, runtime = null } = options;

        return new Script(await this.impl.createScript(source, name, runtime));
    }

    async createScriptFromBytes(bytes: Buffer, options: ScriptOptions = {}): Promise<Script> {
        const { name = null, runtime = null } = options;

        return new Script(await this.impl.createScriptFromBytes(bytes, name, runtime));
    }

    compileScript(source: string, options: ScriptOptions = {}): Promise<Buffer> {
        const { name = null, runtime = null } = options;

        return this.impl.compileScript(source, name, runtime);
    }

    enableDebugger(options: EnableDebuggerOptions = {}): Promise<void> {
        const { port = 0 } = options;

        return this.impl.enableDebugger(port);
    }

    disableDebugger(): Promise<void> {
        return this.impl.disableDebugger();
    }

    enableJit(): Promise<void> {
        return this.impl.enableJit();
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