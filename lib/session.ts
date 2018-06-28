import { Script } from "./script";
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

    async createScript(source: string, options: CreateScriptOptions = {}): Promise<Script> {
        const { name = null } = options;

        return new Script(await this.impl.createScript(name, source));
    }

    async createScriptFromBytes(bytes: Buffer): Promise<Script> {
        return new Script(await this.impl.createScriptFromBytes(bytes));
    }

    compileScript(source: string, options: CreateScriptOptions = {}): Promise<Buffer> {
        const { name = null } = options;

        return this.impl.compileScript(name, source);
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

export type SessionDetachedHandler = (reason: SessionDetachReason) => void;

export enum SessionDetachReason {
    ApplicationRequested = "application-requested",
    ProcessReplaced = "process-replaced",
    ProcessTerminated = "process-terminated",
    ServerTerminated = "server-terminated",
    DeviceLost = "device-lost"
}

export interface CreateScriptOptions {
    name?: string;
}

export interface EnableDebuggerOptions {
    port?: number;
}