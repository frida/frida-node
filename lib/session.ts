import { Events } from "./events";
import { Script } from "./script";

export class Session {
    private impl: any;

    constructor(impl: any) {
        this.impl = impl;
    }

    get pid(): number {
        return this.impl.pid;
    }

    get events(): Events {
        return this.impl.events;
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

    createScript(source: string, options: CreateScriptOptions = {}): Promise<Script> {
        const { name = null } = options;

        return this.impl.createScript(name, source);
    }

    createScriptFromBytes(bytes: Buffer): Promise<Script> {
        return this.impl.createScriptFromBytes(bytes);
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
}

interface CreateScriptOptions {
    name?: string;
}

interface EnableDebuggerOptions {
    port?: number;
}