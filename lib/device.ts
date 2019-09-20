import { Application } from "./application";
import { Cancellable } from "./cancellable";
import { Child } from "./child";
import { Crash } from "./crash";
import { Icon } from "./icon";
import { IOStream } from "./iostream";
import { Process } from "./process";
import { Session } from "./session";
import { Signal } from "./signals";
import { Spawn } from "./spawn";

import { Minimatch } from "minimatch";
import { inspect } from "util";

export class Device {
    spawnAdded: Signal<SpawnAddedHandler>;
    spawnRemoved: Signal<SpawnRemovedHandler>;
    childAdded: Signal<ChildAddedHandler>;
    childRemoved: Signal<ChildRemovedHandler>;
    processCrashed: Signal<ProcessCrashedHandler>;
    output: Signal<OutputHandler>;
    uninjected: Signal<UninjectedHandler>;
    lost: Signal<DeviceLostHandler>;

    constructor(private impl: any) {
        const { signals } = impl;
        this.spawnAdded = new Signal<SpawnAddedHandler>(signals, "spawn-added");
        this.spawnRemoved = new Signal<SpawnRemovedHandler>(signals, "spawn-removed");
        this.childAdded = new Signal<ChildAddedHandler>(signals, "child-added");
        this.childRemoved = new Signal<ChildRemovedHandler>(signals, "child-removed");
        this.processCrashed = new Signal<ProcessCrashedHandler>(signals, "process-crashed");
        this.output = new Signal<OutputHandler>(signals, "output");
        this.uninjected = new Signal<UninjectedHandler>(signals, "uninjected");
        this.lost = new Signal<DeviceLostHandler>(signals, "lost");
    }

    get id(): string {
        return this.impl.id;
    }

    get name(): string {
        return this.impl.name;
    }

    get icon(): Icon {
        return this.impl.icon;
    }

    get type(): DeviceType {
        return this.impl.type;
    }

    getFrontmostApplication(cancellable?: Cancellable): Promise<Application | null> {
        return this.impl.getFrontmostApplication(cancellable);
    }

    enumerateApplications(cancellable?: Cancellable): Promise<Application[]> {
        return this.impl.enumerateApplications(cancellable);
    }

    enumerateProcesses(cancellable?: Cancellable): Promise<Process[]> {
        return this.impl.enumerateProcesses(cancellable);
    }

    async getProcess(name: string, cancellable?: Cancellable): Promise<Process> {
        const processes = await this.enumerateProcesses(cancellable);
        const mm = new Minimatch(name.toLowerCase());
        const matching = processes.filter(process => mm.match(process.name.toLowerCase()));
        if (matching.length === 1) {
            return matching[0];
        } else if (matching.length > 1) {
            throw new Error("Ambiguous name; it matches: " + matching.map(process => `${process.name} (pid: ${process.pid})`).join(", "));
        } else {
            throw new Error("Process not found");
        }
    }

    enableSpawnGating(cancellable?: Cancellable): Promise<void> {
        return this.impl.enableSpawnGating(cancellable);
    }

    disableSpawnGating(cancellable?: Cancellable): Promise<void> {
        return this.impl.disableSpawnGating(cancellable);
    }

    enumeratePendingSpawn(cancellable?: Cancellable): Promise<Spawn[]> {
        return this.impl.enumeratePendingSpawn(cancellable);
    }

    enumeratePendingChildren(cancellable?: Cancellable): Promise<Child[]> {
        return this.impl.enumeratePendingChildren(cancellable);
    }

    spawn(program: string | string[], options: SpawnOptions = {}, cancellable?: Cancellable): Promise<number> {
        const pendingOptions = Object.assign({}, options);

        let argv = consumeOption("argv");
        if (typeof program !== "string") {
            argv = program;
            program = argv[0];
            if (argv.length === 1) {
                argv = null;
            }
        }
        const envp = consumeOption("envp");
        const env = consumeOption("env");
        const cwd = consumeOption("cwd");
        const stdio = consumeOption("stdio");
        const aux = pendingOptions;

        return this.impl.spawn(program, argv, envp, env, cwd, stdio, aux, cancellable);

        function consumeOption(name) {
            const value = pendingOptions[name];
            if (value === undefined) {
                return null;
            }
            delete pendingOptions[name];
            return value;
        }
    }

    async input(target: number | string, data: Buffer, cancellable?: Cancellable): Promise<void> {
        const pid = await this.getPid(target, cancellable);
        return this.impl.input(pid, data, cancellable);
    }

    async resume(target: number | string, cancellable?: Cancellable): Promise<void> {
        const pid = await this.getPid(target, cancellable);
        return this.impl.resume(pid, cancellable);
    }

    async kill(target: number | string, cancellable?: Cancellable): Promise<void> {
        const pid = await this.getPid(target, cancellable);
        return this.impl.kill(pid, cancellable);
    }

    async attach(target: number | string, cancellable?: Cancellable): Promise<Session> {
        const pid = await this.getPid(target, cancellable);
        return new Session(await this.impl.attach(pid, cancellable));
    }

    async injectLibraryFile(target: number | string, path: string, entrypoint: string, data: string,
            cancellable?: Cancellable): Promise<number> {
        const pid = await this.getPid(target, cancellable);
        return this.impl.injectLibraryFile(pid, path, entrypoint, data, cancellable);
    }

    async injectLibraryBlob(target: number | string, blob: Buffer, entrypoint: string, data: string,
            cancellable?: Cancellable): Promise<number> {
        const pid = await this.getPid(target, cancellable);
        return this.impl.injectLibraryBlob(pid, blob, entrypoint, data, cancellable);
    }

    async openChannel(address: string, cancellable?: Cancellable): Promise<IOStream> {
        return new IOStream(await this.impl.openChannel(address, cancellable));
    }

    private async getPid(target: number | string, cancellable?: Cancellable): Promise<number> {
        if (typeof target === "number") {
            return target;
        }

        const process = await this.getProcess(target, cancellable);
        return process.pid;
    }

    [inspect.custom](depth, options) {
        return "Device " + inspect({
            id: this.id,
            name: this.name,
            icon: this.icon,
            type: this.type
        }, options);
    }
}

export type SpawnAddedHandler = (spawn: Spawn) => void;
export type SpawnRemovedHandler = (spawn: Spawn) => void;
export type ChildAddedHandler = (child: Child) => void;
export type ChildRemovedHandler = (child: Child) => void;
export type ProcessCrashedHandler = (crash: Crash) => void;
export type OutputHandler = (pid: number, fd: number, data: Buffer) => void;
export type UninjectedHandler = (id: number) => void;
export type DeviceLostHandler = () => void;

export enum DeviceType {
    Local = "local",
    Remote = "remote",
    Usb = "usb"
}

export interface SpawnOptions {
    argv?: string[];
    envp?: { [name: string]: string };
    env?: { [name: string]: string };
    cwd?: string;
    stdio?: Stdio;

    [name: string]: any;
}

export enum Stdio {
    Inherit = "inherit",
    Pipe = "pipe"
}
