import { Application } from "./application";
import { Child } from "./child";
import { Icon } from "./icon";
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
    output: Signal<OutputHandler>;
    uninjected: Signal<UninjectedHandler>;
    lost: Signal<DeviceLostHandler>;

    private impl: any;

    constructor(impl: any) {
        this.impl = impl;

        const { signals } = impl;
        this.spawnAdded = new Signal<SpawnAddedHandler>(signals, "spawn-added");
        this.spawnRemoved = new Signal<SpawnRemovedHandler>(signals, "spawn-removed");
        this.childAdded = new Signal<ChildAddedHandler>(signals, "child-added");
        this.childRemoved = new Signal<ChildRemovedHandler>(signals, "child-removed");
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

    getFrontmostApplication(): Promise<Application | null> {
        return this.impl.getFrontmostApplication();
    }

    enumerateApplications(): Promise<Application[]> {
        return this.impl.enumerateApplications();
    }

    enumerateProcesses(): Promise<Process[]> {
        return this.impl.enumerateProcesses();
    }

    async getProcess(name: string): Promise<Process> {
        const processes = await this.enumerateProcesses();
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

    enableSpawnGating(): Promise<void> {
        return this.impl.enableSpawnGating();
    }

    disableSpawnGating(): Promise<void> {
        return this.impl.disableSpawnGating();
    }

    enumeratePendingSpawn(): Promise<Spawn[]> {
        return this.impl.enumeratePendingSpawn();
    }

    enumeratePendingChildren(): Promise<Child[]> {
        return this.impl.enumeratePendingChildren();
    }

    spawn(program: string | string[], options: SpawnOptions = {}): Promise<number> {
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

        return this.impl.spawn(program, argv, envp, env, cwd, stdio, aux);

        function consumeOption(name) {
            const value = pendingOptions[name];
            if (value === undefined) {
                return null;
            }
            delete pendingOptions[name];
            return value;
        }
    }

    async input(target: number | string, data: Buffer): Promise<void> {
        return this.impl.input(await this.getPid(target), data);
    }

    async resume(target: number | string): Promise<void> {
        return this.impl.resume(await this.getPid(target));
    }

    async kill(target: number | string): Promise<void> {
        return this.impl.kill(await this.getPid(target));
    }

    async attach(target: number | string): Promise<Session> {
        return new Session(await this.impl.attach(await this.getPid(target)));
    }

    async injectLibraryFile(target: number | string, path: string, entrypoint: string, data: string): Promise<number> {
        return this.impl.injectLibraryFile(await this.getPid(target), path, entrypoint, data);
    }

    async injectLibraryBlob(target: number | string, blob: Buffer, entrypoint: string, data: string): Promise<number> {
        return this.impl.injectLibraryBlob(await this.getPid(target), blob, entrypoint, data);
    }

    private async getPid(target: number | string): Promise<number> {
        if (typeof target === "number") {
            return target;
        }

        const process = await this.getProcess(target);
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