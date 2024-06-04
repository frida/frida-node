import { Application } from "./application";
import { Bus } from "./bus";
import { Cancellable } from "./cancellable";
import { Child } from "./child";
import { Crash } from "./crash";
import { Icon } from "./icon";
import { IOStream } from "./iostream";
import { Process } from "./process";
import { Service } from "./service";
import { Session } from "./session";
import { Signal } from "./signals";
import { Spawn } from "./spawn";
import { SystemParameters } from "./system_parameters";

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

    bus: Bus;

    constructor(private impl: any) {
        this.bus = new Bus(impl.bus);

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

    get icon(): Icon | null {
        return this.impl.icon;
    }

    get type(): DeviceType {
        return this.impl.type;
    }

    get isLost(): boolean {
        return this.impl.isLost;
    }

    querySystemParameters(cancellable?: Cancellable): Promise<SystemParameters> {
        return this.impl.querySystemParameters(cancellable);
    }

    getFrontmostApplication(options: FrontmostQueryOptions = {}, cancellable?: Cancellable): Promise<Application | null> {
        const {
            scope = null,
        } = options;
        return this.impl.getFrontmostApplication(scope, cancellable);
    }

    enumerateApplications(options: ApplicationQueryOptions = {}, cancellable?: Cancellable): Promise<Application[]> {
        const {
            identifiers = [],
            scope = null,
        } = options;
        return this.impl.enumerateApplications(identifiers, scope, cancellable);
    }

    enumerateProcesses(options: ProcessQueryOptions = {}, cancellable?: Cancellable): Promise<Process[]> {
        const {
            pids = [],
            scope = null,
        } = options;
        return this.impl.enumerateProcesses(pids, scope, cancellable);
    }

    async getProcess(name: string, options: ProcessMatchOptions = {}, cancellable?: Cancellable): Promise<Process> {
        const {
            scope = Scope.Minimal,
        } = options;
        const processes = await this.enumerateProcesses({ scope }, cancellable);
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

    spawn(program: string | string[], options: SpawnOptions = {}, cancellable?: Cancellable): Promise<ProcessID> {
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
            delete pendingOptions[name];
            return value ?? null;
        }
    }

    async input(target: TargetProcess, data: Buffer, cancellable?: Cancellable): Promise<void> {
        const pid = await this.getPid(target, cancellable);
        return this.impl.input(pid, data, cancellable);
    }

    async resume(target: TargetProcess, cancellable?: Cancellable): Promise<void> {
        const pid = await this.getPid(target, cancellable);
        return this.impl.resume(pid, cancellable);
    }

    async kill(target: TargetProcess, cancellable?: Cancellable): Promise<void> {
        const pid = await this.getPid(target, cancellable);
        return this.impl.kill(pid, cancellable);
    }

    async attach(target: TargetProcess, options: SessionOptions = {}, cancellable?: Cancellable): Promise<Session> {
        const {
            realm = null,
            persistTimeout = null,
        } = options;

        const pid = await this.getPid(target, cancellable);

        return new Session(await this.impl.attach(pid, realm, persistTimeout, cancellable));
    }

    async injectLibraryFile(target: TargetProcess, path: string, entrypoint: string, data: string,
            cancellable?: Cancellable): Promise<InjecteeID> {
        const pid = await this.getPid(target, cancellable);
        return this.impl.injectLibraryFile(pid, path, entrypoint, data, cancellable);
    }

    async injectLibraryBlob(target: TargetProcess, blob: Buffer, entrypoint: string, data: string,
            cancellable?: Cancellable): Promise<InjecteeID> {
        const pid = await this.getPid(target, cancellable);
        return this.impl.injectLibraryBlob(pid, blob, entrypoint, data, cancellable);
    }

    async openChannel(address: string, cancellable?: Cancellable): Promise<IOStream> {
        return new IOStream(await this.impl.openChannel(address, cancellable));
    }

    async openService(address: string, cancellable?: Cancellable): Promise<Service> {
        return new Service(await this.impl.openService(address, cancellable));
    }

    async unpair(cancellable?: Cancellable): Promise<void> {
        await this.impl.unpair(cancellable);
    }

    private async getPid(target: TargetProcess, cancellable?: Cancellable): Promise<ProcessID> {
        if (typeof target === "number") {
            return target;
        }

        const process = await this.getProcess(target, {}, cancellable);
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

export type ProcessID = number;
export type ProcessName = string;
export type InjecteeID = number;
export type FileDescriptor = number;

export type SpawnAddedHandler = (spawn: Spawn) => void;
export type SpawnRemovedHandler = (spawn: Spawn) => void;
export type ChildAddedHandler = (child: Child) => void;
export type ChildRemovedHandler = (child: Child) => void;
export type ProcessCrashedHandler = (crash: Crash) => void;
export type OutputHandler = (pid: ProcessID, fd: FileDescriptor, data: Buffer) => void;
export type UninjectedHandler = (id: InjecteeID) => void;
export type DeviceLostHandler = () => void;

export enum DeviceType {
    Local = "local",
    Remote = "remote",
    Usb = "usb"
}

export interface FrontmostQueryOptions {
    /**
     * How much data to collect about the frontmost application. The default is `Scope.Minimal`,
     * which means no parameters will be collected. Specify `Scope.Metadata` to collect all
     * parameters except icons, which can be included by specifying `Scope.Full`.
     */
    scope?: Scope;
}

export interface ApplicationQueryOptions {
    /**
     * Limit enumeration to one or more application IDs only. Typically used to fetch additional
     * details about a subset, e.g. based on user interaction.
     */
    identifiers?: string[];

    /**
     * How much data to collect about each application. The default is `Scope.Minimal`, which
     * means no parameters will be collected. Specify `Scope.Metadata` to collect all parameters
     * except icons, which can be included by specifying `Scope.Full`.
     */
    scope?: Scope;
}

export interface ProcessQueryOptions {
    /**
     * Limit enumeration to one or more process IDs only. Typically used to fetch additional
     * details about a subset, e.g. based on user interaction.
     */
    pids?: number[];

    /**
     * How much data to collect about each process. The default is `Scope.Minimal`, which
     * means no parameters will be collected. Specify `Scope.Metadata` to collect all
     * parameters except icons, which can be included by specifying `Scope.Full`.
     */
    scope?: Scope;
}

export interface ProcessMatchOptions {
    /**
     * How much data to collect about the matching process. The default is `Scope.Minimal`,
     * which means no parameters will be collected. Specify `Scope.Metadata` to collect all
     * parameters except icons, which can be included by specifying `Scope.Full`.
     */
    scope?: Scope;
}

/**
 * How much data to collect about a given application or process.
 */
export enum Scope {
    /**
     * Don't collect any parameters. This is the default.
     */
    Minimal = "minimal",

    /**
     * Collect all parameters except icons.
     */
    Metadata = "metadata",

    /**
     * Collect all parameters, including icons.
     */
    Full = "full"
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

export type TargetProcess = ProcessID | ProcessName;

export interface SessionOptions {
    realm?: Realm;
    persistTimeout?: number;
}

export enum Realm {
    Native = "native",
    Emulated = "emulated",
}
