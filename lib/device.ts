import { Application } from "./application";
import { Child } from "./child";
import { Events } from "./events";
import { Icon } from "./icon";
import { Process } from "./process";
import { Session } from "./session";
import { Spawn } from "./spawn";

import { Minimatch } from "minimatch";

export class Device {
    private impl: any;

    constructor(impl: any) {
        this.impl = impl;
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

    get events(): Events {
        return this.impl.events;
    }

    getFrontmostApplication(): Promise<Application> {
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
    };

}

export enum DeviceType {
    Local = "local",
    Tether = "tether",
    Remote = "remote"
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
