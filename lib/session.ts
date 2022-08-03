import { Cancellable } from "./cancellable";
import { Crash } from "./crash";
import { PortalMembership } from "./portal_membership";
import { Relay } from "./relay";
import { Script, ScriptOptions, SnapshotOptions } from "./script";
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

    get persistTimeout(): number {
        return this.impl.persistTimeout;
    }

    get isDetached(): boolean {
        return this.impl.isDetached;
    }

    detach(cancellable?: Cancellable): Promise<void> {
        return this.impl.detach(cancellable);
    }

    resume(cancellable?: Cancellable): Promise<void> {
        return this.impl.resume(cancellable);
    }

    enableChildGating(cancellable?: Cancellable): Promise<void> {
        return this.impl.enableChildGating(cancellable);
    }

    disableChildGating(cancellable?: Cancellable): Promise<void> {
        return this.impl.disableChildGating(cancellable);
    }

    async createScript(source: string, options: ScriptOptions = {}, cancellable?: Cancellable): Promise<Script> {
        const { name = null, snapshot = null, runtime = null } = options;

        return new Script(await this.impl.createScript(source, name, snapshot, runtime, cancellable));
    }

    async createScriptFromBytes(bytes: Buffer, options: ScriptOptions = {}, cancellable?: Cancellable): Promise<Script> {
        const { name = null, snapshot = null, runtime = null } = options;

        return new Script(await this.impl.createScriptFromBytes(bytes, name, snapshot, runtime, cancellable));
    }

    compileScript(source: string, options: ScriptOptions = {}, cancellable?: Cancellable): Promise<Buffer> {
        const { name = null, runtime = null } = options;

        return this.impl.compileScript(source, name, runtime, cancellable);
    }

    snapshotScript(embedScript: string, options: SnapshotOptions = {}, cancellable?: Cancellable): Promise<Buffer> {
        const { warmupScript = null, runtime = null } = options;

        return this.impl.snapshotScript(embedScript, warmupScript, runtime, cancellable);
    }

    setupPeerConnection(options: PeerOptions = {}, cancellable?: Cancellable): Promise<void> {
        const {
            stunServer = null,
            relays = [],
        } = options;
        return this.impl.setupPeerConnection(stunServer, relays, cancellable);
    }

    async joinPortal(address: string, options: PortalOptions = {}, cancellable?: Cancellable): Promise<PortalMembership> {
        const {
            certificate = null,
            token = null,
            acl = null,
        } = options;
        return new PortalMembership(await this.impl.joinPortal(address, certificate, token, acl, cancellable));
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
    ConnectionTerminated = "connection-terminated",
    DeviceLost = "device-lost"
}

export interface PeerOptions {
    stunServer?: string;
    relays?: Relay[];
}

export interface PortalOptions {
    certificate?: string;
    token?: string;
    acl?: string[];
}
