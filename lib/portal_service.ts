import { Application } from "./application";
import { AuthenticatedSessionInfo } from "./authentication";
import { Cancellable } from "./cancellable";
import { Device } from "./device";
import { EndpointParameters } from "./endpoint_parameters";
import { binding } from "./native";
import { Signal } from "./signals";
import { SocketAddress } from "./socket_address";

import { inspect } from "util";

export class PortalService {
    nodeConnected: Signal<PortalNodeConnectedHandler>;
    nodeJoined: Signal<PortalNodeJoinedHandler>;
    nodeLeft: Signal<PortalNodeLeftHandler>;
    nodeDisconnected: Signal<PortalNodeDisconnectedHandler>;

    controllerConnected: Signal<PortalControllerConnectedHandler>;
    controllerDisconnected: Signal<PortalControllerDisconnectedHandler>;

    authenticated: Signal<PortalAuthenticatedHandler>;
    subscribe: Signal<PortalSubscribeHandler>;
    message: Signal<PortalMessageHandler>;

    device: Device;

    private impl: any;

    constructor({ clusterParams = null, controlParams = null }: PortalServiceOptions = {}) {
        const impl = new binding.PortalService(clusterParams, controlParams);
        this.impl = impl;

        this.device = new Device(impl.device);

        const { signals } = impl;

        this.nodeConnected = new Signal<PortalNodeConnectedHandler>(signals, "node-connected");
        this.nodeJoined = new Signal<PortalNodeJoinedHandler>(signals, "node-joined");
        this.nodeLeft = new Signal<PortalNodeLeftHandler>(signals, "node-left");
        this.nodeDisconnected = new Signal<PortalNodeDisconnectedHandler>(signals, "node-disconnected");

        this.controllerConnected = new Signal<PortalControllerConnectedHandler>(signals, "controller-connected");
        this.controllerDisconnected = new Signal<PortalControllerDisconnectedHandler>(signals, "controller-disconnected");

        this.authenticated = new Signal<PortalAuthenticatedHandler>(signals, "authenticated");
        this.subscribe = new Signal<PortalSubscribeHandler>(signals, "subscribe");
        this.message = new Signal<PortalMessageHandler>(signals, "message");
    }

    start(cancellable?: Cancellable): Promise<void> {
        return this.impl.start(cancellable);
    }

    stop(cancellable?: Cancellable): Promise<void> {
        return this.impl.stop(cancellable);
    }

    post(connectionId: PortalConnectionId, message: any, data: Buffer | null = null): void {
        this.impl.post(connectionId, message, data);
    }

    narrowcast(tag: PortalConnectionTag, message: any, data: Buffer | null = null): void {
        this.impl.narrowcast(tag, message, data);
    }

    broadcast(message: any, data: Buffer | null = null): void {
        this.impl.broadcast(message, data);
    }

    enumerateTags(connectionId: PortalConnectionId): Promise<PortalConnectionTag[]> {
        return this.impl.enumerateTags(connectionId);
    }

    tag(connectionId: PortalConnectionId, tag: PortalConnectionTag): void {
        this.impl.tag(connectionId, tag);
    }

    untag(connectionId: PortalConnectionId, tag: PortalConnectionTag): void {
        this.impl.untag(connectionId, tag);
    }

    [inspect.custom]() {
        return "PortalService {}";
    }
}

export interface PortalServiceOptions {
    clusterParams?: EndpointParameters;
    controlParams?: EndpointParameters;
}

export type PortalConnectionId = number;
export type PortalConnectionTag = string;

export type PortalNodeConnectedHandler = (connectionId: PortalConnectionId, remoteAddress: SocketAddress) => void;
export type PortalNodeJoinedHandler = (connectionId: PortalConnectionId, application: Application) => void;
export type PortalNodeLeftHandler = (connectionId: PortalConnectionId, application: Application) => void;
export type PortalNodeDisconnectedHandler = (connectionId: PortalConnectionId, remoteAddress: SocketAddress) => void;

export type PortalControllerConnectedHandler = (connectionId: PortalConnectionId, remoteAddress: SocketAddress) => void;
export type PortalControllerDisconnectedHandler = (connectionId: PortalConnectionId, remoteAddress: SocketAddress) => void;

export type PortalAuthenticatedHandler = (connectionId: PortalConnectionId, sessionInfo: AuthenticatedSessionInfo) => void;
export type PortalSubscribeHandler = (connectionId: PortalConnectionId) => void;
export type PortalMessageHandler = (connectionId: PortalConnectionId, message: any, data: Buffer | null) => void;
