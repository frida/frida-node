import { Device } from "./device";
import { Events, EventHandler } from "./events";

export class DeviceManager {
    private impl: any;

    added: DeviceAddedEvent;
    events: Events;

    constructor(impl: any) {
        this.impl = impl;

        this.events = new DeviceManagerEvents(impl.events);

        this.added = new DeviceAddedEvent(this.events);
    }

    async enumerateDevices(): Promise<Device[]> {
        const devices: any[] = await this.impl.enumerateDevices();
        return devices.map(impl => new Device(impl));
    }

    async addRemoteDevice(host: string): Promise<Device> {
        return new Device(await this.impl.addRemoteDevice());
    }

    removeRemoteDevice(host: string): Promise<void> {
        return this.impl.removeRemoteDevice(host);
    }
}

class DeviceManagerEvents implements Events {
    private impl: Events;
    private proxyHandlers: Map<EventHandler, EventHandler> = new Map();

    constructor(impl: any) {
        this.impl = impl;
    }

    listen(event: string, handler: EventHandler): void {
        let proxyHandler: EventHandler | null = null;

        if (event === "added" || event === "removed") {
            proxyHandler = rawDevice => handler(new Device(rawDevice));
        }

        if (proxyHandler !== null) {
            this.proxyHandlers.set(handler, proxyHandler);
            this.impl.listen(event, proxyHandler);
        } else {
            this.impl.listen(event, handler);
        }
    }

    unlisten(event: string, handler: EventHandler): void {
        const proxyHandler = this.proxyHandlers.get(handler);
        this.impl.unlisten(event, (proxyHandler !== undefined) ? proxyHandler : handler);
    }
}

class DeviceAddedEvent {
    private events: Events;

    constructor(events: Events) {
        this.events = events;
    }

    listen(handler: DeviceAddedHandler): void {
        this.events.listen("added", handler);
    }

    unlisten(handler: DeviceAddedHandler): void {
        this.events.unlisten("added", handler);
    }
}

type DeviceAddedHandler = (device: Device) => void;