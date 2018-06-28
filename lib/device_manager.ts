import { Device } from "./device";
import { Events, Event, EventHandler, EventAdapter } from "./events";

export class DeviceManager {
    private impl: any;

    added: Event<AddedHandler>;
    removed: Event<RemovedHandler>;
    changed: Event<ChangedHandler>;

    constructor(impl: any) {
        this.impl = impl;

        const events = new DeviceManagerEvents(impl.events);

        this.added = new Event<AddedHandler>(events, "added");
        this.removed = new Event<RemovedHandler>(events, "removed");
        this.changed = new Event<ChangedHandler>(events, "changed");
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

class DeviceManagerEvents extends EventAdapter {
    constructor(events: Events) {
        super(events);
    }

    protected getProxy(signal: string, userHandler: EventHandler): EventHandler | null {
        if (signal === "added" || signal === "removed") {
            return impl => userHandler(new Device(impl));
        }

        return null;
    }
}

type AddedHandler = (device: Device) => void;
type RemovedHandler = (device: Device) => void;
type ChangedHandler = () => void;