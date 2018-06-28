import { Device } from "./device";
import { Signals, Signal, SignalHandler, SignalAdapter } from "./signals";

import { inspect } from "util";

export class DeviceManager {
    private impl: any;

    added: Signal<AddedHandler>;
    removed: Signal<RemovedHandler>;
    changed: Signal<ChangedHandler>;

    constructor(impl: any) {
        this.impl = impl;

        const signals = new DeviceManagerSignals(impl.signals);
        this.added = new Signal<AddedHandler>(signals, "added");
        this.removed = new Signal<RemovedHandler>(signals, "removed");
        this.changed = new Signal<ChangedHandler>(signals, "changed");
    }

    async enumerateDevices(): Promise<Device[]> {
        const devices: any[] = await this.impl.enumerateDevices();
        return devices.map(impl => new Device(impl));
    }

    async addRemoteDevice(host: string): Promise<Device> {
        return new Device(await this.impl.addRemoteDevice(host));
    }

    removeRemoteDevice(host: string): Promise<void> {
        return this.impl.removeRemoteDevice(host);
    }

    [inspect.custom]() {
        return "DeviceManager {}";
    }
}

export type AddedHandler = (device: Device) => void;
export type RemovedHandler = (device: Device) => void;
export type ChangedHandler = () => void;

class DeviceManagerSignals extends SignalAdapter {
    constructor(signals: Signals) {
        super(signals);
    }

    protected getProxy(name: string, userHandler: SignalHandler): SignalHandler | null {
        if (name === "added" || name === "removed") {
            return impl => userHandler(new Device(impl));
        }

        return null;
    }
}