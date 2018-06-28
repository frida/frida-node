import { Device } from "./device";
import { Signals, Signal, SignalHandler, SignalAdapter } from "./signals";

import { inspect } from "util";

export class DeviceManager {
    private impl: any;

    added: Signal<DeviceAddedHandler>;
    removed: Signal<DeviceRemovedHandler>;
    changed: Signal<DevicesChangedHandler>;

    constructor(impl: any) {
        this.impl = impl;

        const signals = new DeviceManagerSignals(impl.signals);
        this.added = new Signal<DeviceAddedHandler>(signals, "added");
        this.removed = new Signal<DeviceRemovedHandler>(signals, "removed");
        this.changed = new Signal<DevicesChangedHandler>(signals, "changed");
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

export type DeviceAddedHandler = (device: Device) => void;
export type DeviceRemovedHandler = (device: Device) => void;
export type DevicesChangedHandler = () => void;

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