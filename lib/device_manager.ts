import { Cancellable } from "./cancellable";
import { Device } from "./device";
import { binding } from "./native";
import { Signals, Signal, SignalHandler, SignalAdapter } from "./signals";

import { inspect } from "util";

export class DeviceManager {
    private impl = new binding.DeviceManager();

    added: Signal<DeviceAddedHandler>;
    removed: Signal<DeviceRemovedHandler>;
    changed: Signal<DevicesChangedHandler>;

    constructor() {
        const signals = new DeviceManagerSignals(this.impl.signals);
        this.added = new Signal<DeviceAddedHandler>(signals, "added");
        this.removed = new Signal<DeviceRemovedHandler>(signals, "removed");
        this.changed = new Signal<DevicesChangedHandler>(signals, "changed");
    }

    async enumerateDevices(cancellable?: Cancellable): Promise<Device[]> {
        const devices: any[] = await this.impl.enumerateDevices(cancellable);
        return devices.map(impl => new Device(impl));
    }

    async addRemoteDevice(address: string, options: RemoteDeviceOptions = {}, cancellable?: Cancellable): Promise<Device> {
        const {
            certificate = null,
            origin = null,
            token = null,
            keepaliveInterval = null,
        } = options;
        return new Device(await this.impl.addRemoteDevice(address, certificate, origin, token, keepaliveInterval, cancellable));
    }

    removeRemoteDevice(address: string, cancellable?: Cancellable): Promise<void> {
        return this.impl.removeRemoteDevice(address, cancellable);
    }

    [inspect.custom]() {
        return "DeviceManager {}";
    }
}

export interface RemoteDeviceOptions {
    certificate?: string;
    origin?: string;
    token?: string;
    keepaliveInterval?: number;
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
