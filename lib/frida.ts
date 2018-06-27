import { Device, DeviceType, SpawnOptions } from "./device";
import { DeviceManager } from "./device_manager";
import { Session } from "./session";

import * as bindings from "bindings";

const binding = bindings({
    bindings: "frida_binding",
    try: [
        ["module_root", "build", "bindings"],
        ["module_root", "build", "Debug", "bindings"],
        ["module_root", "build", "Release", "bindings"],
        ["module_root", "out", "Debug", "bindings"],
        ["module_root", "Debug", "bindings"],
        ["module_root", "out", "Release", "bindings"],
        ["module_root", "Release", "bindings"],
        ["module_root", "build", "default", "bindings"],
        ["module_root", "compiled", "version", "platform", "arch", "bindings"],
        [process.cwd(), "bindings"],
    ]
});

let deviceManager: DeviceManager = null;

export async function spawn(program: string | string[], options: SpawnOptions = {}): Promise<number> {
    const device = await getLocalDevice();
    return await device.spawn(program, options);
}

export async function resume(target: number | string): Promise<void> {
    const device = await getLocalDevice();
    await device.resume(target);
}

export async function kill(target: number | string): Promise<void> {
    const device = await getLocalDevice();
    await device.kill(target);
}

export async function attach(target: number | string): Promise<Session> {
    const device = await getLocalDevice();
    return await device.attach(target);
}

export async function injectLibraryFile(target: number | string, path: string, entrypoint: string, data: string): Promise<number> {
    const device = await getLocalDevice();
    return await device.injectLibraryFile(target, path, entrypoint, data);
}

export async function injectLibraryBlob(target: number | string, blob: Buffer, entrypoint: string, data: string): Promise<number> {
    const device = await getLocalDevice();
    return await device.injectLibraryBlob(target, blob, entrypoint, data);
}

export async function enumerateDevices(): Promise<Device[]> {
    const deviceManager = getDeviceManager();

    return await deviceManager.enumerateDevices();
};

export function getDeviceManager(): DeviceManager {
    if (deviceManager === null) {
        deviceManager = new DeviceManager(new binding.DeviceManager());
    }
    return deviceManager;
}

export function getLocalDevice(): Promise<Device> {
    return getMatchingDevice(device => device.type === DeviceType.Local, 0);
}

export function getUsbDevice(timeout: number | null = 0): Promise<Device> {
    return getMatchingDevice(device => device.type === DeviceType.Tether, timeout || 0);
}

export function getRemoteDevice(): Promise<Device> {
    return getMatchingDevice(device => device.type === DeviceType.Remote, 0);
}

export function getDevice(id: string, timeout: number | null = 0): Promise<Device> {
    return getMatchingDevice(device => device.id === id, timeout || 0);
}

async function getMatchingDevice(predicate: DevicePredicate, timeout: number | null = null): Promise<Device> {
    const device = await findDevice(predicate);
    if (device !== null) {
        return device;
    }

    if (timeout === 0) {
        throw new Error("Device not found");
    }

    const getDeviceEventually = new Promise((resolve: (device: Device) => void, reject: (error: Error) => void) => {
        const deviceManager = getDeviceManager();

        deviceManager.added.listen(onDeviceAdded);
        const timer = (typeof timeout === "number") ? setTimeout(onTimeout, timeout) : null;

        findDevice(predicate).then(onSuccess, onError);

        function onDeviceAdded(device: Device) {
            if (predicate(device)) {
                onSuccess(device);
            }
        }

        function onSuccess(device: Device) {
            stopMonitoring();
            resolve(device);
        }

        function onError(error: Error) {
            stopMonitoring();
            reject(error);
        }

        function onTimeout() {
            onError(new Error("Timed out while waiting for device to appear"));
        }

        function stopMonitoring() {
            if (timer !== null) {
                clearTimeout(timer);
            }

            deviceManager.added.unlisten(onDeviceAdded);
        }
    });

    return await getDeviceEventually;
}

async function findDevice(predicate: DevicePredicate): Promise<Device | null> {
    const deviceManager = getDeviceManager();

    const devices = await deviceManager.enumerateDevices();

    const matching = devices.filter(predicate);
    if (matching.length === 0) {
        return null;
    }

    return matching[0];
}

type DevicePredicate = (device: Device) => boolean;