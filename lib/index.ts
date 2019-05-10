import * as applicationModule from "./application";
import * as childModule from "./child";
import * as deviceManagerModule from "./device_manager";
import * as deviceModule from "./device";
import * as iconModule from "./icon";
import * as processModule from "./process";
import * as scriptModule from "./script";
import * as sessionModule from "./session";
import * as spawnModule from "./spawn";

import * as bindings from "bindings";

export type DeviceManager = deviceManagerModule.DeviceManager;
export const DeviceManager = deviceManagerModule.DeviceManager;
export type DeviceAddedHandler = deviceManagerModule.DeviceAddedHandler;
export type DeviceRemovedHandler = deviceManagerModule.DeviceRemovedHandler;
export type DevicesChangedHandler = deviceManagerModule.DevicesChangedHandler;

export type Device = deviceModule.Device;
export const Device = deviceModule.Device;
export type SpawnAddedHandler = deviceModule.SpawnAddedHandler;
export type SpawnRemovedHandler = deviceModule.SpawnRemovedHandler;
export type ChildAddedHandler = deviceModule.ChildAddedHandler;
export type ChildRemovedHandler = deviceModule.ChildRemovedHandler;
export type OutputHandler = deviceModule.OutputHandler;
export type UninjectedHandler = deviceModule.UninjectedHandler;
export type DeviceLostHandler = deviceModule.DeviceLostHandler;
export type DeviceType = deviceModule.DeviceType;
export const DeviceType = deviceModule.DeviceType;
export type SpawnOptions = deviceModule.SpawnOptions;
export type Stdio = deviceModule.Stdio;

export type Session = sessionModule.Session;
export const Session = sessionModule.Session;
export type SessionDetachedHandler = sessionModule.SessionDetachedHandler;
export type SessionDetachReason = sessionModule.SessionDetachReason;
export const SessionDetachReason = sessionModule.SessionDetachReason;
export type EnableDebuggerOptions = sessionModule.EnableDebuggerOptions;

export type Script = scriptModule.Script;
export const Script = scriptModule.Script;
export type ScriptOptions = scriptModule.ScriptOptions;
export type ScriptRuntime = scriptModule.ScriptRuntime;
export const ScriptRuntime = scriptModule.ScriptRuntime;
export type ScriptDestroyedHandler = scriptModule.ScriptDestroyedHandler;
export type ScriptMessageHandler = scriptModule.ScriptMessageHandler;
export type ScriptLogHandler = scriptModule.ScriptLogHandler;
export type Message = scriptModule.Message;
export type MessageType = scriptModule.MessageType;
export const MessageType = scriptModule.MessageType;
export type SendMessage = scriptModule.SendMessage;
export type ErrorMessage = scriptModule.ErrorMessage;
export type ScriptExports = scriptModule.ScriptExports;
export type LogLevel = scriptModule.LogLevel;
export const LogLevel = scriptModule.LogLevel;

export type Application = applicationModule.Application;
export type Process = processModule.Process;
export type Spawn = spawnModule.Spawn;
export type Child = childModule.Child;
export type Icon = iconModule.Icon;

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

let sharedDeviceManager: DeviceManager = null;

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
    if (sharedDeviceManager === null) {
        sharedDeviceManager = new deviceManagerModule.DeviceManager(new binding.DeviceManager());
    }
    return sharedDeviceManager;
}

export function getLocalDevice(): Promise<Device> {
    return getMatchingDevice(device => device.type === DeviceType.Local);
}

export function getRemoteDevice(): Promise<Device> {
    return getMatchingDevice(device => device.type === DeviceType.Remote);
}

export function getUsbDevice(options?: GetDeviceOptions): Promise<Device> {
    return getMatchingDevice(device => device.type === DeviceType.Usb, options);
}

export function getDevice(id: string, options?: GetDeviceOptions): Promise<Device> {
    return getMatchingDevice(device => device.id === id, options);
}

export interface GetDeviceOptions {
    timeout?: number | null;
}

async function getMatchingDevice(predicate: DevicePredicate, options: GetDeviceOptions = {}): Promise<Device> {
    const device = await findMatchingDevice(predicate);
    if (device !== null) {
        return device;
    }

    const { timeout = 0 } = options;
    if (timeout === 0) {
        throw new Error("Device not found");
    }

    const getDeviceEventually = new Promise((resolve: (device: Device) => void, reject: (error: Error) => void) => {
        const deviceManager = getDeviceManager();

        deviceManager.added.connect(onDeviceAdded);
        const timer = (timeout !== null) ? setTimeout(onTimeout, timeout) : null;

        findMatchingDevice(predicate)
            .then(device => {
                if (device !== null) {
                    onSuccess(device);
                }
            })
            .catch(onError);

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

            deviceManager.added.disconnect(onDeviceAdded);
        }
    });

    return await getDeviceEventually;
}

async function findMatchingDevice(predicate: DevicePredicate): Promise<Device | null> {
    const deviceManager = getDeviceManager();

    const devices = await deviceManager.enumerateDevices();

    const matching = devices.filter(predicate);
    if (matching.length === 0) {
        return null;
    }

    return matching[0];
}

type DevicePredicate = (device: Device) => boolean;