import * as applicationModule from "./application";
import * as cancellableModule from "./cancellable";
import * as childModule from "./child";
import * as crashModule from "./crash";
import * as deviceManagerModule from "./device_manager";
import * as deviceModule from "./device";
import * as iconModule from "./icon";
import * as iostreamModule from "./iostream";
import * as processModule from "./process";
import * as scriptModule from "./script";
import * as sessionModule from "./session";
import * as spawnModule from "./spawn";

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
export const Stdio = deviceModule.Stdio;

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

export type IOStream = iostreamModule.IOStream;
export const IOStream = iostreamModule.IOStream;
export type Cancellable = cancellableModule.Cancellable;
export const Cancellable = cancellableModule.Cancellable;

export type Application = applicationModule.Application;
export type Process = processModule.Process;
export type Spawn = spawnModule.Spawn;
export type Child = childModule.Child;
export type ChildOrigin = childModule.ChildOrigin;
export const ChildOrigin = childModule.ChildOrigin;
export type Crash = crashModule.Crash;
export type CrashParameters = crashModule.CrashParameters;
export type Icon = iconModule.Icon;

let sharedDeviceManager: DeviceManager = null;

export async function spawn(program: string | string[], options: SpawnOptions = {}, cancellable?: Cancellable): Promise<number> {
    const device = await getLocalDevice(cancellable);
    return await device.spawn(program, options, cancellable);
}

export async function resume(target: number | string, cancellable?: Cancellable): Promise<void> {
    const device = await getLocalDevice(cancellable);
    await device.resume(target, cancellable);
}

export async function kill(target: number | string, cancellable?: Cancellable): Promise<void> {
    const device = await getLocalDevice(cancellable);
    await device.kill(target, cancellable);
}

export async function attach(target: number | string, cancellable?: Cancellable): Promise<Session> {
    const device = await getLocalDevice(cancellable);
    return await device.attach(target, cancellable);
}

export async function injectLibraryFile(target: number | string, path: string, entrypoint: string, data: string,
        cancellable?: Cancellable): Promise<number> {
    const device = await getLocalDevice(cancellable);
    return await device.injectLibraryFile(target, path, entrypoint, data, cancellable);
}

export async function injectLibraryBlob(target: number | string, blob: Buffer, entrypoint: string, data: string,
        cancellable?: Cancellable): Promise<number> {
    const device = await getLocalDevice(cancellable);
    return await device.injectLibraryBlob(target, blob, entrypoint, data, cancellable);
}

export async function enumerateDevices(cancellable?: Cancellable): Promise<Device[]> {
    const deviceManager = getDeviceManager();
    return await deviceManager.enumerateDevices(cancellable);
};

export function getDeviceManager(): DeviceManager {
    if (sharedDeviceManager === null) {
        sharedDeviceManager = new deviceManagerModule.DeviceManager();
    }
    return sharedDeviceManager;
}

export function getLocalDevice(cancellable?: Cancellable): Promise<Device> {
    return getMatchingDevice(device => device.type === DeviceType.Local, {}, cancellable);
}

export function getRemoteDevice(cancellable?: Cancellable): Promise<Device> {
    return getMatchingDevice(device => device.type === DeviceType.Remote, {}, cancellable);
}

export function getUsbDevice(options?: GetDeviceOptions, cancellable?: Cancellable): Promise<Device> {
    return getMatchingDevice(device => device.type === DeviceType.Usb, options, cancellable);
}

export function getDevice(id: string, options?: GetDeviceOptions, cancellable?: Cancellable): Promise<Device> {
    return getMatchingDevice(device => device.id === id, options, cancellable);
}

export interface GetDeviceOptions {
    timeout?: number | null;
}

async function getMatchingDevice(predicate: DevicePredicate, options: GetDeviceOptions = {}, cancellable?: Cancellable): Promise<Device> {
    const device = await findMatchingDevice(predicate, cancellable);
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

        if (cancellable !== undefined) {
            cancellable.cancelled.connect(onCancel);
            if (cancellable.isCancelled) {
                onCancel();
                return;
            }
        }

        findMatchingDevice(predicate, cancellable)
            .then(device => {
                if (device !== null) {
                    onSuccess(device);
                }
            })
            .catch(onError);

        function onDeviceAdded(device: Device): void {
            if (predicate(device)) {
                onSuccess(device);
            }
        }

        function onSuccess(device: Device): void {
            stopMonitoring();
            resolve(device);
        }

        function onError(error: Error): void {
            stopMonitoring();
            reject(error);
        }

        function onTimeout(): void {
            onError(new Error("Timed out while waiting for device to appear"));
        }

        function onCancel(): void {
            onError(new Error("Operation was cancelled"));
        }

        function stopMonitoring(): void {
            if (cancellable !== undefined) {
                cancellable.cancelled.disconnect(onCancel);
            }

            if (timer !== null) {
                clearTimeout(timer);
            }

            deviceManager.added.disconnect(onDeviceAdded);
        }
    });

    return await getDeviceEventually;
}

async function findMatchingDevice(predicate: DevicePredicate, cancellable?: Cancellable): Promise<Device | null> {
    const deviceManager = getDeviceManager();

    const devices = await deviceManager.enumerateDevices(cancellable);

    const matching = devices.filter(predicate);
    if (matching.length === 0) {
        return null;
    }

    return matching[0];
}

type DevicePredicate = (device: Device) => boolean;