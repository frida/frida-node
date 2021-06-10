import { Cancellable } from "./cancellable";
import { Signals, Signal } from "./signals";

import { inspect } from "util";

export class Bus {
    detached: Signal<BusDetachedHandler>;
    message: Signal<BusMessageHandler>;

    constructor(private impl: any) {
        const signals: Signals = impl.signals;
        this.detached = new Signal<BusDetachedHandler>(signals, "detached");
        this.message = new Signal<BusMessageHandler>(signals, "message");
    }

    attach(cancellable?: Cancellable): Promise<void> {
        return this.impl.attach(cancellable);
    }

    post(message: any, data: Buffer | null = null): void {
        this.impl.post(message, data);
    }

    [inspect.custom](depth, options) {
        return "Bus {}";
    }
}

export type BusDetachedHandler = () => void;
export type BusMessageHandler = (message: any, data: Buffer | null) => void;
