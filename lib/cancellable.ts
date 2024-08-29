import { binding } from "./native";
import { Signal } from "./signals";

import { inspect } from "util";

export class Cancellable {
    private impl = new binding.Cancellable();

    cancelled: Signal<CancelledHandler>;

    constructor() {
        const { signals } = this.impl;
        this.cancelled = new Signal<CancelledHandler>(signals, "cancelled");
    }

    get isCancelled(): boolean {
        return this.impl.isCancelled;
    }

    throwIfCancelled(): void {
        this.impl.throwIfCancelled();
    }

    cancel(): void {
        return this.impl.cancel();
    }

    [inspect.custom]() {
        return "Cancellable {}";
    }

    combine(other: Cancellable): Cancellable {
        const cancel = new Cancellable();
        this.cancelled.connect(() => cancel.cancel());
        other.cancelled.connect(() => cancel.cancel());
        if (this.isCancelled) cancel.cancel();
        if (other.isCancelled) cancel.cancel();
        return cancel;
    }

    public static withTimeout(ms): Cancellable {
        const cancel = new Cancellable();
        setTimeout(() => cancel.cancel(), ms).unref();
        return cancel;
    }
}

export type CancelledHandler = () => void;
