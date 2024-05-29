import { Cancellable } from "./cancellable";
import { Signals, Signal } from "./signals";

import { inspect } from "util";

export class Service {
    close: Signal<ServiceCloseHandler>;
    message: Signal<ServiceMessageHandler>;

    constructor(private impl: any) {
        const signals: Signals = impl.signals;
        this.close = new Signal<ServiceCloseHandler>(signals, "close");
        this.message = new Signal<ServiceMessageHandler>(signals, "message");
    }

    activate(cancellable?: Cancellable): Promise<void> {
        return this.impl.activate(cancellable);
    }

    cancel(cancellable?: Cancellable): Promise<void> {
        return this.impl.cancel(cancellable);
    }

    request(parameters: any, cancellable?: Cancellable): Promise<any> {
        return this.impl.request(parameters, cancellable);
    }

    [inspect.custom](depth, options) {
        return "Service {}";
    }
}

export type ServiceCloseHandler = () => void;
export type ServiceMessageHandler = (message: any) => void;
