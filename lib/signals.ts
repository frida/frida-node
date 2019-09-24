export interface Signals {
    connect(name: string, handler: SignalHandler): void;
    disconnect(name: string, handler: SignalHandler): void;
}

export class Signal<T extends SignalHandler> {
    constructor(private signals: Signals, private name: string) {
    }

    connect(handler: T): void {
        this.signals.connect(this.name, handler);
    }

    disconnect(handler: T): void {
        this.signals.disconnect(this.name, handler);
    }
}

export type SignalHandler = (...args: any[]) => void;

export class SignalAdapter implements Signals {
    private proxyHandlers: Map<SignalHandler, SignalHandler> = new Map();

    constructor(protected signals: Signals) {
    }

    connect(name: string, handler: SignalHandler): void {
        const proxyHandler = this.getProxy(name, handler);
        if (proxyHandler !== null) {
            this.proxyHandlers.set(handler, proxyHandler);
            this.signals.connect(name, proxyHandler);
        } else {
            this.signals.connect(name, handler);
        }
    }

    disconnect(name: string, handler: SignalHandler): void {
        const proxyHandler = this.proxyHandlers.get(handler);
        this.signals.disconnect(name, (proxyHandler !== undefined) ? proxyHandler : handler);
    }

    protected getProxy(name: string, userHandler: SignalHandler): SignalHandler | null {
        return null;
    }
}