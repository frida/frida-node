export interface Signals {
    connect(name: string, handler: SignalHandler);
    disconnect(name: string, handler: SignalHandler);
}

export class Signal<T extends SignalHandler> {
    private signals: Signals;
    private name: string;

    constructor(signals: Signals, name: string) {
        this.signals = signals;
        this.name = name;
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
    protected signals: Signals;

    private proxyHandlers: Map<SignalHandler, SignalHandler> = new Map();

    constructor(signals: Signals) {
        this.signals = signals;
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