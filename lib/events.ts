export interface Events {
    listen(event: string, handler: EventHandler);
    unlisten(event: string, handler: EventHandler);
}

export type EventHandler = (...args: any[]) => void;

export class EventAdapter implements Events {
    protected events: Events;

    private proxyHandlers: Map<EventHandler, EventHandler> = new Map();

    constructor(events: Events) {
        this.events = events;
    }

    listen(signal: string, handler: EventHandler): void {
        const proxyHandler = this.getProxy(signal, handler);
        if (proxyHandler !== null) {
            this.proxyHandlers.set(handler, proxyHandler);
            this.events.listen(signal, proxyHandler);
        } else {
            this.events.listen(signal, handler);
        }
    }

    unlisten(signal: string, handler: EventHandler): void {
        const proxyHandler = this.proxyHandlers.get(handler);
        this.events.unlisten(signal, (proxyHandler !== undefined) ? proxyHandler : handler);
    }

    protected getProxy(signal: string, userHandler: EventHandler): EventHandler | null {
        return null;
    }
}