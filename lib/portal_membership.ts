import { Cancellable } from "./cancellable";

export class PortalMembership {
    constructor(private impl: any) {
    }

    terminate(cancellable?: Cancellable): Promise<void> {
        return this.impl.terminate(cancellable);
    }
}
