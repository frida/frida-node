import { binding } from "./native";

import { inspect } from "util";

export class Relay {
    private impl: RelayProperties;

    constructor({ address, username, password, kind }: RelayProperties) {
        this.impl = new binding.Relay(address, username, password, kind);
    }

    get address(): string {
        return this.impl.address;
    }

    get username(): string {
        return this.impl.username;
    }

    get password(): string {
        return this.impl.password;
    }

    get kind(): RelayKind {
        return this.impl.kind;
    }

    [inspect.custom](depth, options) {
        return inspect(this.impl, { ...options, depth });
    }
}

export interface RelayProperties {
    address: string;
    username: string;
    password: string;
    kind: RelayKind;
}

export enum RelayKind {
    TurnUDP = "turn-udp",
    TurnTCP = "turn-tcp",
    TurnTLS = "turn-tls"
}