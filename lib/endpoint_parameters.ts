import { AuthenticatedSessionInfo } from "./authentication";
import { binding } from "./native";

import { inspect } from "util";

export class EndpointParameters {
    private impl: any;

    constructor({ address = null, port = null, certificate = null, authentication = null }: EndpointParametersSubset = {}) {
        let authToken: string | null = null;
        let authCallback: AuthenticationCallback | null = null;
        if (authentication !== null) {
            if (authentication.scheme === "token") {
                authToken = authentication.token;
            } else {
                authCallback = authentication.callback;
            }
        }

        this.impl = new binding.EndpointParameters(address, port, certificate, authToken, authCallback);
    }

    [inspect.custom]() {
        return "EndpointParameters {}";
    }
}

export interface EndpointParametersSubset {
    address?: string;
    port?: number;
    certificate?: string;
    authentication?: AuthenticationScheme;
}

export type AuthenticationScheme = TokenAuthenticationScheme | CallbackAuthenticationScheme;

export interface TokenAuthenticationScheme {
    scheme: "token";
    token: string;
}

export interface CallbackAuthenticationScheme {
    scheme: "callback";
    callback: AuthenticationCallback;
}

export type AuthenticationCallback = (token: string) => Promise<AuthenticatedSessionInfo>;
