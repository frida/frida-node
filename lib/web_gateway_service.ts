import { Cancellable } from "./cancellable";
import { EndpointParameters } from "./endpoint_parameters";
import { binding } from "./native";

import { inspect } from "util";

export class WebGatewayService {
    private impl: any;

    constructor({ gatewayParams = null, targetParams = null, root = null, origin = null }: WebGatewayServiceOptions = {}) {
        this.impl = new binding.WebGatewayService(gatewayParams, targetParams, root, origin);
    }

    start(cancellable?: Cancellable): Promise<void> {
        return this.impl.start(cancellable);
    }

    stop(cancellable?: Cancellable): Promise<void> {
        return this.impl.stop(cancellable);
    }

    [inspect.custom]() {
        return "WebGatewayService {}";
    }
}

export interface WebGatewayServiceOptions {
    gatewayParams?: EndpointParameters;
    targetParams?: EndpointParameters;
    root?: string;
    origin?: string;
}
