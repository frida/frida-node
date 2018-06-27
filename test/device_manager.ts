import * as frida from "../lib";

import { expect } from "chai";
import "mocha";

declare function gc(): void;

describe("DeviceManager", function () {
    afterEach(gc);

    it("should enumerate devices", async () => {
        const deviceManager = frida.getDeviceManager();
        const devices = await deviceManager.enumerateDevices();
        expect(devices.length).to.be.above(0);
    });
});
