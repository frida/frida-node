import * as frida from "..";

import { expect } from "chai";
import "mocha";

declare function gc(): void;

describe("Device", function () {
    afterEach(gc);

    it("should have some metadata", async () => {
        const device = await frida.getLocalDevice();
        expect(device).to.include.keys("id", "name", "icon", "type", "events");
        expect(device.id).to.be.an.instanceof(String);
        expect(device.name).to.be.an.instanceof(String);
        expect(device.name).to.equal("Local System");
        expect(device.type).to.be.an.instanceof(String);
        expect(device.type).to.equal("local");
    });

    it("should enumerate processes", async () => {
        const device = await frida.getLocalDevice();

        const processes = await device.enumerateProcesses();
        expect(processes.length).to.be.above(0);

        const process = processes[0];
        expect(process).to.include.keys("pid", "name", "smallIcon", "largeIcon");
        expect(process.pid).to.be.an.instanceof(Number);
        expect(process.name).to.be.an.instanceof(String);
    });
});
