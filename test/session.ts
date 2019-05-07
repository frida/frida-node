import * as frida from "../lib";
import { LabRat } from "./labrat";

import { expect } from "chai";
import "mocha";

declare function gc(): void;

describe("Session", function () {
    let target: LabRat;
    let session: frida.Session;

    before(async () => {
        target = await LabRat.start();
        session = await frida.attach(target.pid);
    });

    after(() => {
        target.stop();
    });

    afterEach(gc);

    it("should have some metadata", function () {
        expect(session.pid).to.equal(target.pid);
    });
});
