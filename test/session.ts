import * as frida from "..";
import { targetProgram } from "./data";

import { expect } from "chai";
import "mocha";
import { spawn, ChildProcess } from "child_process";

declare function gc(): void;

describe("Session", function () {
    let target: ChildProcess;
    let session: any;

    before(async () => {
        target = spawn(targetProgram(), [], {
            stdio: ["pipe", process.stdout, process.stderr]
        });
        session = await frida.attach(target.pid);
    });

    after(() => {
        target.kill("SIGKILL");
        target.unref();
    });

    afterEach(gc);

    it("should have some metadata", function () {
        expect(session).to.have.property("pid");
        expect(session.pid).to.equal(target.pid);
    });
});
