import * as frida from "../lib";
import { targetProgram } from "./data";

import { expect } from "chai";
import "mocha";
import { spawn, ChildProcess } from "child_process";

declare function gc(): void;

describe("Script", function () {
    let target: ChildProcess;
    let session: frida.Session;

    beforeEach(async () => {
        target = spawn(targetProgram(), [], {
            stdio: ["pipe", process.stdout, process.stderr]
        });
        session = await frida.attach(target.pid);
    });

    afterEach(() => {
        target.kill("SIGKILL");
        target.unref();
        gc();
    });

    it("should support rpc", async () => {
        const script = await session.createScript(
            "'use strict';" +
            "" +
            "rpc.exports = {" +
            "add: function (a, b) {" +
            "var result = a + b;" +
            "if (result < 0)" +
            "throw new Error('No');" +
            "return result;" +
            "}," +
            "sub: function (a, b) {" +
            "return a - b;" +
            "}," +
            "speak: function () {" +
            "var buf = Memory.allocUtf8String('Yo');" +
            "return Memory.readByteArray(buf, 2);" +
            "}" +
            "};");
        await script.load();

        const agent = script.exports;

        expect(await agent.add(2, 3)).to.equal(5);
        expect(await agent.sub(5, 3)).to.equal(2);

        let thrownException: Error | null = null;
        try {
            await agent.add(1, -2);
        } catch (e) {
            thrownException = e;
        }
        expect(thrownException).to.not.be.equal(null);
        expect(thrownException.message).to.equal("No");

        const buf = await agent.speak();
        expect(buf.toJSON().data).to.deep.equal([0x59, 0x6f]);
    });

    it("should fail rpc request if post() fails", async () => {
        const script = await session.createScript(
            "'use strict';" +
            "" +
            "rpc.exports = {" +
            "init: function () {" +
            "}" +
            "};");
        await script.load();

        await session.detach();

        let thrownException: Error | null = null;
        try {
            await script.exports.init();
        } catch (e) {
            thrownException = e;
        }
        expect(thrownException).to.not.equal(null);
        expect(thrownException.message).to.equal("Script is destroyed");
    });

    it("should fail rpc request if script is unloaded mid-request", async () => {
        const script = await session.createScript(
            "'use strict';" +
            "" +
            "rpc.exports = {" +
            "waitForever: function () {" +
            "return new Promise(function () {});" +
            "}" +
            "};");
        await script.load();

        setTimeout(() => script.unload(), 100);

        let thrownException: Error | null = null;
        try {
            await script.exports.waitForever();
        } catch (e) {
            thrownException = e;
        }
        expect(thrownException).to.not.equal(null);
        expect(thrownException.message).to.equal("Script is destroyed");
    });

    it("should fail rpc request if session gets detached mid-request", async () => {
        const script = await session.createScript(
            "'use strict';" +
            "" +
            "rpc.exports = {" +
            "waitForever: function () {" +
            "return new Promise(function () {});" +
            "}" +
            "};");
        await script.load();

        setTimeout(() => target.kill("SIGKILL"), 100);

        let thrownException: Error | null = null;
        try {
            await script.exports.waitForever();
        } catch (e) {
            thrownException = e;
        }
        expect(thrownException).to.not.equal(null);
        expect(thrownException.message).to.equal("Script is destroyed");
    });

    it("should support custom log handler", async () => {
        const script = await session.createScript(
            "'use strict';" +
            "" +
            "console.error(new Error('test message'))");

        script.logHandler = function (level, text) {
            expect(level).to.equal("error");
            expect(text).to.equal("Error: test message");
        };

        await script.load();
    });
});
