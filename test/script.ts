import * as frida from "..";
import { targetProgram } from "./data";

import { expect } from "chai";
import "mocha";
import { spawn } from "child_process";

declare function gc(): void;

describe("Script", function () {
    var target;
    var session;

    beforeEach(function () {
        target = spawn(targetProgram(), [], {
            stdio: ["pipe", process.stdout, process.stderr]
        });
        return frida.attach(target.pid)
            .then(function (s) {
                session = s;
            });
    });

    afterEach(function () {
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

        (await agent.add(2, 3)).should.equal(5);
        (await agent.sub(5, 3)).should.equal(2);

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
