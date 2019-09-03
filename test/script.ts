import * as frida from "../lib";
import { LabRat } from "./labrat";

import { expect } from "chai";
import "mocha";

declare function gc(): void;

describe("Script", function () {
    let target: LabRat;
    let session: frida.Session;

    beforeEach(async () => {
        target = await LabRat.start();
        session = await frida.attach(target.pid);
    });

    afterEach(() => {
        target.stop();
        gc();
    });

    it("should support rpc", async () => {
        const script = await session.createScript(
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
            "rpc.exports = {" +
            "waitForever: function () {" +
            "return new Promise(function () {});" +
            "}" +
            "};");
        await script.load();

        setTimeout(() => target.stop(), 100);

        let thrownException: Error | null = null;
        try {
            await script.exports.waitForever();
        } catch (e) {
            thrownException = e;
        }
        expect(thrownException).to.not.equal(null);
        expect(thrownException.message).to.equal("Script is destroyed");
    });

    it("should fail rpc request if cancelled mid-request", async () => {
        const cancellable = new frida.Cancellable();

        const script = await session.createScript(
            "rpc.exports = {" +
            "waitForever: function () {" +
            "return new Promise(function () {});" +
            "}" +
            "};", {}, cancellable);
        await script.load(cancellable);

        setTimeout(() => cancellable.cancel(), 100);

        let thrownException: Error | null = null;
        try {
            await script.exports.waitForever(cancellable);
        } catch (e) {
            thrownException = e;
        }
        expect(thrownException).to.not.equal(null);
        expect(thrownException.message).to.equal("Operation was cancelled");
    });

    it("should support returning rpc exports object from async method", async () => {
        const api = await load();
        expect(await api.hello()).to.equal("Is it me you're looking for?");

        async function load(): Promise<frida.ScriptExports> {
            const script = await session.createScript(`
            rpc.exports.hello = function () {
                return "Is it me you're looking for?";
            };`);
            await script.load();

            const api = script.exports;

            expect(api.then).to.be.undefined;
            expect(api.catch).to.be.undefined;
            expect(api.finally).to.be.undefined;

            return api;
        }
    });

    it("should support custom log handler", async () => {
        const script = await session.createScript("console.error(new Error('test message'))");

        script.logHandler = function (level, text) {
            expect(level).to.equal("error");
            expect(text).to.equal("Error: test message");
        };

        await script.load();
    });
});
