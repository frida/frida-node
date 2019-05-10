import * as frida from "../lib";
import { LabRat } from "./labrat";

import { expect } from "chai";
import "mocha";

declare function gc(): void;

describe("Session", () => {
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

    it("should have some metadata", () => {
        expect(session.pid).to.equal(target.pid);
    });

    it("should support specifying which script runtime to use", async () => {
        expect(await evaluteScript("Script.runtime")).to.equal("DUK");
        expect(await evaluteScript("Script.runtime", { runtime: frida.ScriptRuntime.Default })).to.equal("DUK");
        expect(await evaluteScript("Script.runtime", { runtime: frida.ScriptRuntime.Duk })).to.equal("DUK");
        expect(await evaluteScript("Script.runtime", { runtime: frida.ScriptRuntime.V8 })).to.equal("V8");

        expect(await evaluteScript("Script.runtime")).to.equal("DUK");
        await session.enableJit();
        expect(await evaluteScript("Script.runtime")).to.equal("V8");

        const bytes = await session.compileScript("console.log('Hello World!');", { runtime: frida.ScriptRuntime.Duk });
        expect(bytes).instanceOf(Buffer);
        expect(bytes.length).to.be.greaterThan(0);
    });

    async function evaluteScript(expression: string, options?: frida.ScriptOptions): Promise<string> {
        const script = await session.createScript(`send(${expression});`, options);

        const getMessageRequest = getNextMessage(script);
        await script.load();

        const message = await getMessageRequest;

        await script.unload();

        if (message.type !== frida.MessageType.Send) {
            throw new Error("Unexpected message type");
        }

        return message.payload;
    }

    function getNextMessage(script: frida.Script): Promise<frida.Message> {
        return new Promise(resolve => {
            script.message.connect(onMessage);

            function onMessage(message: frida.Message): void {
                resolve(message);
                script.message.disconnect(onMessage);
            }
        })
}});