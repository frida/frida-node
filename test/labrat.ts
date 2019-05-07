import { targetProgram } from "./data";

import { spawn, ChildProcess } from "child_process";

export class LabRat {
    private childProcess: ChildProcess;

    private constructor(childProcess: ChildProcess) {
        this.childProcess = childProcess;
    }

    get pid(): number {
        return this.childProcess.pid;
    }

    static async start(): Promise<LabRat> {
        const childProcess = spawn(targetProgram(), [], {
            stdio: ["pipe", process.stdout, process.stderr]
        });

        // TODO: improve injectors to handle injection into a process that hasn't yet finished initializing
        await sleep(50);

        return new LabRat(childProcess);
    }

    stop(): void {
        this.childProcess.kill("SIGKILL");
        this.childProcess.unref();
    }
}

function sleep(delay: number): Promise<void> {
    return new Promise(resolve => {
        setTimeout(() => { resolve(); }, delay);
    });
}