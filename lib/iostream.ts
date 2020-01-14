import { Cancellable } from "./cancellable";

import { Duplex } from "stream";

export class IOStream extends Duplex {
    private pending = new Set<Promise<void>>();

    private cancellable = new Cancellable();

    constructor(private impl: any) {
        super({});
    }

    async _destroy(error: Error | null, callback: (error: Error | null) => void): Promise<void> {
        this.cancellable.cancel();

        for (const operation of this.pending) {
            try {
                await operation;
            } catch (e) {
            }
        }

        try {
            await this.impl.close();
        } catch (e) {
        }

        callback(error);
    }

    _read(size: number): void {
        const operation = this.impl.read(size, this.cancellable)
            .then((data: Buffer): void => {
                const isEof = data.length === 0;
                if (isEof) {
                    this.push(null);
                    return;
                }

                this.push(data);
            })
            .catch((error: Error): void => {
                if (this.impl.isClosed) {
                    this.push(null);
                }
                this.emit("error", error);
            });
        this.track(operation);
    }

    _write(chunk: any, encoding: BufferEncoding, callback: (error?: Error | null) => void): void {
        let data: Buffer;
        if (Buffer.isBuffer(chunk)) {
            data = chunk;
        } else {
            data = Buffer.from(chunk, encoding);
        }

        const operation = this.impl.write(data, this.cancellable)
            .then((): void => {
                callback(null);
            })
            .catch((error: Error): void => {
                callback(error);
            });
        this.track(operation);
    }

    private track(operation: Promise<void>): void {
        this.pending.add(operation);
        operation
            .catch(_ => {})
            .finally(() => {
                this.pending.delete(operation);
            });
    }
}
