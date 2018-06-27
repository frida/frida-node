export interface Child {
    pid: number;
    parentPid: number;
    origin: ChildOrigin;
    identifier: string | null;
    path: string | null;
    argv: string[] | null;
    envp: { [name: string]: string } | null;
}

export enum ChildOrigin {
    Fork = "fork",
    Exec = "exec",
    Spawn = "spawn"
}