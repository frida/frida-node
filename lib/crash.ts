export interface Crash {
    pid: number;
    processName: string;
    report: string;
    parameters: CrashParameters;
}

export interface CrashParameters {
    [name: string]: string | number | boolean;
}
