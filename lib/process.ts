import { Icon } from "./icon";

export interface Process {
    pid: number;
    name: string;
    smallIcon: Icon;
    largeIcon: Icon;
}