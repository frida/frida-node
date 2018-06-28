import { Icon } from "./icon";

export interface Application {
    identifier: string;
    name: string;
    pid: number;
    smallIcon: Icon;
    largeIcon: Icon;
}