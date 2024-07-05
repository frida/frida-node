export interface SystemParameters {
    /**
     * Operating System details.
     */
    os: {
        /**
         * ID, e.g.: windows, macos, linux, ios, android, qnx, fedora, ubuntu, etc.
         */
        id: string;

        /**
         * Human-readable name, e.g. `"macOS"`.
         */
        name: string;

        /**
         * Human-readable version string, e.g. `"11.2.2"`.
         */
        version?: string;

        /**
         * Build version, e.g. `"21B91"`.
         */
        build?: string;
    }

    /**
     * Platform, same as `Process.platform` in GumJS.
     */
    platform: "windows" | "darwin" | "linux" | "qnx";

    /**
     * Architecture, same as `Process.arch` in GumJS.
     */
    arch: "ia32" | "x64" | "arm" | "arm64" | "mips";

    /**
     * Hardware details.
     */
    hardware?: {
        /**
         * Product type, e.g. `"iPad6,3"`.
         */
        product?: string;

        /**
         * Hardware platform, e.g. `"t8010"`.
         */
        platform?: string;

        /**
         * Hardware model, e.g. `"J71bAP"`.
         */
        model?: string;
    }

    /**
     * Level of access.
     */
    access: "full" | "jailed";

    /**
     * System name, e.g. `"Ole André’s iPhone"`.
     */
    name?: string;

    /**
     * iOS UDID (Unique Device ID).
     */
    udid?: string;

    /**
     * Details about cellular and networking interfaces.
     */
    interfaces?: SystemInterface[];

    /**
     * Android API level, e.g.: `30`.
     */
    apiLevel?: number;

    [name: string]: any;
}

export type SystemInterface = NetworkInterface | CellularInterface;

export interface NetworkInterface {
    type: "ethernet" | "wifi" | "bluetooth";

    /**
     * MAC address, e.g.: `"aa:bb:cc:dd:ee:ff"`.
     */
    address: string;
}

export interface CellularInterface {
    type: "cellular";

    /**
     * Phone number, e.g. `"+47 123 45 678"`.
     */
    phoneNumber: string;
}
