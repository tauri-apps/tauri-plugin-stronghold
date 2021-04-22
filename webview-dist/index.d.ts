export interface Duration {
    millis: number;
    nanos: number;
}
export interface Status {
    snapshot: {
        status: string;
        data?: Duration;
    };
}
declare type Unregister = () => void;
export declare enum StrongholdFlag {
}
export declare class Location {
    type: string;
    payload: {
        [key: string]: any;
    };
    constructor(type: string, payload: {
        [key: string]: any;
    });
    static generic(vaultName: string, recordName: string): Location;
    static counter(vaultName: string, counter: number): Location;
}
export declare type RecordHint = [number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number];
export declare function setPasswordClearInterval(interval: Duration): any;
export declare class Store {
    path: string;
    name: string;
    flags: StrongholdFlag[];
    constructor(path: string, name: string, flags: StrongholdFlag[]);
    private get vault();
    get(location: Location): Promise<string>;
    insert(location: Location, record: string, lifetime?: Duration): Promise<void>;
    remove(location: Location): Promise<void>;
}
export declare class Vault {
    path: string;
    name: string;
    flags: StrongholdFlag[];
    constructor(path: string, name: string, flags: StrongholdFlag[]);
    private get vault();
    insert(location: Location, record: string, recordHint?: RecordHint): Promise<void>;
    remove(location: Location, gc?: boolean): Promise<void>;
    generateSLIP10Seed(outputLocation: Location, sizeBytes?: number, hint?: RecordHint): Promise<void>;
    deriveSLIP10(chain: number[], source: 'Seed' | 'Key', sourceLocation: Location, outputLocation: Location, hint?: RecordHint): Promise<string>;
    recoverBIP39(mnemonic: string, outputLocation: Location, passphrase?: string, hint?: RecordHint): Promise<void>;
    generateBIP39(outputLocation: Location, passphrase?: string, hint?: RecordHint): Promise<void>;
    getPublicKey(privateKeyLocation: Location): Promise<string>;
    sign(privateKeyLocation: Location, msg: string): Promise<string>;
}
export declare class Stronghold {
    path: string;
    constructor(path: string, password: string);
    reload(password: string): Promise<void>;
    unload(): Promise<void>;
    getVault(name: string, flags: StrongholdFlag[]): Vault;
    getStore(name: string, flags: StrongholdFlag[]): Store;
    save(): Promise<void>;
    getStatus(): Promise<Status>;
    onStatusChange(cb: (status: Status) => void): Unregister;
}
export {};
