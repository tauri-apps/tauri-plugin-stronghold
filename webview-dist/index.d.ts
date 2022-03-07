export interface Duration {
    secs: number;
    nanos: number;
}
export interface Status {
    snapshot: {
        status: string;
        data?: Duration;
    };
}
export interface SwarmInfo {
    peerId: string;
    listeningAddresses: string[];
}
export declare enum RelayDirection {
    Dialing = 0,
    Listening = 1,
    Both = 2
}
export declare enum RequestPermission {
    CheckVault = 0,
    CheckRecord = 1,
    WriteToStore = 2,
    ReadFromStore = 3,
    DeleteFromStore = 4,
    CreateNewVault = 5,
    WriteToVault = 6,
    RevokeData = 7,
    GarbageCollect = 8,
    ListIds = 9,
    ReadSnapshot = 10,
    WriteSnapshot = 11,
    FillSnapshot = 12,
    ClearCache = 13,
    ControlRequest = 14
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
export declare function setPasswordClearInterval(interval: Duration): Promise<unknown>;
declare class ProcedureExecutor {
    procedureArgs: {
        [k: string]: any;
    };
    command: string;
    constructor(isRemote: boolean, procedureArgs: {
        [k: string]: any;
    });
    generateSLIP10Seed(outputLocation: Location, sizeBytes?: number, hint?: RecordHint): Promise<void>;
    deriveSLIP10(chain: number[], source: 'Seed' | 'Key', sourceLocation: Location, outputLocation: Location, hint?: RecordHint): Promise<string>;
    recoverBIP39(mnemonic: string, outputLocation: Location, passphrase?: string, hint?: RecordHint): Promise<void>;
    generateBIP39(outputLocation: Location, passphrase?: string, hint?: RecordHint): Promise<void>;
    getPublicKey(privateKeyLocation: Location): Promise<string>;
    sign(privateKeyLocation: Location, msg: string): Promise<string>;
}
export declare class RemoteStore {
    path: string;
    peerId: string;
    constructor(path: string, peerId: string);
    get(location: Location): Promise<string>;
    insert(location: Location, record: string, lifetime?: Duration): Promise<void>;
}
export declare class RemoteVault extends ProcedureExecutor {
    path: string;
    peerId: string;
    constructor(path: string, peerId: string);
}
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
export declare class Vault extends ProcedureExecutor {
    path: string;
    name: string;
    flags: StrongholdFlag[];
    constructor(path: string, name: string, flags: StrongholdFlag[]);
    private get vault();
    insert(location: Location, record: string, recordHint?: RecordHint): Promise<void>;
    remove(location: Location, gc?: boolean): Promise<void>;
}
export declare class Communication {
    path: string;
    constructor(path: string);
    stop(): Promise<void>;
    startListening(addr?: string): Promise<string>;
    getSwarmInfo(): Promise<SwarmInfo>;
    addPeer(peerId: string, addr?: string, relayDirection?: RelayDirection): Promise<string>;
    changeRelayDirection(peerId: string, relayDirection: RelayDirection): Promise<string>;
    removeRelay(peerId: string): Promise<void>;
    allowAllRequests(peers: string[], setDefault?: boolean): Promise<void>;
    rejectAllRequests(peers: string[], setDefault?: boolean): Promise<void>;
    allowRequests(peers: string[], permissions: RequestPermission[], changeDefault?: boolean): Promise<void>;
    rejectRequests(peers: string[], permissions: RequestPermission[], changeDefault?: boolean): Promise<void>;
    removeFirewallRules(peers: string[]): Promise<void>;
    getRemoteVault(peerId: string): RemoteVault;
    getRemoteStore(peerId: string): RemoteStore;
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
    spawnCommunication(): Promise<Communication>;
}
export {};
