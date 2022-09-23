export interface NetworkConfig {
}
export interface Duration {
    millis: number;
    nanos: number;
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
export declare function setPasswordClearInterval(interval: Duration): Promise<unknown>;
declare class ProcedureExecutor {
    procedureArgs: {
        [k: string]: any;
    };
    constructor(procedureArgs: {
        [k: string]: any;
    });
    generateSLIP10Seed(outputLocation: Location, sizeBytes?: number): Promise<void>;
    deriveSLIP10(chain: number[], source: 'Seed' | 'Key', sourceLocation: Location, outputLocation: Location): Promise<string>;
    recoverBIP39(mnemonic: string, outputLocation: Location, passphrase?: string): Promise<void>;
    generateBIP39(outputLocation: Location, passphrase?: string): Promise<void>;
    getEd25519PublicKey(privateKeyLocation: Location): Promise<string>;
    signEd25519(privateKeyLocation: Location, msg: string): Promise<string>;
}
export declare class Client {
    path: string;
    name: string;
    constructor(path: string, name: string);
    getVault(name: string): Vault;
    getStore(): Store;
}
export declare class Store {
    path: string;
    client: string;
    constructor(path: string, client: string);
    get(key: string): Promise<number[]>;
    insert(key: string, value: number[], lifetime?: Duration): Promise<void>;
    remove(key: string): Promise<number[] | null>;
}
export declare class Vault extends ProcedureExecutor {
    path: string;
    client: string;
    name: string;
    constructor(path: string, client: string, name: string);
    insert(key: string, secret: number[]): Promise<void>;
    remove(location: Location): Promise<void>;
}
export declare class Communication {
    path: string;
    constructor(path: string);
    connect(peer: string): Promise<string>;
    serve(): Promise<void>;
    private send;
    getSnapshotHierarchy(peer: string, client: string): Promise<void>;
    checkVault(peer: string, client: string, vault: string): Promise<boolean>;
    checkRecord(peer: string, client: string, location: Location): Promise<boolean>;
    writeToVault(peer: string, client: string, location: Location, payload: number[]): Promise<void>;
    revokeData(peer: string, client: string, location: Location): Promise<void>;
    deleteData(peer: string, client: string, location: Location): Promise<void>;
    readFromStore(peer: string, client: string, key: string): Promise<number[]>;
    writeToStore(peer: string, client: string, key: string, payload: number[], lifetime?: Duration): Promise<void>;
    deleteFromStore(peer: string, client: string, key: string): Promise<void>;
    generateSLIP10Seed(peer: string, client: string, outputLocation: Location, sizeBytes?: number): Promise<void>;
    deriveSLIP10(peer: string, client: string, chain: number[], source: 'Seed' | 'Key', sourceLocation: Location, outputLocation: Location): Promise<string>;
    recoverBIP39(peer: string, client: string, mnemonic: string, outputLocation: Location, passphrase?: string): Promise<void>;
    generateBIP39(peer: string, client: string, outputLocation: Location, passphrase?: string): Promise<void>;
    getEd25519PublicKey(peer: string, client: string, privateKeyLocation: Location): Promise<string>;
    signEd25519(peer: string, client: string, privateKeyLocation: Location, msg: string): Promise<string>;
    stop(): Promise<void>;
    startListening(addr?: string): Promise<string>;
    stopListening(): Promise<string>;
    addPeerAddr(peerId: string, addr: string): Promise<string>;
}
export declare class Stronghold {
    path: string;
    constructor(path: string, password: string);
    reload(password: string): Promise<void>;
    unload(): Promise<void>;
    loadClient(client: string): Promise<Client>;
    createClient(client: string): Promise<Client>;
    save(): Promise<void>;
    spawnCommunication(client: string, config?: NetworkConfig, keypair?: Location): Promise<Communication>;
}
export {};
