declare type BytesDto = string | number[];
export declare type ClientPath = string | Iterable<number> | ArrayLike<number> | ArrayBuffer;
export declare type VaultPath = string | Iterable<number> | ArrayLike<number> | ArrayBuffer;
export declare type RecordPath = string | Iterable<number> | ArrayLike<number> | ArrayBuffer;
export declare type StoreKey = string | Iterable<number> | ArrayLike<number> | ArrayBuffer;
export interface ConnectionLimits {
    maxPendingIncoming?: number;
    maxPendingOutgoing?: number;
    maxEstablishedIncoming?: number;
    maxEstablishedOutgoing?: number;
    maxEstablishedPerPeer?: number;
    maxEstablishedTotal?: number;
}
export interface PeerAddress {
    known: string[];
    use_relay_fallback: boolean;
}
export interface AddressInfo {
    peers: Map<string, PeerAddress>;
    relays: string[];
}
export interface ClientAccess {
    useVaultDefault?: boolean;
    useVaultExceptions?: Map<VaultPath, boolean>;
    writeVaultDefault?: boolean;
    writeVaultExceptions?: Map<VaultPath, boolean>;
    cloneVaultDefault?: boolean;
    cloneVaultExceptions?: Map<VaultPath, boolean>;
    readStore?: boolean;
    writeStore?: boolean;
}
export interface Permissions {
    default?: ClientAccess;
    exceptions?: Map<VaultPath, ClientAccess>;
}
export interface NetworkConfig {
    requestTimeout?: Duration;
    connectionTimeout?: Duration;
    connectionsLimit?: ConnectionLimits;
    enableMdns?: boolean;
    enableRelay?: boolean;
    addresses?: AddressInfo;
    peerPermissions?: Map<string, Permissions>;
    permissionsDefault?: Permissions;
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
    static generic(vault: VaultPath, record: RecordPath): Location;
    static counter(vault: VaultPath, counter: number): Location;
}
declare class ProcedureExecutor {
    procedureArgs: {
        [k: string]: any;
    };
    constructor(procedureArgs: {
        [k: string]: any;
    });
    generateSLIP10Seed(outputLocation: Location, sizeBytes?: number): Promise<Uint8Array>;
    deriveSLIP10(chain: number[], source: 'Seed' | 'Key', sourceLocation: Location, outputLocation: Location): Promise<Uint8Array>;
    recoverBIP39(mnemonic: string, outputLocation: Location, passphrase?: string): Promise<Uint8Array>;
    generateBIP39(outputLocation: Location, passphrase?: string): Promise<Uint8Array>;
    getEd25519PublicKey(privateKeyLocation: Location): Promise<Uint8Array>;
    signEd25519(privateKeyLocation: Location, msg: string): Promise<Uint8Array>;
}
export declare class Client {
    path: string;
    name: BytesDto;
    constructor(path: string, name: ClientPath);
    getVault(name: VaultPath): Vault;
    getStore(): Store;
}
export declare class Store {
    path: string;
    client: BytesDto;
    constructor(path: string, client: BytesDto);
    get(key: StoreKey): Promise<Uint8Array>;
    insert(key: StoreKey, value: number[], lifetime?: Duration): Promise<void>;
    remove(key: StoreKey): Promise<Uint8Array | null>;
}
export declare class Vault extends ProcedureExecutor {
    path: string;
    client: BytesDto;
    name: BytesDto;
    constructor(path: string, client: ClientPath, name: VaultPath);
    insert(recordPath: RecordPath, secret: number[]): Promise<void>;
    remove(location: Location): Promise<void>;
}
export declare class Communication {
    path: string;
    constructor(path: string);
    connect(peer: string): Promise<string>;
    serve(): Promise<void>;
    private send;
    getSnapshotHierarchy(peer: string, client: ClientPath): Promise<void>;
    checkVault(peer: string, client: ClientPath, vault: VaultPath): Promise<boolean>;
    checkRecord(peer: string, client: ClientPath, location: Location): Promise<boolean>;
    writeToVault(peer: string, client: ClientPath, location: Location, payload: number[]): Promise<void>;
    revokeData(peer: string, client: ClientPath, location: Location): Promise<void>;
    deleteData(peer: string, client: ClientPath, location: Location): Promise<void>;
    readFromStore(peer: string, client: ClientPath, key: StoreKey): Promise<number[]>;
    writeToStore(peer: string, client: ClientPath, key: StoreKey, payload: number[], lifetime?: Duration): Promise<void>;
    deleteFromStore(peer: string, client: ClientPath, key: StoreKey): Promise<void>;
    generateSLIP10Seed(peer: string, client: ClientPath, outputLocation: Location, sizeBytes?: number): Promise<Uint8Array>;
    deriveSLIP10(peer: string, client: ClientPath, chain: number[], source: 'Seed' | 'Key', sourceLocation: Location, outputLocation: Location): Promise<Uint8Array>;
    recoverBIP39(peer: string, client: ClientPath, mnemonic: string, outputLocation: Location, passphrase?: string): Promise<Uint8Array>;
    generateBIP39(peer: string, client: ClientPath, outputLocation: Location, passphrase?: string): Promise<Uint8Array>;
    getEd25519PublicKey(peer: string, client: ClientPath, privateKeyLocation: Location): Promise<Uint8Array>;
    signEd25519(peer: string, client: ClientPath, privateKeyLocation: Location, msg: string): Promise<Uint8Array>;
    stop(): Promise<void>;
    startListening(addr?: string): Promise<string>;
    stopListening(): Promise<string>;
    addPeerAddr(peerId: string, addr: string): Promise<string>;
}
export declare class Stronghold {
    path: string;
    constructor(path: string, password: string);
    private reload;
    unload(): Promise<void>;
    loadClient(client: ClientPath): Promise<Client>;
    createClient(client: ClientPath): Promise<Client>;
    save(): Promise<void>;
    spawnCommunication(client: ClientPath, config?: NetworkConfig, keypair?: Location): Promise<Communication>;
}
export {};
