/** A duration definition. */
export interface Duration {
    /** The number of whole seconds contained by this Duration. */
    secs: number;
    /** The fractional part of this Duration, in nanoseconds. */
    nanos: number;
}
/** The stronghold status. */
export interface Status {
    /** The snapshot status. */
    snapshot: {
        status: 'unlocked';
        /**
         * The amount of time left before the snapshot is locked.
         */
        data?: Duration;
    } | {
        status: 'locked';
    };
}
/** Swarm information of the local peer. */
export interface SwarmInfo {
    /** Peer id. */
    peerId: string;
    /** List of listening addresses. */
    listeningAddresses: string[];
}
/** Relay direction. */
export declare enum RelayDirection {
    Dialing = 0,
    Listening = 1,
    Both = 2
}
/** Permissions that can be set for P2P access of a stronghold. */
export declare enum RequestPermission {
    /** Allow checking if a vault exists. */
    CheckVault = 0,
    /** Allow checking if a record exists. */
    CheckRecord = 1,
    /** Allow writing to the store. */
    WriteToStore = 2,
    /** Allow reading the store. */
    ReadFromStore = 3,
    /** Allow deleting store records. */
    DeleteFromStore = 4,
    /** Allow creating new vaults. */
    CreateNewVault = 5,
    /** Allow writing to a vault. */
    WriteToVault = 6,
    /** Allow deleting vault records. */
    RevokeData = 7,
    /** Allow garbage collecting the stronghold. */
    GarbageCollect = 8,
    /** Allow listing vault ids. */
    ListIds = 9,
    /** Allow reading data from a snapshot. */
    ReadSnapshot = 10,
    /** Allow writing to a snapshot. */
    WriteSnapshot = 11,
    /** Allow writing a client to the snapshot. */
    FillSnapshot = 12,
    /** Allow clearing the snapshot cache. */
    ClearCache = 13,
    /** Allow running procedures. */
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
/**
 * The record hint can be used to identify a record for further access
 * using the `listIds` API.
 * It is a number array with size 24.
*/
export declare type RecordHint = [number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number];
/**
 * Sets the interval used to clear the password cache.
 * The cache is cleared after `interval` if the stronghold is not accessed.
 * @param interval
 * @returns
 */
export declare function setPasswordClearInterval(interval: Duration): Promise<unknown>;
declare class ProcedureExecutor {
    procedureArgs: {
        [k: string]: any;
    };
    command: string;
    constructor(isRemote: boolean, procedureArgs: {
        [k: string]: any;
    });
    /**
     * Generate a SLIP10 seed on the given location.
     * @param outputLocation Location of the record where the seed will be stored.
     * @param sizeBytes The size in bytes of the SLIP10 seed.
     * @param hint The record hint.
     * @returns
     */
    generateSLIP10Seed(outputLocation: Location, sizeBytes?: number, hint?: RecordHint): Promise<void>;
    /**
     * Derive a SLIP10 private key using a seed or key.
     * @param chain The chain path.
     * @param source The source type, either 'Seed' or 'Key'.
     * @param sourceLocation The source location, must be the `outputLocation` of a previous call to `generateSLIP10Seed` or `deriveSLIP10`.
     * @param outputLocation Location of the record where the private key will be stored.
     * @param hint The record hint.
     * @returns
     */
    deriveSLIP10(chain: number[], source: 'Seed' | 'Key', sourceLocation: Location, outputLocation: Location, hint?: RecordHint): Promise<string>;
    /**
     * Store a BIP39 mnemonic.
     * @param mnemonic The mnemonic string.
     * @param outputLocation The location of the record where the BIP39 mnemonic will be stored.
     * @param passphrase The optional mnemonic passphrase.
     * @param hint The record hint.
     * @returns
     */
    recoverBIP39(mnemonic: string, outputLocation: Location, passphrase?: string, hint?: RecordHint): Promise<void>;
    /**
     * Generate a BIP39 seed.
     * @param outputLocation The location of the record where the BIP39 seed will be stored.
     * @param passphrase The optional mnemonic passphrase.
     * @param hint The record hint.
     * @returns
     */
    generateBIP39(outputLocation: Location, passphrase?: string, hint?: RecordHint): Promise<void>;
    /**
     * Gets the Ed25519 public key of a SLIP10 private key.
     * @param privateKeyLocation The location of the private key. Must be the `outputLocation` of a previous call to `deriveSLIP10`.
     * @returns A promise resolving to the public key hex string.
     */
    getPublicKey(privateKeyLocation: Location): Promise<string>;
    /**
     * Creates a Ed25519 signature from a private key.
     * @param privateKeyLocation The location of the record where the private key is stored. Must be the `outputLocation` of a previous call to `deriveSLIP10`.
     * @param msg The message to sign.
     * @returns A promise resolving to the signature hex string.
     */
    sign(privateKeyLocation: Location, msg: string): Promise<string>;
}
/**
 * A stronghold store that is accessed remotely via a P2P connection.
 */
export declare class RemoteStore {
    /** The snapshot path. */
    path: string;
    /** The peer id. */
    peerId: string;
    /** @ignore */
    constructor(path: string, peerId: string);
    /**
     * Read the remote store with the given location key.
     * @param location The record location.
     * @returns
     */
    get(location: Location): Promise<string>;
    /**
     * Insert the key-value pair to the remote store.
     * @param location The record location.
     * @param record The data to store on the record.
     * @param lifetime The amount of time the record must live.
     * @returns
     */
    insert(location: Location, record: string, lifetime?: Duration): Promise<void>;
}
/**
 * A stronghold vault that is accessed remotely via a P2P connection.
 */
export declare class RemoteVault extends ProcedureExecutor {
    /** The snapshot path. */
    path: string;
    /** The peer id. */
    peerId: string;
    /** @ignore */
    constructor(path: string, peerId: string);
}
/**
 * A key-value storage that allows create, read, update and delete operations.
 */
export declare class Store {
    /** The snapshot path. */
    path: string;
    /** The store name. */
    name: string;
    /** The store permission flags. */
    flags: StrongholdFlag[];
    /** @ignore */
    constructor(path: string, name: string, flags: StrongholdFlag[]);
    /** @ignore */
    private get store();
    /**
     * Read a record on the store.
     * @param location The record location.
     * @returns
     */
    get(location: Location): Promise<string>;
    /**
     * Save a record on the store.
     * @param location The record location.
     * @param record The data to store on the record.
     * @param lifetime The record lifetime.
     * @returns
     */
    insert(location: Location, record: string, lifetime?: Duration): Promise<void>;
    /**
     * Deletes a record.
     * @param location The record location.
     * @returns
     */
    remove(location: Location): Promise<void>;
}
/**
 * A key-value storage that allows create, update and delete operations.
 * It does not allow reading the data, so one of the procedures must be used to manipulate
 * the stored data, allowing secure storage of secrets.
 */
export declare class Vault extends ProcedureExecutor {
    /** The vault path. */
    path: string;
    /** The vault name. */
    name: string;
    /** The vault's permission flags. */
    flags: StrongholdFlag[];
    /** @ignore */
    constructor(path: string, name: string, flags: StrongholdFlag[]);
    /** @ignore */
    private get vault();
    /**
     * Insert a record to this vault.
     * @param location The record location.
     * @param record  The record data.
     * @param recordHint The record hint.
     * @returns
     */
    insert(location: Location, record: string, recordHint?: RecordHint): Promise<void>;
    /**
     * Remove a record from the vault.
     * @param location The record location.
     * @param gc Whether to additionally perform the gargage collection or not.
     * @returns
     */
    remove(location: Location, gc?: boolean): Promise<void>;
}
/**
 * Representation of a P2P connection with a remote stronghold.
 */
export declare class Communication {
    /** The snapshot path. */
    path: string;
    /** @ignore */
    constructor(path: string);
    /**
     * Stop the connection.
     */
    stop(): Promise<void>;
    /**
     * Start listening on the given address.
     * @param addr The address to connect to.
     * @returns
     */
    startListening(addr?: string): Promise<string>;
    /**
     * Gets the swarm information of the local peer.
     * @returns The swarm information.
     */
    getSwarmInfo(): Promise<SwarmInfo>;
    /**
     * Adds a peer.
     * @param peerId
     * @param addr
     * @param relayDirection
     * @returns
     */
    addPeer(peerId: string, addr?: string, relayDirection?: RelayDirection): Promise<string>;
    /**
     * Change the relay direction of the given peer.
     * @param peerId
     * @param relayDirection
     * @returns
     */
    changeRelayDirection(peerId: string, relayDirection: RelayDirection): Promise<string>;
    /**
     * Remove the relay on the given peer.
     * @param peerId
     * @returns
     */
    removeRelay(peerId: string): Promise<void>;
    /**
     * Allow all requests from the given peer list.
     * @param peers
     * @param setDefault
     * @returns
     */
    allowAllRequests(peers: string[], setDefault?: boolean): Promise<void>;
    /**
     * Reject all requests from the given peer list.
     * @param peers
     * @param setDefault
     * @returns
     */
    rejectAllRequests(peers: string[], setDefault?: boolean): Promise<void>;
    /**
     * Allow the specified set of requests from the given peer list.
     * @param peers
     * @param permissions
     * @param changeDefault
     * @returns
     */
    allowRequests(peers: string[], permissions: RequestPermission[], changeDefault?: boolean): Promise<void>;
    /**
     * Reject the specified set of requests from the given peer list.
     * @param peers
     * @param permissions
     * @param changeDefault
     * @returns
     */
    rejectRequests(peers: string[], permissions: RequestPermission[], changeDefault?: boolean): Promise<void>;
    /**
     * Remove firewall rules for the given peer list.
     * @param peers
     * @returns
     */
    removeFirewallRules(peers: string[]): Promise<void>;
    /**
     * Get a RemoteVault to interact with the given peer.
     * @param peerId
     * @returns
     */
    getRemoteVault(peerId: string): RemoteVault;
    /**
     * Get a RemoteStore to interact with the given peer.
     * @param peerId
     * @returns
     */
    getRemoteStore(peerId: string): RemoteStore;
}
/**
 * A representation of an access to a stronghold.
 */
export declare class Stronghold {
    path: string;
    /**
     * Initializes a stronghold.
     * If the snapshot path located at `path` exists, the password must match.
     * @param path
     * @param password
     */
    constructor(path: string, password: string);
    /**
     * Force a reload of the snapshot. The password must match.
     * @param password
     * @returns
     */
    reload(password: string): Promise<void>;
    /**
     * Remove this instance from the cache.
    */
    unload(): Promise<void>;
    /**
     * Get a vault by name.
     * @param name
     * @param flags
     * @returns
     */
    getVault(name: string, flags: StrongholdFlag[]): Vault;
    /**
     * Get a store by name.
     * @param name
     * @param flags
     * @returns
     */
    getStore(name: string, flags: StrongholdFlag[]): Store;
    /**
     * Persists the stronghold state to the snapshot.
     * @returns
     */
    save(): Promise<void>;
    /**
     * Gets the current status of the stronghold.
     * @returns
     */
    getStatus(): Promise<Status>;
    /**
     * Listen to status changes on the stronghold.
     * @param cb
     * @returns
     */
    onStatusChange(cb: (status: Status) => void): Unregister;
    /**
     * Starts the P2P communication system.
     * @returns
     */
    spawnCommunication(): Promise<Communication>;
}
export {};
