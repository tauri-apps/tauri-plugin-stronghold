import { invoke } from '@tauri-apps/api/tauri'
import { listen } from '@tauri-apps/api/event'

/** A duration definition. */
export interface Duration {
  /** The number of whole seconds contained by this Duration. */
  secs: number
  /** The fractional part of this Duration, in nanoseconds. */
  nanos: number
}

/** The stronghold status. */
export interface Status {
  /** The snapshot status. */
  snapshot: {
    status: 'unlocked'
    /**
     * The amount of time left before the snapshot is locked.
     */
    data?: Duration
  } | {
    status: 'locked'
  }
}

/** Swarm information of the local peer. */
export interface SwarmInfo {
  /** Peer id. */
  peerId: string
  /** List of listening addresses. */
  listeningAddresses: string[]
}

/** Relay direction. */
export enum RelayDirection {
  Dialing,
  Listening,
  Both
}

/** Permissions that can be set for P2P access of a stronghold. */
export enum RequestPermission {
  /** Allow checking if a vault exists. */
  CheckVault,
  /** Allow checking if a record exists. */
  CheckRecord,
  /** Allow writing to the store. */
  WriteToStore,
  /** Allow reading the store. */
  ReadFromStore,
  /** Allow deleting store records. */
  DeleteFromStore,
  /** Allow creating new vaults. */
  CreateNewVault,
  /** Allow writing to a vault. */
  WriteToVault,
  /** Allow deleting vault records. */
  RevokeData,
  /** Allow garbage collecting the stronghold. */
  GarbageCollect,
  /** Allow listing vault ids. */
  ListIds,
  /** Allow reading data from a snapshot. */
  ReadSnapshot,
  /** Allow writing to a snapshot. */
  WriteSnapshot,
  /** Allow writing a client to the snapshot. */
  FillSnapshot,
  /** Allow clearing the snapshot cache. */
  ClearCache,
  /** Allow running procedures. */
  ControlRequest,
}

interface StatusListener {
  id: string
  cb: (status: Status) => void
}

type Unregister = () => void

const statusChangeListeners: { [snapshotPath: string]: StatusListener[] } = {}

listen('stronghold://status-change', event => {
  const { snapshotPath, status } = event.payload as any
  for (const listener of (statusChangeListeners[snapshotPath] || [])) {
    listener.cb(status)
  }
})

export enum StrongholdFlag { }

export class Location {
  type: string
  payload: { [key: string]: any }

  constructor(type: string, payload: { [key: string]: any }) {
    this.type = type
    this.payload = payload
  }

  static generic(vaultName: string, recordName: string) {
    return new Location('Generic', {
      vault: vaultName,
      record: recordName
    })
  }

  static counter(vaultName: string, counter: number) {
    return new Location('Counter', {
      vault: vaultName,
      counter
    })
  }
}

/**
 * The record hint can be used to identify a record for further access
 * using the `listIds` API.
 * It is a number array with size 24.
*/
export type RecordHint = [number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number]

/**
 * Sets the interval used to clear the password cache.
 * The cache is cleared after `interval` if the stronghold is not accessed.
 * @param interval
 * @returns 
 */
export function setPasswordClearInterval(interval: Duration) {
  return invoke('plugin:stronghold|set_password_clear_interval', {
    interval
  })
}

class ProcedureExecutor {
  procedureArgs: { [k: string]: any }
  command: string

  constructor(isRemote: boolean, procedureArgs: { [k: string]: any }) {
    this.procedureArgs = procedureArgs
    this.command = isRemote ? 'execute_remote_procedure' : 'execute_procedure'
  }

  /**
   * Generate a SLIP10 seed on the given location.
   * @param outputLocation Location of the record where the seed will be stored.
   * @param sizeBytes The size in bytes of the SLIP10 seed.
   * @param hint The record hint.
   * @returns 
   */
  generateSLIP10Seed(outputLocation: Location, sizeBytes?: number, hint?: RecordHint): Promise<void> {
    return invoke(`plugin:stronghold|${this.command}`, {
      ...this.procedureArgs,
      procedure: {
        type: 'SLIP10Generate',
        payload: {
          output: outputLocation,
          sizeBytes,
          hint
        }
      }
    })
  }

  /**
   * Derive a SLIP10 private key using a seed or key.
   * @param chain The chain path.
   * @param source The source type, either 'Seed' or 'Key'.
   * @param sourceLocation The source location, must be the `outputLocation` of a previous call to `generateSLIP10Seed` or `deriveSLIP10`.
   * @param outputLocation Location of the record where the private key will be stored.
   * @param hint The record hint.
   * @returns 
   */
  deriveSLIP10(chain: number[], source: 'Seed' | 'Key', sourceLocation: Location, outputLocation: Location, hint?: RecordHint): Promise<string> {
    return invoke(`plugin:stronghold|${this.command}`, {
      ...this.procedureArgs,
      procedure: {
        type: 'SLIP10Derive',
        payload: {
          chain,
          input: {
            type: source,
            payload: sourceLocation
          },
          output: outputLocation,
          hint
        }
      }
    })
  }

  /**
   * Store a BIP39 mnemonic.
   * @param mnemonic The mnemonic string.
   * @param outputLocation The location of the record where the BIP39 mnemonic will be stored. 
   * @param passphrase The optional mnemonic passphrase.
   * @param hint The record hint.
   * @returns 
   */
  recoverBIP39(mnemonic: string, outputLocation: Location, passphrase?: string, hint?: RecordHint): Promise<void> {
    return invoke(`plugin:stronghold|${this.command}`, {
      ...this.procedureArgs,
      procedure: {
        type: 'BIP39Recover',
        payload: {
          mnemonic,
          passphrase,
          output: outputLocation,
          hint
        }
      }
    })
  }

  /**
   * Generate a BIP39 seed.
   * @param outputLocation The location of the record where the BIP39 seed will be stored.
   * @param passphrase The optional mnemonic passphrase.
   * @param hint The record hint.
   * @returns 
   */
  generateBIP39(outputLocation: Location, passphrase?: string, hint?: RecordHint): Promise<void> {
    return invoke(`plugin:stronghold|${this.command}`, {
      ...this.procedureArgs,
      procedure: {
        type: 'BIP39Generate',
        payload: {
          output: outputLocation,
          passphrase,
          hint
        }
      }
    })
  }

  /**
   * Gets the Ed25519 public key of a SLIP10 private key.
   * @param privateKeyLocation The location of the private key. Must be the `outputLocation` of a previous call to `deriveSLIP10`.
   * @returns A promise resolving to the public key hex string.
   */
  getPublicKey(privateKeyLocation: Location): Promise<string> {
    return invoke(`plugin:stronghold|${this.command}`, {
      ...this.procedureArgs,
      procedure: {
        type: 'Ed25519PublicKey',
        payload: {
          privateKey: privateKeyLocation
        }
      }
    })
  }

  /**
   * Creates a Ed25519 signature from a private key.
   * @param privateKeyLocation The location of the record where the private key is stored. Must be the `outputLocation` of a previous call to `deriveSLIP10`.
   * @param msg The message to sign.
   * @returns A promise resolving to the signature hex string.
   */
  sign(privateKeyLocation: Location, msg: string): Promise<string> {
    return invoke(`plugin:stronghold|${this.command}`, {
      ...this.procedureArgs,
      procedure: {
        type: 'Ed25519Sign',
        payload: {
          privateKey: privateKeyLocation,
          msg
        }
      }
    })
  }
}

/**
 * A stronghold store that is accessed remotely via a P2P connection.
 */
export class RemoteStore {
  /** The snapshot path. */
  path: string
  /** The peer id. */
  peerId: string

  /** @ignore */
  constructor(path: string, peerId: string) {
    this.path = path
    this.peerId = peerId
  }

  /**
   * Read the remote store with the given location key.
   * @param location The record location.
   * @returns 
   */
  get(location: Location): Promise<string> {
    return invoke('plugin:stronghold|get_remote_store_record', {
      snapshotPath: this.path,
      peerId: this.peerId,
      location
    })
  }

  /**
   * Insert the key-value pair to the remote store.
   * @param location The record location.
   * @param record The data to store on the record.
   * @param lifetime The amount of time the record must live.
   * @returns 
   */
  insert(location: Location, record: string, lifetime?: Duration): Promise<void> {
    return invoke('plugin:stronghold|save_remote_store_record', {
      snapshotPath: this.path,
      peerId: this.peerId,
      location,
      record,
      lifetime
    })
  }
}

/**
 * A stronghold vault that is accessed remotely via a P2P connection.
 */
export class RemoteVault extends ProcedureExecutor {
  /** The snapshot path. */
  path: string
  /** The peer id. */
  peerId: string

  /** @ignore */
  constructor(path: string, peerId: string) {
    super(true, {
      peerId
    })
    this.path = path
    this.peerId = peerId
  }
}

/**
 * A key-value storage that allows create, read, update and delete operations.
 */
export class Store {
  /** The snapshot path. */
  path: string
  /** The store name. */
  name: string
  /** The store permission flags. */
  flags: StrongholdFlag[]

  /** @ignore */
  constructor(path: string, name: string, flags: StrongholdFlag[]) {
    this.path = path
    this.name = name
    this.flags = flags
  }

  /** @ignore */
  private get store() {
    return {
      name: this.name,
      flags: this.flags
    }
  }

  /**
   * Read a record on the store.
   * @param location The record location.
   * @returns 
   */
  get(location: Location): Promise<string> {
    return invoke('plugin:stronghold|get_store_record', {
      snapshotPath: this.path,
      store: this.store,
      location
    })
  }

  /**
   * Save a record on the store.
   * @param location The record location.
   * @param record The data to store on the record.
   * @param lifetime The record lifetime.
   * @returns 
   */
  insert(location: Location, record: string, lifetime?: Duration): Promise<void> {
    return invoke('plugin:stronghold|save_store_record', {
      snapshotPath: this.path,
      store: this.store,
      location,
      record,
      lifetime
    })
  }

  /**
   * Deletes a record.
   * @param location The record location.
   * @returns 
   */
  remove(location: Location): Promise<void> {
    return invoke('plugin:stronghold|remove_store_record', {
      snapshotPath: this.path,
      store: this.store,
      location
    })
  }
}

/**
 * A key-value storage that allows create, update and delete operations.
 * It does not allow reading the data, so one of the procedures must be used to manipulate
 * the stored data, allowing secure storage of secrets.
 */
export class Vault extends ProcedureExecutor {
  /** The vault path. */
  path: string
  /** The vault name. */
  name: string
  /** The vault's permission flags. */
  flags: StrongholdFlag[]

  /** @ignore */
  constructor(path: string, name: string, flags: StrongholdFlag[]) {
    super(false, {
      snapshotPath: path,
      vault: {
        name,
        flags
      }
    })
    this.path = path
    this.name = name
    this.flags = flags
  }

  /** @ignore */
  private get vault() {
    return {
      name: this.name,
      flags: this.flags
    }
  }

  /**
   * Insert a record to this vault.
   * @param location The record location.
   * @param record  The record data.
   * @param recordHint The record hint.
   * @returns 
   */
  insert(location: Location, record: string, recordHint?: RecordHint): Promise<void> {
    return invoke('plugin:stronghold|save_record', {
      snapshotPath: this.path,
      vault: this.vault,
      location,
      record,
      recordHint,
      flags: []
    })
  }

  /**
   * Remove a record from the vault.
   * @param location The record location.
   * @param gc Whether to additionally perform the gargage collection or not.
   * @returns 
   */
  remove(location: Location, gc = true): Promise<void> {
    return invoke('plugin:stronghold|remove_record', {
      snapshotPath: this.path,
      vault: this.vault,
      location,
      gc
    })
  }
}

/**
 * Representation of a P2P connection with a remote stronghold.
 */
export class Communication {
  /** The snapshot path. */
  path: string

  /** @ignore */
  constructor(path: string) {
    this.path = path
  }

  /**
   * Stop the connection.
   */
  stop(): Promise<void> {
    return invoke('plugin:stronghold|stop_communication', {
      snapshotPath: this.path
    })
  }

  /**
   * Start listening on the given address.
   * @param addr The address to connect to.
   * @returns 
   */
  startListening(addr?: string): Promise<string> {
    return invoke('plugin:stronghold|start_listening', {
      snapshotPath: this.path,
      addr
    })
  }

  /**
   * Gets the swarm information of the local peer.
   * @returns The swarm information.
   */
  getSwarmInfo(): Promise<SwarmInfo> {
    return invoke('plugin:stronghold|get_swarm_info', { snapshotPath: this.path })
  }

  /**
   * Adds a peer.
   * @param peerId 
   * @param addr 
   * @param relayDirection 
   * @returns 
   */
  addPeer(peerId: string, addr?: string, relayDirection?: RelayDirection): Promise<string> {
    return invoke('plugin:stronghold|add_peer', {
      snapshotPath: this.path,
      peerId,
      addr,
      relayDirection: relayDirection ? { type: RelayDirection[relayDirection] } : null
    })
  }

  /**
   * Change the relay direction of the given peer.
   * @param peerId
   * @param relayDirection 
   * @returns 
   */
  changeRelayDirection(peerId: string, relayDirection: RelayDirection): Promise<string> {
    return invoke('plugin:stronghold|change_relay_direction', {
      snapshotPath: this.path,
      peerId,
      relayDirection: { type: RelayDirection[relayDirection] }
    })
  }

  /**
   * Remove the relay on the given peer.
   * @param peerId
   * @returns 
   */
  removeRelay(peerId: string): Promise<void> {
    return invoke('plugin:stronghold|remove_relay', {
      snapshotPath: this.path,
      peerId
    })
  }

  /**
   * Allow all requests from the given peer list.
   * @param peers 
   * @param setDefault 
   * @returns 
   */
  allowAllRequests(peers: string[], setDefault = false): Promise<void> {
    return invoke('plugin:stronghold|allow_all_requests', {
      snapshotPath: this.path,
      peers,
      setDefault
    })
  }

  /**
   * Reject all requests from the given peer list.
   * @param peers
   * @param setDefault 
   * @returns 
   */
  rejectAllRequests(peers: string[], setDefault = false): Promise<void> {
    return invoke('plugin:stronghold|reject_all_requests', {
      snapshotPath: this.path,
      peers,
      setDefault
    })
  }

  /**
   * Allow the specified set of requests from the given peer list.
   * @param peers 
   * @param permissions 
   * @param changeDefault 
   * @returns 
   */
  allowRequests(peers: string[], permissions: RequestPermission[], changeDefault = false): Promise<void> {
    return invoke('plugin:stronghold|allow_requests', {
      snapshotPath: this.path,
      peers,
      requests: permissions.map(p => ({ type: RequestPermission[p] })),
      changeDefault
    })
  }

  /**
   * Reject the specified set of requests from the given peer list.
   * @param peers 
   * @param permissions 
   * @param changeDefault 
   * @returns 
   */
  rejectRequests(peers: string[], permissions: RequestPermission[], changeDefault = false): Promise<void> {
    return invoke('plugin:stronghold|reject_requests', {
      snapshotPath: this.path,
      peers,
      requests: permissions.map(p => ({ type: RequestPermission[p] })),
      changeDefault
    })
  }

  /**
   * Remove firewall rules for the given peer list.
   * @param peers 
   * @returns 
   */
  removeFirewallRules(peers: string[]): Promise<void> {
    return invoke('plugin:stronghold|remove_firewall_rules', {
      snapshotPath: this.path,
      peers
    })
  }

  /**
   * Get a RemoteVault to interact with the given peer.
   * @param peerId 
   * @returns 
   */
  getRemoteVault(peerId: string): RemoteVault {
    return new RemoteVault(this.path, peerId)
  }

  /**
   * Get a RemoteStore to interact with the given peer.
   * @param peerId 
   * @returns 
   */
  getRemoteStore(peerId: string): RemoteStore {
    return new RemoteStore(this.path, peerId)
  }
}

/**
 * A representation of an access to a stronghold.
 */
export class Stronghold {
  path: string

  /**
   * Initializes a stronghold.
   * If the snapshot path located at `path` exists, the password must match.
   * @param path
   * @param password 
   */
  constructor(path: string, password: string) {
    this.path = path
    this.reload(password)
  }

  /**
   * Force a reload of the snapshot. The password must match.
   * @param password
   * @returns 
   */
  reload(password: string): Promise<void> {
    return invoke('plugin:stronghold|init', {
      snapshotPath: this.path,
      password
    })
  }

  /**
   * Remove this instance from the cache.
  */
  unload(): Promise<void> {
    return invoke('plugin:stronghold|destroy', {
      snapshotPath: this.path
    })
  }

  /**
   * Get a vault by name.
   * @param name
   * @param flags 
   * @returns 
   */
  getVault(name: string, flags: StrongholdFlag[]): Vault {
    return new Vault(this.path, name, flags)
  }

  /**
   * Get a store by name.
   * @param name
   * @param flags 
   * @returns 
   */
  getStore(name: string, flags: StrongholdFlag[]): Store {
    return new Store(this.path, name, flags)
  }

  /**
   * Persists the stronghold state to the snapshot.
   * @returns 
   */
  save(): Promise<void> {
    return invoke('plugin:stronghold|save_snapshot', {
      snapshotPath: this.path
    })
  }

  /**
   * Gets the current status of the stronghold.
   * @returns 
   */
  getStatus(): Promise<Status> {
    return invoke('plugin:stronghold|get_status', {
      snapshotPath: this.path
    })
  }

  /**
   * Listen to status changes on the stronghold.
   * @param cb
   * @returns 
   */
  onStatusChange(cb: (status: Status) => void): Unregister {
    if (statusChangeListeners[this.path] === void 0) {
      statusChangeListeners[this.path] = []
    }
    const id = crypto.getRandomValues(new Uint8Array(1))[0].toString()
    statusChangeListeners[this.path].push({
      id,
      cb
    })
    return () => {
      statusChangeListeners[this.path] = statusChangeListeners[this.path].filter(listener => listener.id !== id)
    }
  }

  /**
   * Starts the P2P communication system.
   * @returns
   */
  spawnCommunication(): Promise<Communication> {
    return invoke('plugin:stronghold|spawn_communication', {
      snapshotPath: this.path
    }).then(() => new Communication(this.path))
  }
}
