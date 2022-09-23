import { invoke } from '@tauri-apps/api/tauri'

export type VaultPath = string | number[]

export interface ConnectionLimits {
  maxPendingIncoming?: number
  maxPendingOutgoing?: number
  maxEstablishedIncoming?: number
  maxEstablishedOutgoing?: number
  maxEstablishedPerPeer?: number
  maxEstablishedTotal?: number
}

export interface PeerAddress {
  known: string[] // multiaddr
  use_relay_fallback: boolean
}

export interface AddressInfo {
  peers: Map<string, PeerAddress>
  relays: string[] // peers
}

export interface ClientAccess {
  useVaultDefault?: boolean
  useVaultExceptions?: Map<VaultPath, boolean>
  writeVaultDefault?: boolean
  writeVaultExceptions?: Map<VaultPath, boolean>
  cloneVaultDefault?: boolean
  cloneVaultExceptions?: Map<VaultPath, boolean>
  readStore?: boolean
  writeStore?: boolean
}

export interface Permissions {
  default?: ClientAccess
  exceptions?: Map<VaultPath, ClientAccess>
}

export interface NetworkConfig {
  requestTimeout?: Duration
  connectionTimeout?: Duration
  connectionsLimit?: ConnectionLimits
  enableMdns?: boolean
  enableRelay?: boolean
  addresses?: AddressInfo
  peerPermissions?: Map<string, Permissions>
  permissionsDefault?: Permissions
}

export interface Duration {
  millis: number
  nanos: number
}

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

export function setPasswordClearInterval(interval: Duration) {
  return invoke('plugin:stronghold|set_password_clear_interval', {
    interval
  })
}

class ProcedureExecutor {
  procedureArgs: { [k: string]: any }

  constructor(procedureArgs: { [k: string]: any }) {
    this.procedureArgs = procedureArgs
  }

  generateSLIP10Seed(outputLocation: Location, sizeBytes?: number): Promise<void> {
    return invoke(`plugin:stronghold|execute_procedure`, {
      ...this.procedureArgs,
      procedure: {
        type: 'SLIP10Generate',
        payload: {
          output: outputLocation,
          sizeBytes,
        }
      }
    })
  }

  deriveSLIP10(chain: number[], source: 'Seed' | 'Key', sourceLocation: Location, outputLocation: Location): Promise<string> {
    return invoke(`plugin:stronghold|execute_procedure`, {
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
        }
      }
    })
  }

  recoverBIP39(mnemonic: string, outputLocation: Location, passphrase?: string): Promise<void> {
    return invoke(`plugin:stronghold|execute_procedure`, {
      ...this.procedureArgs,
      procedure: {
        type: 'BIP39Recover',
        payload: {
          mnemonic,
          passphrase,
          output: outputLocation,
        }
      }
    })
  }

  generateBIP39(outputLocation: Location, passphrase?: string): Promise<void> {
    return invoke(`plugin:stronghold|execute_procedure`, {
      ...this.procedureArgs,
      procedure: {
        type: 'BIP39Generate',
        payload: {
          output: outputLocation,
          passphrase,
        }
      }
    })
  }

  getEd25519PublicKey(privateKeyLocation: Location): Promise<string> {
    return invoke(`plugin:stronghold|execute_procedure`, {
      ...this.procedureArgs,
      procedure: {
        type: 'PublicKey',
        payload: {
          type: 'Ed25519',
          privateKey: privateKeyLocation
        }
      }
    })
  }

  signEd25519(privateKeyLocation: Location, msg: string): Promise<string> {
    return invoke(`plugin:stronghold|execute_procedure`, {
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

export class Client {
  path: string
  name: string

  constructor(path: string, name: string) {
    this.path = path
    this.name = name
  }

  getVault(name: string): Vault {
    return new Vault(this.path, this.name, name)
  }

  getStore(): Store {
    return new Store(this.path, this.name)
  }
}

export class Store {
  path: string
  client: string

  constructor(path: string, client: string) {
    this.path = path
    this.client = client
  }

  get(key: string): Promise<number[]> {
    return invoke('plugin:stronghold|get_store_record', {
      snapshotPath: this.path,
      client: this.client,
      key
    })
  }

  insert(key: string, value: number[], lifetime?: Duration): Promise<void> {
    return invoke('plugin:stronghold|save_store_record', {
      snapshotPath: this.path,
      client: this.client,
      key,
      value,
      lifetime
    })
  }

  remove(key: string): Promise<number[] | null> {
    return invoke('plugin:stronghold|remove_store_record', {
      snapshotPath: this.path,
      client: this.client,
      key
    })
  }
}

export class Vault extends ProcedureExecutor {
  path: string
  client: string
  name: string

  constructor(path: string, client: string, name: string) {
    super({
      snapshotPath: path,
      client,
      vault: name,
    })
    this.path = path
    this.client = client
    this.name = name
  }

  insert(key: string, secret: number[]): Promise<void> {
    return invoke('plugin:stronghold|save_secret', {
      snapshotPath: this.path,
      client: this.client,
      vault: this.name,
      recordPath: key,
      secret,
    })
  }

  remove(location: Location): Promise<void> {
    return invoke('plugin:stronghold|remove_secret', {
      snapshotPath: this.path,
      client: this.client,
      vault: this.name,
      location,
    })
  }
}

export class Communication {
  path: string

  constructor(path: string) {
    this.path = path
  }

  connect(peer: string): Promise<string> {
    return invoke('plugin:stronghold|p2p_connect', {
      snapshotPath: this.path,
      peer
    })
  }

  serve(): Promise<void> {
    return invoke('plugin:stronghold|p2p_serve', {
      snapshotPath: this.path
    })
  }

  private send<T>(peer: string, client: string, request: any): Promise<T> {
    return invoke('plugin:stronghold|p2p_send', {
      snapshotPath: this.path,
      peer,
      client,
      request,
    })
  }

  getSnapshotHierarchy(peer: string, client: string): Promise<void> {
    return this.send(peer, client, {
      type: 'SnapshotRequest',
      payload: {
        request: {
          type: 'GetRemoteHierarchy'
        }
      }
    })
  }

  checkVault(peer: string, client: string, vault: string): Promise<boolean> {
    return this.send(peer, client, {
      type: 'ClientRequest',
      payload: {
        request: {
          type: 'CheckVault',
          payload: {
            vaultPath: vault
          }
        }
      }
    })
  }

  checkRecord(peer: string, client: string, location: Location): Promise<boolean> {
    return this.send(peer, client, {
      type: 'ClientRequest',
      payload: {
        request: {
          type: 'CheckRecord',
          payload: {
            location
          }
        }
      }
    })
  }

  writeToVault(peer: string, client: string, location: Location, payload: number[]): Promise<void> {
    return this.send(peer, client, {
      type: 'ClientRequest',
      payload: {
        request: {
          type: 'WriteToVault',
          payload: {
            location,
            payload
          }
        }
      }
    })
  }

  revokeData(peer: string, client: string, location: Location): Promise<void> {
    return this.send(peer, client, {
      type: 'ClientRequest',
      payload: {
        request: {
          type: 'RevokeData',
          payload: {
            location,
          }
        }
      }
    })
  }

  deleteData(peer: string, client: string, location: Location): Promise<void> {
    return this.send(peer, client, {
      type: 'ClientRequest',
      payload: {
        request: {
          type: 'DeleteData',
          payload: {
            location,
          }
        }
      }
    })
  }

  readFromStore(peer: string, client: string, key: string): Promise<number[]> {
    return this.send(peer, client, {
      type: 'ClientRequest',
      payload: {
        request: {
          type: 'ReadFromStore',
          payload: {
            key,
          }
        }
      }
    })
  }

  writeToStore(peer: string, client: string, key: string, payload: number[], lifetime?: Duration): Promise<void> {
    return this.send(peer, client, {
      type: 'ClientRequest',
      payload: {
        request: {
          type: 'WriteToStore',
          payload: {
            key,
            payload,
            lifetime
          }
        }
      }
    })
  }

  deleteFromStore(peer: string, client: string, key: string): Promise<void> {
    return this.send(peer, client, {
      type: 'ClientRequest',
      payload: {
        request: {
          type: 'DeleteFromStore',
          payload: {
            key,
          }
        }
      }
    })
  }

  generateSLIP10Seed(peer: string, client: string, outputLocation: Location, sizeBytes?: number): Promise<void> {
    return this.send(peer, client, {
      type: 'ClientRequest',
      payload: {
        request: {
          type: 'Procedures',
          payload: {
            procedures: [{
              type: 'SLIP10Generate',
              payload: {
                output: outputLocation,
                sizeBytes,
              }
            }],
          }
        }
      }
    })
  }

  deriveSLIP10(peer: string, client: string, chain: number[], source: 'Seed' | 'Key', sourceLocation: Location, outputLocation: Location): Promise<string> {
    return this.send(peer, client, {
      type: 'ClientRequest',
      payload: {
        request: {
          type: 'Procedures',
          payload: {
            procedures: [{
              type: 'SLIP10Derive',
              payload: {
                chain,
                input: {
                  type: source,
                  payload: sourceLocation
                },
                output: outputLocation,
              }
            }],
          }
        }
      }
    })
  }

  recoverBIP39(peer: string, client: string, mnemonic: string, outputLocation: Location, passphrase?: string): Promise<void> {
    return this.send(peer, client, {
      type: 'ClientRequest',
      payload: {
        request: {
          type: 'Procedures',
          payload: {
            procedures: [{
              type: 'BIP39Recover',
              payload: {
                mnemonic,
                passphrase,
                output: outputLocation,
              }
            }],
          }
        }
      }
    })
  }

  generateBIP39(peer: string, client: string, outputLocation: Location, passphrase?: string): Promise<void> {
    return this.send(peer, client, {
      type: 'ClientRequest',
      payload: {
        request: {
          type: 'Procedures',
          payload: {
            procedures: [{
              type: 'BIP39Generate',
              payload: {
                output: outputLocation,
                passphrase,
              }
            }],
          }
        }
      }
    })
  }

  getEd25519PublicKey(peer: string, client: string, privateKeyLocation: Location): Promise<string> {
    return this.send(peer, client, {
      type: 'ClientRequest',
      payload: {
        request: {
          type: 'Procedures',
          payload: {
            procedures: [{
              type: 'PublicKey',
              payload: {
                type: 'Ed25519',
                privateKey: privateKeyLocation
              }
            }],
          }
        }
      }
    })
  }

  signEd25519(peer: string, client: string, privateKeyLocation: Location, msg: string): Promise<string> {
    return this.send(peer, client, {
      type: 'ClientRequest',
      payload: {
        request: {
          type: 'Procedures',
          payload: {
            procedures: [{
              type: 'Ed25519Sign',
              payload: {
                privateKey: privateKeyLocation,
                msg
              }
            }],
          }
        }
      }
    })
  }

  stop(): Promise<void> {
    return invoke('plugin:stronghold|p2p_stop', {
      snapshotPath: this.path
    })
  }

  startListening(addr?: string): Promise<string> {
    return invoke('plugin:stronghold|p2p_start_listening', {
      snapshotPath: this.path,
      addr
    })
  }

  stopListening(): Promise<string> {
    return invoke('plugin:stronghold|p2p_stop_listening', {
      snapshotPath: this.path,
    })
  }

  addPeerAddr(peerId: string, addr: string): Promise<string> {
    return invoke('plugin:stronghold|p2p_add_peer', {
      snapshotPath: this.path,
      peerId,
      addr
    })
  }
}

export class Stronghold {
  path: string

  constructor(path: string, password: string) {
    this.path = path
    this.reload(password)
  }

  reload(password: string): Promise<void> {
    return invoke('plugin:stronghold|initialize', {
      snapshotPath: this.path,
      password
    })
  }

  unload(): Promise<void> {
    return invoke('plugin:stronghold|destroy', {
      snapshotPath: this.path
    })
  }

  loadClient(client: string): Promise<Client> {
    return invoke('plugin:stronghold|load_client', {
      snapshotPath: this.path,
      client
    }).then(() => new Client(this.path, client))
  }

  createClient(client: string): Promise<Client> {
    return invoke('plugin:stronghold|create_client', {
      snapshotPath: this.path,
      client
    }).then(() => new Client(this.path, client))
  }

  save(): Promise<void> {
    return invoke('plugin:stronghold|save', {
      snapshotPath: this.path
    })
  }

  spawnCommunication(client: string, config?: NetworkConfig, keypair?: Location): Promise<Communication> {
    return invoke('plugin:stronghold|p2p_spawn', {
      snapshotPath: this.path,
      client,
      config,
      keypair
    }).then(() => new Communication(this.path))
  }
}
