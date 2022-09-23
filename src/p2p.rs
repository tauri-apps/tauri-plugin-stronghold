use iota_stronghold::network_old::{
    ClientAccess as StrongholdClientAccess, ClientRequest as StrongholdClientRequest,
    NetworkConfig as StrongholdNetworkConfig, Permissions as StrongholdPermissions,
    SnapshotRequest as StrongholdSnapshotRequest, StrongholdRequest,
};
use libp2p::{Multiaddr, PeerId};
use serde::{Deserialize, Serialize, Serializer};
use stronghold_p2p::{AddressInfo, ConnectionLimits as StrongholdConnectionLimits};
use tauri::State;

use std::{collections::HashMap, path::PathBuf, str::FromStr, time::Duration};

use crate::{BytesDto, LocationDto, ProcedureDto, StrongholdCollection};

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("peer is invalid")]
    InvalidPeer,
    #[error("stronghold not initialized")]
    StrongholdNotInitialized,
    #[error(transparent)]
    Stronghold(#[from] iota_stronghold::ClientError),
    #[error(transparent)]
    Spawn(#[from] iota_stronghold::SpawnNetworkError),
    #[error(transparent)]
    Listen(#[from] stronghold_p2p::ListenErr),
    #[error(transparent)]
    Dial(#[from] stronghold_p2p::DialErr),
}

impl Serialize for Error {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.to_string().as_str())
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ConnectionLimits {
    max_pending_incoming: Option<u32>,
    max_pending_outgoing: Option<u32>,
    max_established_incoming: Option<u32>,
    max_established_outgoing: Option<u32>,
    max_established_per_peer: Option<u32>,
    max_established_total: Option<u32>,
}

impl Default for ConnectionLimits {
    fn default() -> Self {
        ConnectionLimits {
            max_pending_incoming: None,
            max_pending_outgoing: None,
            max_established_incoming: None,
            max_established_outgoing: None,
            max_established_per_peer: Some(5),
            max_established_total: None,
        }
    }
}

impl From<ConnectionLimits> for StrongholdConnectionLimits {
    fn from(l: ConnectionLimits) -> Self {
        StrongholdConnectionLimits::default()
            .with_max_pending_incoming(l.max_pending_incoming)
            .with_max_pending_outgoing(l.max_pending_outgoing)
            .with_max_established_incoming(l.max_established_incoming)
            .with_max_established_outgoing(l.max_established_outgoing)
            .with_max_established_per_peer(l.max_established_per_peer)
            .with_max_established(l.max_established_total)
    }
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ClientAccess {
    use_vault_default: bool,
    use_vault_exceptions: HashMap<Vec<u8>, bool>,
    write_vault_default: bool,
    write_vault_exceptions: HashMap<Vec<u8>, bool>,
    clone_vault_default: bool,
    clone_vault_exceptions: HashMap<Vec<u8>, bool>,
    read_store: bool,
    write_store: bool,
}

impl From<ClientAccess> for StrongholdClientAccess {
    fn from(a: ClientAccess) -> StrongholdClientAccess {
        let mut acc = StrongholdClientAccess::allow_none()
            .with_default_vault_access(
                a.use_vault_default,
                a.write_vault_default,
                a.clone_vault_default,
            )
            .with_store_access(a.read_store, a.write_store);

        #[derive(Default)]
        struct Exception {
            use_: bool,
            write: bool,
            clone: bool,
        }
        let mut exceptions: HashMap<Vec<u8>, Exception> = Default::default();
        for (path, flag) in a.use_vault_exceptions {
            exceptions.entry(path).or_default().use_ = flag;
        }
        for (path, flag) in a.write_vault_exceptions {
            exceptions.entry(path).or_default().write = flag;
        }
        for (path, flag) in a.clone_vault_exceptions {
            exceptions.entry(path).or_default().clone = flag;
        }
        for (path, exception) in exceptions {
            acc = acc.with_vault_access(path, exception.use_, exception.write, exception.clone);
        }

        acc
    }
}

#[derive(Default, Deserialize)]
pub(crate) struct Permissions {
    default: ClientAccess,
    exceptions: HashMap<Vec<u8>, ClientAccess>,
}

impl From<Permissions> for StrongholdPermissions {
    fn from(p: Permissions) -> Self {
        let mut perm = StrongholdPermissions::new(p.default.into());
        for (path, permissions) in p.exceptions {
            perm = perm.with_client_permissions(path, permissions.into());
        }
        perm
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NetworkConfig {
    request_timeout: Option<Duration>,
    connection_timeout: Option<Duration>,
    connections_limit: Option<ConnectionLimits>,
    enable_mdns: bool,
    enable_relay: bool,
    addresses: Option<AddressInfo>,
    peer_permissions: HashMap<PeerId, Permissions>,
    permissions_default: Permissions,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        let connection_limits = ConnectionLimits {
            max_established_incoming: Some(10),
            max_pending_incoming: Some(5),
            max_established_per_peer: Some(5),
            ..Default::default()
        };
        NetworkConfig {
            request_timeout: Some(Duration::from_secs(30)),
            connection_timeout: Some(Duration::from_secs(30)),
            connections_limit: Some(connection_limits),
            enable_mdns: false,
            enable_relay: false,
            addresses: None,
            peer_permissions: HashMap::new(),
            permissions_default: Permissions::default(),
        }
    }
}

impl From<NetworkConfig> for StrongholdNetworkConfig {
    fn from(c: NetworkConfig) -> Self {
        let mut conf = StrongholdNetworkConfig::new(c.permissions_default.into())
            .with_mdns_enabled(c.enable_mdns)
            .with_relay_enabled(c.enable_relay);

        if let Some(timeout) = c.request_timeout {
            conf = conf.with_request_timeout(timeout);
        }
        if let Some(timeout) = c.connection_timeout {
            conf = conf.with_connection_timeout(timeout);
        }
        if let Some(limits) = c.connections_limit {
            conf = conf.with_connections_limit(limits.into());
        }
        if let Some(info) = c.addresses {
            conf = conf.with_address_info(info);
        }
        for (id, permissions) in c.peer_permissions {
            conf = conf.with_peer_permission(id, permissions.into());
        }

        conf
    }
}

#[derive(Deserialize)]
#[serde(tag = "type", content = "payload")]
pub(crate) enum ClientRequest {
    CheckVault {
        #[serde(rename = "vaultPath")]
        vault_path: BytesDto,
    },
    CheckRecord {
        location: LocationDto,
    },
    WriteToVault {
        location: LocationDto,
        payload: Vec<u8>,
    },
    RevokeData {
        location: LocationDto,
    },
    DeleteData {
        location: LocationDto,
    },
    ReadFromStore {
        key: BytesDto,
    },
    WriteToStore {
        key: BytesDto,
        payload: Vec<u8>,
        lifetime: Option<Duration>,
    },
    DeleteFromStore {
        key: BytesDto,
    },
    Procedures {
        procedures: Vec<ProcedureDto>,
    },
}

impl From<ClientRequest> for StrongholdClientRequest {
    fn from(r: ClientRequest) -> Self {
        match r {
            ClientRequest::CheckVault { vault_path } => Self::CheckVault {
                vault_path: vault_path.into(),
            },
            ClientRequest::CheckRecord { location } => Self::CheckRecord {
                location: location.into(),
            },
            ClientRequest::WriteToVault { location, payload } => Self::WriteToVault {
                location: location.into(),
                payload,
            },
            ClientRequest::RevokeData { location } => Self::RevokeData {
                location: location.into(),
            },
            ClientRequest::DeleteData { location } => Self::DeleteData {
                location: location.into(),
            },
            ClientRequest::ReadFromStore { key } => Self::ReadFromStore { key: key.into() },
            ClientRequest::WriteToStore {
                key,
                payload,
                lifetime,
            } => Self::WriteToStore {
                key: key.into(),
                payload,
                lifetime,
            },
            ClientRequest::DeleteFromStore { key } => Self::DeleteFromStore { key: key.into() },
            ClientRequest::Procedures { procedures } => Self::Procedures {
                procedures: procedures.into_iter().map(Into::into).collect(),
            },
        }
    }
}

#[derive(Deserialize)]
#[serde(tag = "type", content = "payload")]
pub(crate) enum SnapshotRequest {
    GetRemoteHierarchy,
}

impl From<SnapshotRequest> for StrongholdSnapshotRequest {
    fn from(r: SnapshotRequest) -> Self {
        match r {
            SnapshotRequest::GetRemoteHierarchy => Self::GetRemoteHierarchy,
        }
    }
}

#[derive(Deserialize)]
#[serde(tag = "type", content = "payload")]
pub(crate) enum Request {
    ClientRequest {
        #[serde(rename = "clientPath")]
        client_path: BytesDto,
        request: ClientRequest,
    },
    SnapshotRequest {
        request: SnapshotRequest,
    },
}

impl From<Request> for StrongholdRequest {
    fn from(r: Request) -> Self {
        match r {
            Request::ClientRequest {
                client_path,
                request,
            } => Self::ClientRequest {
                client_path: client_path.into(),
                request: request.into(),
            },
            Request::SnapshotRequest { request } => Self::SnapshotRequest {
                request: request.into(),
            },
        }
    }
}

#[tauri::command]
pub(crate) async fn p2p_spawn(
    collection: State<'_, StrongholdCollection>,
    snapshot_path: PathBuf,
    client: BytesDto,
    config: Option<NetworkConfig>,
    keypair: Option<LocationDto>,
) -> Result<()> {
    let stronghold = get_stronghold(collection, snapshot_path)?;
    stronghold
        .spawn_p2p(
            client,
            config.unwrap_or_default().into(),
            keypair.map(Into::into),
        )
        .await
        .map_err(Into::into)
}

#[tauri::command]
pub(crate) async fn p2p_stop(
    collection: State<'_, StrongholdCollection>,
    snapshot_path: PathBuf,
) -> Result<()> {
    let (stronghold, p2p_server) = if let Some((stronghold, p2p_server)) = collection
        .0
        .lock()
        .unwrap()
        .get(&snapshot_path)
        .map(|s| (s.inner().clone(), s.p2p_server.clone()))
    {
        (stronghold, p2p_server)
    } else {
        return Err(Error::StrongholdNotInitialized);
    };
    crate::stronghold::p2p_stop(p2p_server).await;
    stronghold.clear_network().await?;
    Ok(())
}

#[tauri::command]
pub(crate) fn p2p_serve(
    collection: State<'_, StrongholdCollection>,
    snapshot_path: PathBuf,
) -> Result<()> {
    let collection = collection.0.lock().unwrap();
    if let Some(stronghold) = collection.get(&snapshot_path) {
        stronghold.p2p_serve();
        Ok(())
    } else {
        Err(Error::StrongholdNotInitialized)
    }
}

#[tauri::command]
pub(crate) async fn p2p_start_listening(
    collection: State<'_, StrongholdCollection>,
    snapshot_path: PathBuf,
    addr: Option<Multiaddr>,
) -> Result<Multiaddr> {
    let stronghold = get_stronghold(collection, snapshot_path)?;
    stronghold.start_listening(addr).await.map_err(Into::into)
}

#[tauri::command]
pub(crate) async fn p2p_stop_listening(
    collection: State<'_, StrongholdCollection>,
    snapshot_path: PathBuf,
) -> Result<()> {
    let stronghold = get_stronghold(collection, snapshot_path)?;
    stronghold.stop_listening().await.map_err(Into::into)
}

#[tauri::command]
pub(crate) async fn p2p_add_peer_addr(
    collection: State<'_, StrongholdCollection>,
    snapshot_path: PathBuf,
    peer: String,
    address: Multiaddr,
) -> Result<Multiaddr> {
    let stronghold = get_stronghold(collection, snapshot_path)?;
    stronghold
        .add_peer_addr(
            PeerId::from_str(&peer).map_err(|_e| Error::InvalidPeer)?,
            address,
        )
        .await
        .map_err(Into::into)
}

#[tauri::command]
pub(crate) async fn p2p_connect(
    collection: State<'_, StrongholdCollection>,
    snapshot_path: PathBuf,
    peer: String,
) -> Result<()> {
    let stronghold = get_stronghold(collection, snapshot_path)?;
    stronghold
        .connect(PeerId::from_str(&peer).map_err(|_e| Error::InvalidPeer)?)
        .await
        .map_err(Into::into)
}

#[tauri::command]
pub(crate) async fn p2p_send(
    collection: State<'_, StrongholdCollection>,
    snapshot_path: PathBuf,
    peer: String,
    client: BytesDto,
    request: Request,
) -> Result<()> {
    let stronghold = get_stronghold(collection, snapshot_path)?;
    stronghold
        .send(
            PeerId::from_str(&peer).map_err(|_e| Error::InvalidPeer)?,
            client,
            request,
        )
        .await?;
    Ok(())
}

fn get_stronghold(
    collection: State<'_, StrongholdCollection>,
    snapshot_path: PathBuf,
) -> Result<iota_stronghold::Stronghold> {
    let collection = collection.0.lock().unwrap();
    if let Some(stronghold) = collection.get(&snapshot_path) {
        Ok(stronghold.inner().clone())
    } else {
        Err(Error::StrongholdNotInitialized)
    }
}
