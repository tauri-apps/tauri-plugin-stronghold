use std::convert::{TryFrom, Infallible};
use async_std::{
    sync::Mutex,
    task::{sleep, spawn},
};
use std::{
    collections::{HashMap},
    sync::Arc,
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
    str::from_utf8
};
use crypto::hashes::{blake2b::Blake2b256, Digest};
use once_cell::sync::{OnceCell};
use iota_stronghold as stronghold;
use stronghold::{
    procedures::{
        KeyType,
        StrongholdProcedure,
    },
    Client, ClientError, KeyProvider, Location, SnapshotPath, Stronghold, RecordError, VaultError, Provider
};
use engine::vault::{DbView, Key, RecordHint, RecordId, VaultId};
use serde::{ser::Serializer, Serialize};
use zeroize::Zeroize;

#[derive(PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
struct Password(Vec<u8>);

type SnapshotToPasswordMap = HashMap<PathBuf, Arc<Password>>;
static PASSWORD_STORE: OnceCell<Arc<Mutex<SnapshotToPasswordMap>>> = OnceCell::new();
static VAULT_ID: OnceCell<Arc<Mutex<VaultId>>> = OnceCell::new();
static PASSWORD_CLEAR_INTERVAL: OnceCell<Arc<Mutex<Duration>>> = OnceCell::new();
static CURRENT_SNAPSHOT_PATH: OnceCell<Arc<Mutex<Option<PathBuf>>>> = OnceCell::new();
static STRONGHOLD_ACCESS_STORE: OnceCell<Arc<Mutex<HashMap<PathBuf, Instant>>>> = OnceCell::new();

const DEFAULT_PASSWORD_CLEAR_INTERVAL: Duration = Duration::from_millis(0);

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("record not found")]
    RecordNotFound,
    #[error("snapshot password not set")]
    PasswordNotSet,
}

impl Serialize for Error {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.to_string().as_str())
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub struct VaultLocation {
    vault_path: String,
    record_path: String,
}

impl VaultLocation {
    fn from(vault: String, record: String) -> Self {
        Self {
            record_path: record,
            vault_path: vault,
        }
    }
    
    fn to_location(&self) -> Location {
        Location::Generic {
            record_path: self.record_path.clone().into_bytes().to_vec(),
            vault_path: self.vault_path.clone().into_bytes().to_vec(),
        }
    }
}

fn default_password_store() -> Arc<Mutex<HashMap<PathBuf, Arc<Password>>>> {
    thread::spawn(|| {
        spawn(async {
            loop {
                let interval = *PASSWORD_CLEAR_INTERVAL
                    .get_or_init(|| Arc::new(Mutex::new(DEFAULT_PASSWORD_CLEAR_INTERVAL)))
                    .lock()
                    .await;
                sleep(interval).await;

                if interval.as_nanos() == 0 {
                    continue;
                }

                let mut passwords = PASSWORD_STORE
                    .get_or_init(default_password_store)
                    .lock()
                    .await;
                let access_store = STRONGHOLD_ACCESS_STORE
                    .get_or_init(Default::default)
                    .lock()
                    .await;
                let mut snapshots_paths_to_clear = Vec::new();
                for (snapshot_path, _) in passwords.iter() {
                    // if the stronghold was accessed `interval` ago, we clear the password
                    if let Some(access_instant) = access_store.get(snapshot_path) {
                        if access_instant.elapsed() > interval {
                            snapshots_paths_to_clear.push(snapshot_path.clone());
                        }
                    }
                }

                let current_snapshot_path = &*CURRENT_SNAPSHOT_PATH
                    .get_or_init(Default::default)
                    .lock()
                    .await;
                for snapshot_path in snapshots_paths_to_clear {
                    passwords.remove(&snapshot_path);
                    if let Some(curr_snapshot_path) = current_snapshot_path {
                        if &snapshot_path == curr_snapshot_path {
                           // let mut runtime = actor_runtime().lock().await;
                          //  let _ = clear_stronghold_cache(&mut runtime, true);
                        }
                    }
                    /*emit_status_change(
                        &snapshot_path,
                        &Status {
                            snapshot: SnapshotStatus::Locked,
                        },
                    )
                    .await;*/
                }
            }
        })
    });
    Default::default()
}

async fn get_password(snapshot_path: &Path) -> Result<Arc<Password>> {
    PASSWORD_STORE
        .get_or_init(default_password_store)
        .lock()
        .await
        .get(snapshot_path)
        .cloned()
        .ok_or(Error::PasswordNotSet)
}

/// Calculates the Blake2b from a String
fn hash_blake2b(input: String) -> Vec<u8> {
    let mut hasher = Blake2b256::new();
    hasher.update(input.as_bytes());
    hasher.finalize().to_vec()
}

async fn create_snapshot(snapshot_path: &str, password: &str ) {
    let stronghold = Stronghold::default();

    let snapshot_path = SnapshotPath::from_path(format!("{:?}", snapshot_path.as_path()));
    let password_vec = password.as_bytes();
    let keyprovider = KeyProvider::try_from(password_vec).expect("KeyProvider failed");

    }

async fn read_snapshot(path: String, client_path: String, key: String, private_key_location: VaultLocation) {
    let stronghold = Stronghold::default();
    let client_path = client_path.as_bytes().to_vec();
    let snapshot_path = SnapshotPath::from_path(path);

    // calculate hash from key
    let key = hash_blake2b(key);
    let keyprovider = KeyProvider::try_from(key).expect("Failed to load key");

    let client = stronghold
        .load_client_from_snapshot(client_path, &keyprovider, &snapshot_path)
        .expect("Could not load client from Snapshot");

    // get the public key
    let public_key_procedure = stronghold::procedures::PublicKey {
        ty: KeyType::Ed25519,
        private_key: private_key_location.to_location(),
    };

    let procedure_result = client.execute_procedure(StrongholdProcedure::PublicKey(public_key_procedure));

    let procedure_result = procedure_result.unwrap();
    let output: Vec<u8> = procedure_result.into();
}

async fn write_from_store(key: String, value: String) -> Result<(), ClientError> {
    let client = Client::default();
    let store = client.store();

    store.insert(key.as_bytes().to_vec(), value.as_bytes().to_vec(), None)?;

    Ok(())
}

async fn read_from_store(key: String) -> String {
    let client = Client::default();
    let store = client.store();
    
    let record = store.get(key.as_bytes()).unwrap() ;
    
    return String::from_utf8(record.unwrap()).unwrap();
}

async fn init_vault() {
  let mut view: DbView<Provider> = DbView::new();

  let key = Key::random();
  let vaultId = VaultId::random::<Provider>().unwrap();
  
   view.init_vault(&key, vaultId);
}

async fn get_vault_value(view: DbView<Provider>, key: Key<Provider>, vault: VaultId, record: RecordId) -> Result<String, VaultError<Provider>> {
  view.get_guard::<Infallible, _>(&key, vault, record, |g| {
    Ok(from_utf8(&(*g.borrow())).unwrap())
  })
} 

async fn write_vault_value(view: DbView<Provider>, key: Key<Provider>, vault: VaultId, record: RecordId, data: String,  record_hint: RecordHint) -> Result<()> {
    view.write(&key, vault, record, data.as_bytes(), record_hint)?;
    Ok(())
}

async fn remove_vault_values(view: DbView<Provider>, key: Key<Provider>, vaultId: VaultId, recordId: RecordId) -> Result<(), VaultError<Provider>> {
    view.revoke_record(&key, vaultId, recordId)?;
    Ok(())
}
