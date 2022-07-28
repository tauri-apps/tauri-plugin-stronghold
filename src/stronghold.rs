use async_std::{
    sync::Mutex,
    task::{sleep, spawn},
};
use std::{
    collections::{HashMap},
    sync::Arc,
    path::{Path, PathBuf},
    thread,
    convert::{TryFrom, Infallible},
    ops::DerefMut,
    time::{Duration, Instant},
    str::from_utf8
};
use crypto::hashes::{blake2b::Blake2b256, Digest};
use once_cell::sync::{Lazy, OnceCell};
use iota_stronghold as stronghold;
use stronghold::{
    Client, ClientError, KeyProvider, Location, SnapshotPath, Stronghold, RecordError, VaultError, Provider, SnapshotError
};
use engine::vault::{DbView, Key, RecordHint, RecordId, VaultId};
use serde::{ser::Serializer, Serialize};
use zeroize::Zeroize;

struct StatusChangeEventHandler {
    on_event: Box<dyn FnMut(&Path, &Status) + Send>,
}

type StrongholdStatusChangeListeners = Arc<Mutex<Vec<StatusChangeEventHandler>>>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("`{0}`")]
    ClientError(#[from] ClientError),
    #[error("`{0}`")]
    SnapshotError(#[from] SnapshotError),
    #[error("`{0}`")]
    VaultError(#[from] VaultError<Infallible>),
    #[error("record not found")]
    RecordNotFound(#[from] RecordError),
    #[error("failed to perform action: `{0}`")]
    FailedToPerformAction(String),
    #[error("snapshot password not set")]
    PasswordNotSet,
    #[error(transparent)]
    InvalidPeer(Box<dyn std::error::Error + Send>),
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

fn status_change_listeners() -> &'static StrongholdStatusChangeListeners {
    static LISTENERS: Lazy<StrongholdStatusChangeListeners> = Lazy::new(Default::default);
    &LISTENERS
}

async fn emit_status_change(snapshot_path: &Path, status: &Status) {
    let mut listeners = status_change_listeners().lock().await;
    for listener in listeners.deref_mut() {
        (listener.on_event)(snapshot_path, status)
    }
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

async fn get_password_if_needed(
    snapshot_path: &Path,
    password: Option<Arc<Password>>,
) -> Result<Arc<Password>> {
    match password {
        Some(password) => Ok(password),
        None => get_password(snapshot_path).await,
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
                            let _ = clear_stronghold_cache(true);
                        }
                    }
                    emit_status_change(
                        &snapshot_path,
                        &Status {
                            snapshot: SnapshotStatus::Locked,
                        },
                    )
                    .await;
                }
            }
        })
    });
    Default::default()
}

/// Calculates the Blake2b from a String
fn hash_blake2b(input: String) -> Vec<u8> {
    let mut hasher = Blake2b256::new();
    hasher.update(input.as_bytes());
    hasher.finalize().to_vec()
}

async fn create_snapshot(snapshot_path: &str, client_path: &str, password: Vec<u8>) -> Result<()> {
    let stronghold = Stronghold::default();
    let snapshot_path = SnapshotPath::from_path(Path::new(snapshot_path));
  //  let password_vec = password.as_bytes().to_vec();
    let keyprovider = KeyProvider::try_from(password).expect("can not load password");

    stronghold.create_client(client_path)?;
    Ok(()) 
    }

async fn read_snapshot(path: String, client_path: String, password: Vec<u8>) -> Result<()> {
    let stronghold = Stronghold::default();
    let client_path = client_path.as_bytes().to_vec();
    let snapshot_path = SnapshotPath::from_path(path);

    let keyprovider = KeyProvider::try_from(password).expect("can not load password");

    let client = stronghold
        .load_client_from_snapshot(client_path, &keyprovider, &snapshot_path)?;
}

/// Snapshot status.
#[derive(Debug, Serialize)]
#[serde(tag = "status", content = "data")]
pub enum SnapshotStatus {
    /// Snapshot is locked. This means that the password must be set again.
    Locked,
    /// Snapshot is unlocked. The duration is the amount of time left before it locks again.
    Unlocked(Duration),
}

#[derive(Debug, Serialize)]
/// Stronghold status.
pub struct Status {
    snapshot: SnapshotStatus,
}

#[derive(Debug)]
pub struct Api {
    snapshot_path: PathBuf,
}

impl Api {
    pub async fn load(&self, password: Vec<u8>) -> Result<()> {
        if CURRENT_SNAPSHOT_PATH
            .get_or_init(Default::default)
            .lock()
            .await
            .as_ref()
            == Some(&self.snapshot_path)
        {
            let (is_password_empty, is_password_updated) = {
                let passwords = PASSWORD_STORE
                    .get_or_init(default_password_store)
                    .lock()
                    .await;
                let stored_password = passwords.get(&self.snapshot_path).map(|p| &p.0);
                (
                    stored_password.is_none(),
                    stored_password != Some(&password),
                )
            };
            if !is_password_empty && is_password_updated
            {
                save_snapshot(&self.snapshot_path).await?;
            }
        }
        check_snapshot(
            &self.snapshot_path,
            Some(Arc::new(Password(password.clone()))),
        )
        .await?;
        self.set_password(password).await;
        emit_status_change(&self.snapshot_path, &self.get_status().await).await;
        Ok(())
    }

    pub async fn unload(&self, persist: bool) -> Result<()> {
        let current_snapshot_path = CURRENT_SNAPSHOT_PATH
            .get_or_init(Default::default)
            .lock()
            .await
            .clone();
        if let Some(current) = &current_snapshot_path {
            if current == &self.snapshot_path {
                clear_stronghold_cache(persist).await?;
                CURRENT_SNAPSHOT_PATH
                    .get_or_init(Default::default)
                    .lock()
                    .await
                    .take();
            }
        }

        Ok(())
    }
} 

//Store API
async fn write_from_store(key: String, value: String) -> Result<()> {
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

//Vault API
pub async fn init(password: Key<Provider>, vaultId: VaultId) {
  let mut view: DbView<Provider> = DbView::new();
  
  view.init_vault(&password, vaultId);
}

async fn get_record(view: DbView<Provider>, key: Key<Provider>, vault: VaultId, record: RecordId) -> Result<String> {
  view.get_guard::<Infallible, _>(&key, vault, record, |g| {
    Ok(from_utf8(&(*g.borrow())).unwrap().to_owned())
  })
} 

async fn save_record(view: DbView<Provider>, key: Key<Provider>, vault: VaultId, record: RecordId, data: String,  record_hint: RecordHint) -> Result<()> {
    view.write(&key, vault, record, data.as_bytes(), record_hint)?;
    Ok(())
}

async fn remove_record(view: DbView<Provider>, key: Key<Provider>, vaultId: VaultId, recordId: RecordId) -> Result<()> {
    view.revoke_record(&key, vaultId, recordId)?;
    Ok(())
}

// check if the snapshot path is different than the current loaded one
// if it is, write the current snapshot and load the new one
async fn check_snapshot(
    snapshot_path: &Path,
    password: Option<Arc<Password>>,
) -> Result<()> {
    let curr_snapshot_path = CURRENT_SNAPSHOT_PATH
        .get_or_init(Default::default)
        .lock()
        .await
        .as_ref()
        .cloned();

    if let Some(curr_snapshot_path) = &curr_snapshot_path {
        // if the current loaded snapshot is different than the snapshot we're tring to use,
        // save the current snapshot and clear the cache
        if curr_snapshot_path != snapshot_path {
            switch_snapshot(snapshot_path).await?;
        }
        if snapshot_path.exists() {
            if let Some(client_path) {
                // reload a client to check if the password is correct
		read_snasphot(snapshot_path, client_path, password )?;
            }
        }
    } else {
        CURRENT_SNAPSHOT_PATH
            .get_or_init(Default::default)
            .lock()
            .await
            .replace(snapshot_path.to_path_buf());
    }

    Ok(())
}

// saves the snapshot to the file system.
async fn save_snapshot(stronghold: Stronghold, snapshot_path: String, key: String) -> Result<()> {
    stronghold.commit(&SnapshotPath::from_path(snapshot_path), &KeyProvider::try_from(key))?;
    Ok(()) 
}

async fn clear_stronghold_cache(persist: bool) -> Result<()> {
    if let Some(curr_snapshot_path) = CURRENT_SNAPSHOT_PATH
        .get_or_init(Default::default)
        .lock()
        .await
        .as_ref()
    {
        if persist {
            save_snapshot(curr_snapshot_path).await?;
        } 
	Stronghold::reset();
    }

    Ok(())
}

async fn switch_snapshot(snapshot_path: &Path) -> Result<()> {
    clear_stronghold_cache(true).await?;

    CURRENT_SNAPSHOT_PATH
        .get_or_init(Default::default)
        .lock()
        .await
        .replace(snapshot_path.to_path_buf());

    Ok(())
}
