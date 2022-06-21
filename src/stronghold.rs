use async_std::{
    sync::Mutex,
    task::{sleep, spawn},
};
pub use engine::vault::RecordId;
use iota_stronghold as stronghold;
use stronghold::{
    procedures::{
        BIP39Generate, Chain, GenerateKey, KeyType, MnemonicLanguage, Slip10Derive, Slip10DeriveInput, Slip10Generate,
        StrongholdProcedure,
    },
    Client, ClientError, ClientVault, KeyProvider, Location, SnapshotPath, Store, Stronghold,
};
use p2p::{Multiaddr, PeerId};
use engine::vault::{RecordHint, Snapshot};

use once_cell::sync::{Lazy, OnceCell};
use riker::actors::*;
use serde::{ser::Serializer, Serialize};
use zeroize::Zeroize;

use std::{
    collections::{HashMap, HashSet},
    ops::DerefMut,
    path::{Path, PathBuf},
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

#[derive(PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
struct Password(Vec<u8>);

type SnapshotToPasswordMap = HashMap<PathBuf, Arc<Password>>;
static PASSWORD_STORE: OnceCell<Arc<Mutex<SnapshotToPasswordMap>>> = OnceCell::new();
static STRONGHOLD_ACCESS_STORE: OnceCell<Arc<Mutex<HashMap<PathBuf, Instant>>>> = OnceCell::new();
static CURRENT_SNAPSHOT_PATH: OnceCell<Arc<Mutex<Option<PathBuf>>>> = OnceCell::new();
static PASSWORD_CLEAR_INTERVAL: OnceCell<Arc<Mutex<Duration>>> = OnceCell::new();

const DEFAULT_PASSWORD_CLEAR_INTERVAL: Duration = Duration::from_millis(0);

struct StatusChangeEventHandler {
    on_event: Box<dyn FnMut(&Path, &Status) + Send>,
}

type StrongholdStatusChangeListeners = Arc<Mutex<Vec<StatusChangeEventHandler>>>;

#[derive(Debug, Clone)]
pub struct SwarmInfo {
    pub peer_id: PeerId,
    pub listening_addresses: Vec<Multiaddr>,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("`{0}`")]
    StrongholdError(#[from] iota_stronghold::ClientError),
    #[error("record not found")]
    RecordNotFound,
    #[error("failed to perform action: `{0}`")]
    FailedToPerformAction(String),
    #[error("snapshot password not set")]
    PasswordNotSet,
    #[error(transparent)]
    InvalidPeer(Box<dyn std::error::Error + Send>),
}

#[derive(Debug)]
pub struct Api {
    snapshot_path: PathBuf,
}

impl Api {
    pub fn new<S: AsRef<Path>>(snapshot_path: S) -> Self {
        Self {
            snapshot_path: snapshot_path.as_ref().to_path_buf(),
        }
    }

    pub fn get_vault<S: AsRef<str>>(&self, name: S) -> Vault {
        Vault {
            snapshot_path: self.snapshot_path.clone(),
            name: name.as_ref().as_bytes().to_vec(),
        }
    }

    pub fn get_store<S: AsRef<str>>(&self, name: S) -> Store {
        Store {
            snapshot_path: self.snapshot_path.clone(),
            name: name.as_ref().as_bytes().to_vec(),
        }
    }

    pub async fn load(&self, password: Vec<u8>) -> Result<()> {
        let mut runtime = actor_runtime().lock().await;
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
            if !runtime.spawned_client_paths.is_empty() && !is_password_empty && is_password_updated
            {
                save_snapshot(&mut runtime, &self.snapshot_path).await?;
            }
        }
        check_snapshot(
            &mut runtime,
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
                let mut runtime = actor_runtime().lock().await;
                clear_stronghold_cache(&mut runtime, persist).await?;
                CURRENT_SNAPSHOT_PATH
                    .get_or_init(Default::default)
                    .lock()
                    .await
                    .take();
            }
        }

        Ok(())
    }

    pub async fn save(&self) -> Result<()> {
        let mut runtime = actor_runtime().lock().await;
        save_snapshot(&mut runtime, &self.snapshot_path).await
    }

    /// Gets the stronghold status for the given snapshot.
    pub async fn get_status(&self) -> Status {
        let password_clear_interval = *PASSWORD_CLEAR_INTERVAL
            .get_or_init(|| Arc::new(Mutex::new(DEFAULT_PASSWORD_CLEAR_INTERVAL)))
            .lock()
            .await;
        if let Some(access_instant) = STRONGHOLD_ACCESS_STORE
            .get_or_init(Default::default)
            .lock()
            .await
            .get(&self.snapshot_path)
        {
            let locked = password_clear_interval.as_millis() > 0
                && access_instant.elapsed() >= password_clear_interval;
            Status {
                snapshot: if locked {
                    SnapshotStatus::Locked
                } else {
                    SnapshotStatus::Unlocked(if password_clear_interval.as_millis() == 0 {
                        password_clear_interval
                    } else {
                        password_clear_interval - access_instant.elapsed()
                    })
                },
            }
        } else {
            Status {
                snapshot: SnapshotStatus::Locked,
            }
        }
    }

    pub async fn set_password(&self, password: Vec<u8>) {
        let mut passwords = PASSWORD_STORE
            .get_or_init(default_password_store)
            .lock()
            .await;
        let mut access_store = STRONGHOLD_ACCESS_STORE
            .get_or_init(Default::default)
            .lock()
            .await;

        access_store.insert(self.snapshot_path.clone(), Instant::now());
        passwords.insert(self.snapshot_path.clone(), Arc::new(Password(password)));
    }
}

// check if the snapshot path is different than the current loaded one
// if it is, write the current snapshot and load the new one
async fn check_snapshot(
    runtime: &mut ActorRuntime,
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
            switch_snapshot(runtime, snapshot_path).await?;
        }
        if snapshot_path.exists() {
            if let Some(client_path) = runtime.loaded_client_paths.iter().next() {
                // reload a client to check if the password is correct
                stronghold_response_to_result(
                    runtime
                        .stronghold
                        .read_snapshot(
                            client_path.to_vec(),
                            None,
                            &get_password_if_needed(snapshot_path, password)
                                .await?
                                .0
                                .to_vec(),
                            None,
                            Some(snapshot_path.to_path_buf()),
                        )
                        .await,
                )?;
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
async fn save_snapshot(runtime: &mut ActorRuntime, snapshot_path: &Path) -> Result<()> {
    stronghold_response_to_result(
        runtime
            .stronghold
            .write_all_to_snapshot(
                &get_password(snapshot_path).await?.0.to_vec(),
                None,
                Some(snapshot_path.to_path_buf()),
            )
            .await,
    )
}

async fn clear_stronghold_cache(mut runtime: &mut ActorRuntime, persist: bool) -> Result<()> {
    if let Some(curr_snapshot_path) = CURRENT_SNAPSHOT_PATH
        .get_or_init(Default::default)
        .lock()
        .await
        .as_ref()
    {
        if persist && !runtime.spawned_client_paths.is_empty() {
            save_snapshot(runtime, curr_snapshot_path).await?;
        }
        for path in &runtime.spawned_client_paths {
            stronghold_response_to_result(
                runtime
                    .stronghold
                    .kill_stronghold(path.clone(), false)
                    .await,
            )?;
            stronghold_response_to_result(
                runtime.stronghold.kill_stronghold(path.clone(), true).await,
            )?;
        }
        // delay to wait for the actors to be killed
        thread::sleep(std::time::Duration::from_millis(300));
        runtime.spawned_client_paths = HashSet::new();
        runtime.loaded_client_paths = HashSet::new();
    }

    Ok(())
}

async fn switch_snapshot(runtime: &mut ActorRuntime, snapshot_path: &Path) -> Result<()> {
    clear_stronghold_cache(runtime, true).await?;

    CURRENT_SNAPSHOT_PATH
        .get_or_init(Default::default)
        .lock()
        .await
        .replace(snapshot_path.to_path_buf());

    Ok(())
}

//Create new Snapshot
pub fn new (name: Option<&str>) {
    Snapshot::get_path(name);
}

#[cfg(test)]
mod tests {
    use iota_stronghold::Location;
    use rand::{distributions::Alphanumeric, thread_rng, Rng};
    use rusty_fork::rusty_fork_test;
    use std::path::PathBuf;
    use std::time::Duration;

    fn get_location(name: &str) -> Location {
        Location::generic(name, name)
    }

    rusty_fork_test! {
        #[test]
        fn password_expires() {
            async_std::task::block_on(async {
                let interval = 500;
                super::set_password_clear_interval(Duration::from_millis(interval)).await;
                let snapshot_path: String = std::iter::repeat(())
                  .map(|()| thread_rng().sample(Alphanumeric))
                  .map(char::from)
                  .take(10)
                  .collect();
                std::fs::create_dir_all("./test-storage").unwrap();
                let snapshot_path = PathBuf::from(format!("./test-storage/{}.stronghold", snapshot_path));

                let api = super::Api::new(&snapshot_path);
                api.load([0; 32].to_vec()).await.unwrap();

                std::thread::sleep(Duration::from_millis(interval * 3));

                let store = api.get_store("");
                let res = store.get_record(get_location("passwordexpires")).await;
                assert!(res.is_err());
                let error = res.unwrap_err();
                if let super::Error::PasswordNotSet = error {
                    let status = api.get_status().await;
                    if let super::SnapshotStatus::Unlocked(_) = status.snapshot {
                        panic!("unexpected snapshot status");
                    }
                } else {
                    panic!("unexpected error: {:?}", error);
                }
            });
        }
    }

    rusty_fork_test! {
        #[test]
        fn action_keeps_password() {
            async_std::task::block_on(async {
                let interval = Duration::from_millis(900);
                super::set_password_clear_interval(interval).await;
                let snapshot_path: String = std::iter::repeat(())
        .map(|()| thread_rng().sample(Alphanumeric))
        .map(char::from)
        .take(10)
        .collect();
                std::fs::create_dir_all("./test-storage").unwrap();
                let snapshot_path = PathBuf::from(format!("./test-storage/{}.stronghold", snapshot_path));

                let api = super::Api::new(&snapshot_path);
                api.load([0; 32].to_vec()).await.unwrap();
                let store = api.get_store("");

                for i in 1..6 {
                    let instant = std::time::Instant::now();
                    store.save_record(
                        get_location(&format!("actionkeepspassword{}", i)),
                        "data".to_string(),
                        None,
                    )
                    .await
                    .unwrap();

                    let status = api.get_status().await;
                    if let super::SnapshotStatus::Locked = status.snapshot {
                        panic!("unexpected snapshot status");
                    }

                    if let Some(sleep_duration) = interval.checked_sub(instant.elapsed()) {
                        std::thread::sleep(sleep_duration / 2);
                    } else {
                        // if the elapsed > interval, set the password again
                        // this might happen if the test is stopped by another thread
                        api.set_password([0; 32].to_vec()).await;
                    }
                }

                let id = "actionkeepspassword1".to_string();
                let res = store.get_record(get_location(&id)).await;
                assert!(res.is_ok());

                std::thread::sleep(interval * 2);

                let res = store.get_record(get_location(&id)).await;
                assert!(res.is_err());
                if let super::Error::PasswordNotSet = res.unwrap_err() {
                    let status = api.get_status().await;
                    if let super::SnapshotStatus::Unlocked(_) = status.snapshot {
                        panic!("unexpected snapshot status");
                    }
                } else {
                    panic!("unexpected error");
                }
            });
        }
    }

    #[async_std::test]
    async fn write_and_read() -> super::Result<()> {
        let snapshot_path: String = std::iter::repeat(())
            .map(|()| thread_rng().sample(Alphanumeric))
            .map(char::from)
            .take(10)
            .collect();
        std::fs::create_dir_all("./test-storage").unwrap();
        let snapshot_path = PathBuf::from(format!("./test-storage/{}.stronghold", snapshot_path));

        let api = super::Api::new(&snapshot_path);
        api.load([0; 32].to_vec()).await.unwrap();
        let store = api.get_store("");

        let id = "writeandreadtest".to_string();
        let data = "account data";
        store
            .save_record(get_location(&id), data.to_string(), None)
            .await?;
        let stored_data = store.get_record(get_location(&id)).await?;
        assert_eq!(stored_data, data);

        Ok(())
    }

    #[async_std::test]
    async fn write_and_delete() -> super::Result<()> {
        let snapshot_path: String = std::iter::repeat(())
            .map(|()| thread_rng().sample(Alphanumeric))
            .map(char::from)
            .take(10)
            .collect();
        std::fs::create_dir_all("./test-storage").unwrap();
        let snapshot_path = PathBuf::from(format!("./test-storage/{}.stronghold", snapshot_path));

        let api = super::Api::new(&snapshot_path);
        api.load([0; 32].to_vec()).await.unwrap();
        let store = api.get_store("");

        let id = "writeanddeleteid".to_string();
        let data = "account data";
        store
            .save_record(get_location(&id), data.to_string(), None)
            .await?;
        store.remove_record(get_location(&id)).await?;

        Ok(())
    }

    #[async_std::test]
    async fn write_and_read_multiple_snapshots() -> super::Result<()> {
        let mut snapshot_saves = vec![];

        for i in 1..3 {
            let snapshot_path: String = std::iter::repeat(())
                .map(|()| thread_rng().sample(Alphanumeric))
                .map(char::from)
                .take(10)
                .collect();
            std::fs::create_dir_all("./test-storage").unwrap();
            let snapshot_path =
                PathBuf::from(format!("./test-storage/{}.stronghold", snapshot_path));

            let api = super::Api::new(&snapshot_path);
            api.load([0; 32].to_vec()).await.unwrap();
            let store = api.get_store("");

            let id = format!("multiplesnapshots{}", i);
            let data: String = std::iter::repeat(())
                .map(|()| thread_rng().sample(Alphanumeric))
                .map(char::from)
                .take(10)
                .collect();
            store
                .save_record(get_location(&id), data.clone(), None)
                .await?;
            snapshot_saves.push((snapshot_path, id, data));
        }

        for (snapshot_path, account_id, data) in snapshot_saves {
            let api = super::Api::new(&snapshot_path);
            api.load([0; 32].to_vec()).await.unwrap();
            let store = api.get_store("");
            let stored_data = store.get_record(get_location(&account_id)).await?;
            assert_eq!(stored_data, data);
        }

        Ok(())
    }
}
