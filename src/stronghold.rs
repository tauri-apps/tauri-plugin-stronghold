use async_std::{
    sync::Mutex,
    task::{sleep, spawn},
};
use iota_stronghold::{
    Location, ProcResult, Procedure, RecordHint, ResultMessage, Stronghold, StrongholdFlags,
    VaultFlags,
};
use once_cell::sync::{Lazy, OnceCell};
use riker::actors::*;
use serde::Serialize;
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
    on_event: Box<dyn FnMut(&PathBuf, &Status) + Send>,
}

type StrongholdStatusChangeListeners = Arc<Mutex<Vec<StatusChangeEventHandler>>>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("`{0}`")]
    StrongholdError(#[from] iota_stronghold::Error),
    #[error("record not found")]
    RecordNotFound,
    #[error("failed to perform action: `{0}`")]
    FailedToPerformAction(String),
    #[error("snapshot password not set")]
    PasswordNotSet,
}

pub type Result<T> = std::result::Result<T, Error>;

pub struct ActorRuntime {
    pub stronghold: Stronghold,
    spawned_client_paths: HashSet<Vec<u8>>,
    loaded_client_paths: HashSet<Vec<u8>>,
}

fn actor_runtime() -> &'static Arc<Mutex<ActorRuntime>> {
    static SYSTEM: Lazy<Arc<Mutex<ActorRuntime>>> = Lazy::new(|| {
        let system = SystemBuilder::new()
            .log(slog::Logger::root(slog::Discard, slog::o!()))
            .create()
            .unwrap();
        let stronghold = Stronghold::init_stronghold_system(system, vec![], vec![]);

        let runtime = ActorRuntime {
            stronghold,
            spawned_client_paths: Default::default(),
            loaded_client_paths: Default::default(),
        };
        Arc::new(Mutex::new(runtime))
    });
    &SYSTEM
}

fn status_change_listeners() -> &'static StrongholdStatusChangeListeners {
    static LISTENERS: Lazy<StrongholdStatusChangeListeners> = Lazy::new(Default::default);
    &LISTENERS
}

async fn emit_status_change(snapshot_path: &PathBuf, status: &Status) {
    let mut listeners = status_change_listeners().lock().await;
    for listener in listeners.deref_mut() {
        (listener.on_event)(&snapshot_path, &status)
    }
}

/// Listen to status change events.
pub async fn on_status_change<F: FnMut(&PathBuf, &Status) + Send + 'static>(cb: F) {
    let mut l = status_change_listeners().lock().await;
    l.push(StatusChangeEventHandler {
        on_event: Box::new(cb),
    })
}

pub fn stronghold_response_to_result<T>(status: ResultMessage<T>) -> Result<T> {
    match status {
        ResultMessage::Ok(v) => Ok(v),
        ResultMessage::Error(e) => Err(Error::FailedToPerformAction(e)),
    }
}

async fn load_actor(
    runtime: &mut ActorRuntime,
    snapshot_path: &PathBuf,
    client_path: &Vec<u8>,
    flags: &Vec<StrongholdFlags>,
) -> Result<()> {
    on_stronghold_access(&snapshot_path).await?;

    if runtime.spawned_client_paths.contains(client_path) {
        stronghold_response_to_result(
            runtime
                .stronghold
                .switch_actor_target(client_path.clone())
                .await,
        )?;
    } else {
        stronghold_response_to_result(
            runtime
                .stronghold
                .spawn_stronghold_actor(
                    client_path.clone(),
                    flags
                        .iter()
                        .map(|flag| match flag {
                            StrongholdFlags::IsReadable(flag) => StrongholdFlags::IsReadable(*flag),
                        })
                        .collect(),
                )
                .await,
        )?;
        runtime.spawned_client_paths.insert(client_path.clone());
    };

    if !runtime.loaded_client_paths.contains(client_path) {
        if snapshot_path.exists() {
            stronghold_response_to_result(
                runtime
                    .stronghold
                    .read_snapshot(
                        client_path.clone(),
                        None,
                        &get_password(snapshot_path).await?.0,
                        None,
                        Some(snapshot_path.to_path_buf()),
                    )
                    .await,
            )?;
        }
        runtime.loaded_client_paths.insert(client_path.clone());
    }

    Ok(())
}

async fn on_stronghold_access<S: AsRef<Path>>(snapshot_path: S) -> Result<()> {
    let passwords = PASSWORD_STORE
        .get_or_init(default_password_store)
        .lock()
        .await;
    if !passwords.contains_key(&snapshot_path.as_ref().to_path_buf()) {
        Err(Error::PasswordNotSet)
    } else {
        let mut store = STRONGHOLD_ACCESS_STORE
            .get_or_init(Default::default)
            .lock()
            .await;
        store.insert(snapshot_path.as_ref().to_path_buf(), Instant::now());
        Ok(())
    }
}

/// Set the password clear interval.
/// If the stronghold isn't used after `interval`, the password is cleared and must be set again.
pub async fn set_password_clear_interval(interval: Duration) {
    let mut clear_interval = PASSWORD_CLEAR_INTERVAL
        .get_or_init(|| Arc::new(Mutex::new(DEFAULT_PASSWORD_CLEAR_INTERVAL)))
        .lock()
        .await;
    *clear_interval = interval;
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
                            let mut runtime = actor_runtime().lock().await;
                            let _ = clear_stronghold_cache(&mut runtime, true);
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

async fn get_password_if_needed(
    snapshot_path: &PathBuf,
    password: Option<Arc<Password>>,
) -> Result<Arc<Password>> {
    match password {
        Some(password) => Ok(password),
        None => get_password(snapshot_path).await,
    }
}

async fn get_password(snapshot_path: &PathBuf) -> Result<Arc<Password>> {
    PASSWORD_STORE
        .get_or_init(default_password_store)
        .lock()
        .await
        .get(snapshot_path)
        .cloned()
        .ok_or(Error::PasswordNotSet)
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

pub struct Store {
    snapshot_path: PathBuf,
    name: Vec<u8>,
    flags: Vec<StrongholdFlags>,
}

impl Store {
    /// Gets a record.
    pub async fn get_record(&self, location: Location) -> Result<String> {
        let mut runtime = actor_runtime().lock().await;
        check_snapshot(&mut runtime, &self.snapshot_path, None).await?;

        load_actor(&mut runtime, &self.snapshot_path, &self.name, &self.flags).await?;

        let (data, status) = runtime.stronghold.read_from_store(location).await;
        stronghold_response_to_result(status).map_err(|_| Error::RecordNotFound)?;
        Ok(String::from_utf8_lossy(&data).to_string())
    }

    /// Saves a record.
    pub async fn save_record(
        &self,
        location: Location,
        record: String,
        lifetime: Option<Duration>,
    ) -> Result<()> {
        let mut runtime = actor_runtime().lock().await;
        check_snapshot(&mut runtime, &self.snapshot_path, None).await?;

        load_actor(&mut runtime, &self.snapshot_path, &self.name, &self.flags).await?;

        stronghold_response_to_result(
            runtime
                .stronghold
                .write_to_store(location, record.as_bytes().to_vec(), lifetime)
                .await,
        )?;

        Ok(())
    }

    /// Removes a record.
    pub async fn remove_record(&self, location: Location) -> Result<()> {
        let mut runtime = actor_runtime().lock().await;
        check_snapshot(&mut runtime, &self.snapshot_path, None).await?;

        load_actor(&mut runtime, &self.snapshot_path, &self.name, &self.flags).await?;

        stronghold_response_to_result(runtime.stronghold.delete_from_store(location).await)?;

        Ok(())
    }
}

pub struct Vault {
    snapshot_path: PathBuf,
    name: Vec<u8>,
    flags: Vec<StrongholdFlags>,
}

impl Vault {
    /// Saves a record.
    pub async fn save_record(
        &self,
        location: Location,
        record: String,
        hint: RecordHint,
        flags: Vec<VaultFlags>,
    ) -> Result<()> {
        let mut runtime = actor_runtime().lock().await;
        check_snapshot(&mut runtime, &self.snapshot_path, None).await?;

        load_actor(&mut runtime, &self.snapshot_path, &self.name, &self.flags).await?;

        stronghold_response_to_result(
            runtime
                .stronghold
                .write_to_vault(location, record.as_bytes().to_vec(), hint, flags)
                .await,
        )?;

        Ok(())
    }

    /// Removes a record.
    pub async fn remove_record(&self, location: Location, gc: bool) -> Result<()> {
        let mut runtime = actor_runtime().lock().await;
        check_snapshot(&mut runtime, &self.snapshot_path, None).await?;

        load_actor(&mut runtime, &self.snapshot_path, &self.name, &self.flags).await?;

        stronghold_response_to_result(runtime.stronghold.delete_data(location, gc).await)?;

        Ok(())
    }

    pub async fn execute_procedure(&self, procedure: Procedure) -> Result<ProcResult> {
        let mut runtime = actor_runtime().lock().await;
        check_snapshot(&mut runtime, &self.snapshot_path, None).await?;

        load_actor(&mut runtime, &self.snapshot_path, &self.name, &self.flags).await?;

        let result = runtime.stronghold.runtime_exec(procedure).await;
        Ok(result)
    }
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

    pub fn get_vault<S: AsRef<str>>(&self, name: S, flags: Vec<StrongholdFlags>) -> Vault {
        Vault {
            snapshot_path: self.snapshot_path.clone(),
            name: name.as_ref().as_bytes().to_vec(),
            flags,
        }
    }

    pub fn get_store<S: AsRef<str>>(&self, name: S, flags: Vec<StrongholdFlags>) -> Store {
        Store {
            snapshot_path: self.snapshot_path.clone(),
            name: name.as_ref().as_bytes().to_vec(),
            flags,
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
    mut runtime: &mut ActorRuntime,
    snapshot_path: &PathBuf,
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
            switch_snapshot(&mut runtime, snapshot_path).await?;
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
                            &get_password_if_needed(&snapshot_path, password)
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
            .replace(snapshot_path.clone());
    }

    Ok(())
}

// saves the snapshot to the file system.
async fn save_snapshot(runtime: &mut ActorRuntime, snapshot_path: &PathBuf) -> Result<()> {
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
            save_snapshot(&mut runtime, &curr_snapshot_path).await?;
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

async fn switch_snapshot(mut runtime: &mut ActorRuntime, snapshot_path: &PathBuf) -> Result<()> {
    clear_stronghold_cache(&mut runtime, true).await?;

    CURRENT_SNAPSHOT_PATH
        .get_or_init(Default::default)
        .lock()
        .await
        .replace(snapshot_path.clone());

    Ok(())
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

                let store = api.get_store("", vec![]);
                let res = store.get_record(get_location("passwordexpires")).await;
                assert_eq!(res.is_err(), true);
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
                let store = api.get_store("", vec![]);

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
                assert_eq!(res.is_ok(), true);

                std::thread::sleep(interval * 2);

                let res = store.get_record(get_location(&id)).await;
                assert_eq!(res.is_err(), true);
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
        let store = api.get_store("", vec![]);

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
        let store = api.get_store("", vec![]);

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
            let store = api.get_store("", vec![]);

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
            let store = api.get_store("", vec![]);
            let stored_data = store.get_record(get_location(&account_id)).await?;
            assert_eq!(stored_data, data);
        }

        Ok(())
    }
}
