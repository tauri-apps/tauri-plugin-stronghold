use async_std::{
    sync::Mutex,
    task::{sleep, spawn},
};

use engine::{
    vault::RecordHint,
    snapshot::{
        files,
        logic::*,
    },
};

use once_cell::sync::{OnceCell};
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

/// Set the password clear interval.
/// If the stronghold isn't used after `interval`, the password is cleared and must be set again.
pub async fn set_password_clear_interval(interval: Duration) {
    let mut clear_interval = PASSWORD_CLEAR_INTERVAL
        .get_or_init(|| Arc::new(Mutex::new(DEFAULT_PASSWORD_CLEAR_INTERVAL)))
        .lock()
        .await;
    *clear_interval = interval;
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

async fn get_password(snapshot_path: &Path) -> Result<Arc<Password>> {
    PASSWORD_STORE
        .get_or_init(default_password_store)
        .lock()
        .await
        .get(snapshot_path)
        .cloned()
        .ok_or(Error::PasswordNotSet)
}

fn init_or_check_snapshot(name: Option<&str>) {
    file::get_path(name)
     .map_err(|error| format!("Failed to create snapshot", error))?;
}
