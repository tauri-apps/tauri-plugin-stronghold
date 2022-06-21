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
use engine::vault::RecordHint;

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

