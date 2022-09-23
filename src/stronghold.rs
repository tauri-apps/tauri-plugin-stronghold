use std::{convert::TryFrom, ops::Deref, path::Path};

use iota_stronghold::{KeyProvider, SnapshotPath};
use serde::{Serialize, Serializer};

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(feature = "p2p")]
type P2pServer = std::sync::Arc<
    std::sync::Mutex<
        Option<(
            tauri::async_runtime::JoinHandle<std::result::Result<(), iota_stronghold::ClientError>>,
            futures_channel::mpsc::UnboundedSender<()>,
        )>,
    >,
>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("stronghold not initialized")]
    StrongholdNotInitialized,
    #[error(transparent)]
    Stronghold(#[from] iota_stronghold::ClientError),
    #[error(transparent)]
    Memory(#[from] iota_stronghold::MemoryError),
    #[error(transparent)]
    Procedure(#[from] iota_stronghold::procedures::ProcedureError),
}

impl Serialize for Error {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.to_string().as_str())
    }
}

pub struct Stronghold {
    inner: iota_stronghold::Stronghold,
    path: SnapshotPath,
    keyprovider: KeyProvider,
    #[cfg(feature = "p2p")]
    pub(crate) p2p_server: P2pServer,
}

impl Stronghold {
    pub fn new<P: AsRef<Path>>(path: P, password: Vec<u8>) -> Result<Self> {
        let path = SnapshotPath::from_path(path);
        let stronghold = iota_stronghold::Stronghold::default();
        let keyprovider = KeyProvider::try_from(password)?;
        if path.exists() {
            stronghold.load_snapshot(&keyprovider, &path)?;
        }
        Ok(Self {
            inner: stronghold,
            path,
            keyprovider,
            #[cfg(feature = "p2p")]
            p2p_server: Default::default(),
        })
    }

    pub fn save(&self) -> Result<()> {
        self.inner.commit(&self.path, &self.keyprovider)?;
        Ok(())
    }

    #[cfg(feature = "p2p")]
    pub(crate) fn p2p_serve(&self) {
        let (sender_terminate_signal, receiver_terminate_signal) =
            futures_channel::mpsc::unbounded();

        let inner = self.inner.clone();
        let handle =
            tauri::async_runtime::spawn(
                async move { inner.serve(receiver_terminate_signal).await },
            );

        self.p2p_server
            .lock()
            .unwrap()
            .replace((handle, sender_terminate_signal));
    }

    pub fn inner(&self) -> &iota_stronghold::Stronghold {
        &self.inner
    }
}

#[cfg(feature = "p2p")]
pub(crate) async fn p2p_stop(p2p_server: P2pServer) {
    let server = p2p_server.lock().unwrap().take();
    if let Some((handle, mut sender_terminate_signal)) = server {
        use futures_util::SinkExt;
        let _ = sender_terminate_signal.send(()).await;
        let _ = handle.await;
    }
}

impl Deref for Stronghold {
    type Target = iota_stronghold::Stronghold;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}
