pub use iota_stronghold::Location;
use tauri::{plugin::Plugin, Invoke, Runtime};

pub mod stronghold;

pub struct TauriStronghold<R: Runtime> {
    invoke_handler: Box<dyn Fn(Invoke<R>) + Send + Sync>,
}

impl<R: Runtime> Default for TauriStronghold<R> {
    fn default() -> Self {
        Self {
            invoke_handler: Box::new(tauri::generate_handler![
              save_record
           ]),
        }
    }
}

impl<R: Runtime> Plugin<R> for TauriStronghold<R> {
    fn name(&self) -> &'static str {
        "stronghold"
    }

    fn extend_api(&mut self, invoke: Invoke<R>) {
        (self.invoke_handler)(invoke)
    }
}

pub struct TauriStronghold<R: Runtime> {
    invoke_handler: Box<dyn Fn(Invoke<R>) + Send + Sync>,
}

#[tauri::command]
async fn save_record() {
    
}
