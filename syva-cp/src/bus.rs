use anyhow::Result;
use sqlx::postgres::{PgListener, PgPool};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
use tokio::task::JoinHandle;
use uuid::Uuid;

const CHANNEL: &str = "syva_cp_assignments";

#[derive(Clone)]
pub struct AssignmentBus {
    inner: Arc<RwLock<HashMap<Uuid, broadcast::Sender<()>>>>,
}

impl AssignmentBus {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn subscribe(&self, node_id: Uuid) -> broadcast::Receiver<()> {
        let mut map = self.inner.write().await;
        let entry = map
            .entry(node_id)
            .or_insert_with(|| broadcast::channel(64).0);
        entry.subscribe()
    }

    async fn notify(&self, node_id: Uuid) {
        let map = self.inner.read().await;
        if let Some(sender) = map.get(&node_id) {
            let _ = sender.send(());
        }
    }
}

impl Default for AssignmentBus {
    fn default() -> Self {
        Self::new()
    }
}

pub async fn spawn_listener(pool: PgPool, bus: AssignmentBus) -> Result<JoinHandle<()>> {
    let mut listener = PgListener::connect_with(&pool).await?;
    listener.listen(CHANNEL).await?;

    let handle = tokio::spawn(async move {
        loop {
            match listener.recv().await {
                Ok(notification) => {
                    let payload = notification.payload();
                    if let Ok(node_id) = Uuid::parse_str(payload) {
                        bus.notify(node_id).await;
                    } else {
                        tracing::warn!("bus: bad notify payload: {payload}");
                    }
                }
                Err(err) => {
                    tracing::error!("bus: listener error: {err}");
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                }
            }
        }
    });

    Ok(handle)
}
