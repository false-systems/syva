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
        let mut map = self.inner.write().await;
        let should_remove = match map.get(&node_id) {
            Some(sender) if sender.receiver_count() == 0 => true,
            Some(sender) => {
                let _ = sender.send(());
                false
            }
            None => false,
        };

        if should_remove {
            map.remove(&node_id);
        }
    }
}

impl Default for AssignmentBus {
    fn default() -> Self {
        Self::new()
    }
}

pub async fn spawn_listener(pool: PgPool, bus: AssignmentBus) -> Result<JoinHandle<()>> {
    let handle = tokio::spawn(async move {
        let mut listener = match connect_listener(&pool).await {
            Ok(listener) => listener,
            Err(err) => {
                tracing::error!("bus: initial listener setup failed: {err}");
                return;
            }
        };

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
                    match connect_listener(&pool).await {
                        Ok(new_listener) => listener = new_listener,
                        Err(reconnect_err) => {
                            tracing::error!("bus: listener reconnect failed: {reconnect_err}");
                        }
                    }
                }
            }
        }
    });

    Ok(handle)
}

async fn connect_listener(pool: &PgPool) -> Result<PgListener> {
    let mut listener = PgListener::connect_with(pool).await?;
    listener.listen(CHANNEL).await?;
    Ok(listener)
}
