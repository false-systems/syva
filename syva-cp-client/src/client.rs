use crate::error::CpClientError;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tonic::transport::{Channel, Endpoint};
use tracing::{debug, info, warn};
use uuid::Uuid;

use syva_proto::syva_control::v1::assignment_service_client::AssignmentServiceClient;
use syva_proto::syva_control::v1::node_service_client::NodeServiceClient;
use syva_proto::syva_control::v1::{
    AppliedAssignment, FailedAssignment, HeartbeatRequest, NodeAssignmentUpdate,
    RegisterNodeRequest, ReportAssignmentStateRequest, SubscribeAssignmentsRequest,
};

#[derive(Debug, Clone)]
pub struct NodeRegistration {
    pub node_id: Uuid,
    pub node_name: String,
}

#[derive(Debug, Clone)]
pub struct CpClientConfig {
    pub endpoint: String,
    pub node_name: String,
    pub cluster_id: Option<String>,
    pub fingerprint: Option<String>,
    pub labels: BTreeMap<String, String>,
    pub node_id_path: PathBuf,
    pub heartbeat_interval: Duration,
    pub connect_timeout: Duration,
}

impl Default for CpClientConfig {
    fn default() -> Self {
        Self {
            endpoint: "http://127.0.0.1:50051".to_string(),
            node_name: "unknown".to_string(),
            cluster_id: None,
            fingerprint: None,
            labels: BTreeMap::new(),
            node_id_path: PathBuf::from("/var/lib/syva/node-id"),
            heartbeat_interval: Duration::from_secs(15),
            connect_timeout: Duration::from_secs(5),
        }
    }
}

#[derive(Clone)]
pub struct CpClient {
    config: CpClientConfig,
    channel: Channel,
    registration: Arc<RwLock<Option<NodeRegistration>>>,
}

impl CpClient {
    pub async fn connect(config: CpClientConfig) -> Result<Self, CpClientError> {
        let endpoint = Endpoint::from_shared(config.endpoint.clone())
            .map_err(|error| CpClientError::InvalidEndpoint(error.to_string()))?
            .connect_timeout(config.connect_timeout)
            .tcp_keepalive(Some(Duration::from_secs(30)));

        let channel = endpoint.connect().await?;
        info!(endpoint = %config.endpoint, "connected to syva-cp");

        Ok(Self {
            config,
            channel,
            registration: Arc::new(RwLock::new(None)),
        })
    }

    pub async fn register(&self) -> Result<NodeRegistration, CpClientError> {
        let proposed_id = self.read_or_generate_node_id().await;

        let mut client = NodeServiceClient::new(self.channel.clone());
        let request = RegisterNodeRequest {
            node_name: self.config.node_name.clone(),
            fingerprint: self.config.fingerprint.clone().unwrap_or_default(),
            cluster_id: self.config.cluster_id.clone().unwrap_or_default(),
            labels: self.config.labels.clone().into_iter().collect(),
            capabilities_json: "{}".to_string(),
            proposed_id: proposed_id.to_string(),
        };
        let response = client.register_node(request).await?.into_inner();

        let assigned_id = Uuid::parse_str(&response.assigned_id)
            .map_err(|error| CpClientError::Internal(format!("bad assigned_id: {error}")))?;

        self.persist_node_id(assigned_id).await;

        let registration = NodeRegistration {
            node_id: assigned_id,
            node_name: self.config.node_name.clone(),
        };

        *self.registration.write().await = Some(registration.clone());
        info!(node_id = %assigned_id, "registered with syva-cp");
        Ok(registration)
    }

    pub async fn heartbeat(&self, status_hint: &str) -> Result<(), CpClientError> {
        let node_id = self.require_registered().await?;
        let mut client = NodeServiceClient::new(self.channel.clone());
        client
            .heartbeat(HeartbeatRequest {
                node_id: node_id.to_string(),
                status_hint: status_hint.to_string(),
            })
            .await?;
        Ok(())
    }

    pub fn spawn_heartbeat_loop(&self) -> tokio::task::JoinHandle<()> {
        let client = self.clone();
        let interval = client.config.heartbeat_interval;

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

            loop {
                ticker.tick().await;
                match client.heartbeat("online").await {
                    Ok(()) => debug!("heartbeat sent"),
                    Err(error) => warn!("heartbeat failed: {error}"),
                }
            }
        })
    }

    pub async fn subscribe_assignments(
        &self,
    ) -> Result<tonic::Streaming<NodeAssignmentUpdate>, CpClientError> {
        let node_id = self.require_registered().await?;
        let mut client = AssignmentServiceClient::new(self.channel.clone());
        let stream = client
            .subscribe_assignments(SubscribeAssignmentsRequest {
                node_id: node_id.to_string(),
            })
            .await?
            .into_inner();
        Ok(stream)
    }

    pub async fn report_assignment_state(
        &self,
        applied: Vec<AppliedReport>,
        failed: Vec<FailedReport>,
    ) -> Result<(usize, usize), CpClientError> {
        let node_id = self.require_registered().await?;
        let mut client = AssignmentServiceClient::new(self.channel.clone());
        let response = client
            .report_assignment_state(ReportAssignmentStateRequest {
                node_id: node_id.to_string(),
                applied: applied
                    .into_iter()
                    .map(|item| AppliedAssignment {
                        assignment_id: item.assignment_id.to_string(),
                        actual_zone_version: item.actual_zone_version,
                        actual_policy_id: item.actual_policy_id.to_string(),
                    })
                    .collect(),
                failed: failed
                    .into_iter()
                    .map(|item| FailedAssignment {
                        assignment_id: item.assignment_id.to_string(),
                        error_json: item.error_json.to_string(),
                    })
                    .collect(),
            })
            .await?
            .into_inner();

        Ok((
            response.accepted_count as usize,
            response.rejected_count as usize,
        ))
    }

    async fn require_registered(&self) -> Result<Uuid, CpClientError> {
        self.registration
            .read()
            .await
            .as_ref()
            .map(|registration| registration.node_id)
            .ok_or(CpClientError::NotRegistered)
    }

    async fn read_or_generate_node_id(&self) -> Uuid {
        match tokio::fs::read_to_string(&self.config.node_id_path).await {
            Ok(text) => {
                let trimmed = text.trim();
                if let Ok(uuid) = Uuid::parse_str(trimmed) {
                    return uuid;
                }
            }
            Err(error) => {
                debug!(
                    path = %self.config.node_id_path.display(),
                    error = %error,
                    "node id file not readable; generating a fresh id"
                );
            }
        }

        Uuid::from_u128(ulid::Ulid::new().0)
    }

    async fn persist_node_id(&self, id: Uuid) {
        if let Some(parent) = self.config.node_id_path.parent() {
            if let Err(error) = tokio::fs::create_dir_all(parent).await {
                warn!(
                    path = %parent.display(),
                    error = %error,
                    "could not create node-id directory"
                );
                return;
            }
        }

        if let Err(error) = tokio::fs::write(&self.config.node_id_path, id.to_string()).await {
            warn!(
                path = %self.config.node_id_path.display(),
                error = %error,
                "could not persist node_id"
            );
        }
    }
}

#[derive(Debug, Clone)]
pub struct AppliedReport {
    pub assignment_id: Uuid,
    pub actual_zone_version: i64,
    pub actual_policy_id: Uuid,
}

#[derive(Debug, Clone)]
pub struct FailedReport {
    pub assignment_id: Uuid,
    pub error_json: serde_json::Value,
}

