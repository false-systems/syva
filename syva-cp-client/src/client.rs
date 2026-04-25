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
use syva_proto::syva_control::v1::zone_service_client::ZoneServiceClient;
use syva_proto::syva_control::v1::{
    get_zone_request::Identifier as GetZoneIdentifier, AppliedAssignment, CreateZoneRequest,
    DeleteZoneRequest, FailedAssignment, GetZoneRequest, HeartbeatRequest, ListZonesRequest,
    NodeAssignmentUpdate, RegisterNodeRequest, ReportAssignmentStateRequest,
    SubscribeAssignmentsRequest, UpdateZoneRequest,
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

pub struct CreateZoneArgs {
    pub team_id: Uuid,
    pub name: String,
    pub display_name: Option<String>,
    pub policy_json: serde_json::Value,
    pub summary_json: Option<serde_json::Value>,
    pub selector_json: Option<serde_json::Value>,
    pub metadata_json: Option<serde_json::Value>,
}

pub struct CreatedZone {
    pub zone_id: Uuid,
    pub policy_id: Uuid,
    pub version: i64,
}

pub struct UpdateZoneArgs {
    pub zone_id: Uuid,
    pub if_version: i64,
    pub policy_json: Option<serde_json::Value>,
    pub selector_json: Option<serde_json::Value>,
    pub metadata_json: Option<serde_json::Value>,
}

pub struct UpdatedZone {
    pub zone_id: Uuid,
    pub version: i64,
    pub new_policy_id: Option<Uuid>,
    pub new_policy_version: Option<i64>,
}

pub struct DeleteZoneArgs {
    pub zone_id: Uuid,
    pub if_version: i64,
    pub drain: bool,
}

pub struct ZoneSnapshot {
    pub zone_id: Uuid,
    pub team_id: Uuid,
    pub name: String,
    pub display_name: Option<String>,
    pub status: String,
    pub version: i64,
    pub current_policy_id: Option<Uuid>,
    pub current_policy_json: Option<serde_json::Value>,
    pub selector_json: Option<serde_json::Value>,
    pub metadata_json: Option<serde_json::Value>,
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

    pub async fn create_zone(&self, args: CreateZoneArgs) -> Result<CreatedZone, CpClientError> {
        let mut client = ZoneServiceClient::new(self.channel.clone());
        let response = client
            .create_zone(CreateZoneRequest {
                team_id: args.team_id.to_string(),
                name: args.name,
                display_name: args.display_name.unwrap_or_default(),
                policy_json: args.policy_json.to_string(),
                summary_json: args
                    .summary_json
                    .map(|value| value.to_string())
                    .unwrap_or_default(),
                selector_json: args
                    .selector_json
                    .map(|value| value.to_string())
                    .unwrap_or_default(),
                metadata_json: args
                    .metadata_json
                    .map(|value| value.to_string())
                    .unwrap_or_default(),
            })
            .await?
            .into_inner();

        let zone = response
            .zone
            .ok_or_else(|| CpClientError::Internal("CreateZoneResponse missing zone".into()))?;
        let policy = response
            .policy
            .ok_or_else(|| CpClientError::Internal("CreateZoneResponse missing policy".into()))?;

        Ok(CreatedZone {
            zone_id: parse_uuid(&zone.id, "zone.id")?,
            policy_id: parse_uuid(&policy.id, "policy.id")?,
            version: zone.version,
        })
    }

    pub async fn update_zone(&self, args: UpdateZoneArgs) -> Result<UpdatedZone, CpClientError> {
        let mut client = ZoneServiceClient::new(self.channel.clone());
        let response = client
            .update_zone(UpdateZoneRequest {
                zone_id: args.zone_id.to_string(),
                if_version: args.if_version,
                policy_json: args
                    .policy_json
                    .map(|value| value.to_string())
                    .unwrap_or_default(),
                selector_json: args
                    .selector_json
                    .map(|value| value.to_string())
                    .unwrap_or_default(),
                metadata_json: args
                    .metadata_json
                    .map(|value| value.to_string())
                    .unwrap_or_default(),
            })
            .await?
            .into_inner();

        let zone = response
            .zone
            .ok_or_else(|| CpClientError::Internal("UpdateZoneResponse missing zone".into()))?;
        let new_policy = response.new_policy;

        Ok(UpdatedZone {
            zone_id: parse_uuid(&zone.id, "zone.id")?,
            version: zone.version,
            new_policy_id: new_policy
                .as_ref()
                .map(|policy| parse_uuid(&policy.id, "policy.id"))
                .transpose()?,
            new_policy_version: new_policy.map(|policy| policy.version),
        })
    }

    pub async fn delete_zone(&self, args: DeleteZoneArgs) -> Result<(), CpClientError> {
        let mut client = ZoneServiceClient::new(self.channel.clone());
        client
            .delete_zone(DeleteZoneRequest {
                zone_id: args.zone_id.to_string(),
                if_version: args.if_version,
                drain: args.drain,
            })
            .await?;
        Ok(())
    }

    pub async fn get_zone_by_name(
        &self,
        team_id: Uuid,
        name: &str,
    ) -> Result<Option<ZoneSnapshot>, CpClientError> {
        let mut client = ZoneServiceClient::new(self.channel.clone());
        let response = match client
            .get_zone(GetZoneRequest {
                identifier: Some(GetZoneIdentifier::NameRef(
                    syva_proto::syva_control::v1::ZoneNameRef {
                        team_id: team_id.to_string(),
                        name: name.to_string(),
                    },
                )),
            })
            .await
        {
            Ok(response) => response.into_inner(),
            Err(error) if error.code() == tonic::Code::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };

        let zone = match response.zone {
            Some(zone) => zone,
            None => return Ok(None),
        };

        Ok(Some(ZoneSnapshot {
            zone_id: parse_uuid(&zone.id, "zone.id")?,
            team_id: parse_uuid(&zone.team_id, "zone.team_id")?,
            name: zone.name,
            display_name: if zone.display_name.is_empty() {
                None
            } else {
                Some(zone.display_name)
            },
            status: zone.status,
            version: zone.version,
            current_policy_id: if zone.current_policy_id.is_empty() {
                None
            } else {
                Some(parse_uuid(
                    &zone.current_policy_id,
                    "zone.current_policy_id",
                )?)
            },
            current_policy_json: response
                .current_policy
                .as_ref()
                .filter(|policy| !policy.policy_json.is_empty())
                .map(|policy| serde_json::from_str(&policy.policy_json))
                .transpose()?,
            selector_json: parse_optional_json(&zone.selector_json)?,
            metadata_json: parse_optional_json(&zone.metadata_json)?,
        }))
    }

    pub async fn list_zones(
        &self,
        team_id: Uuid,
        status_filter: Option<&str>,
        limit: i64,
    ) -> Result<Vec<ZoneSnapshot>, CpClientError> {
        let mut client = ZoneServiceClient::new(self.channel.clone());
        let response = client
            .list_zones(ListZonesRequest {
                team_id: team_id.to_string(),
                status: status_filter.unwrap_or_default().to_string(),
                limit,
            })
            .await?
            .into_inner();

        response
            .zones
            .into_iter()
            .map(|zone| {
                Ok(ZoneSnapshot {
                    zone_id: parse_uuid(&zone.id, "zone.id")?,
                    team_id: parse_uuid(&zone.team_id, "zone.team_id")?,
                    name: zone.name,
                    display_name: if zone.display_name.is_empty() {
                        None
                    } else {
                        Some(zone.display_name)
                    },
                    status: zone.status,
                    version: zone.version,
                    current_policy_id: if zone.current_policy_id.is_empty() {
                        None
                    } else {
                        Some(parse_uuid(
                            &zone.current_policy_id,
                            "zone.current_policy_id",
                        )?)
                    },
                    current_policy_json: None,
                    selector_json: parse_optional_json(&zone.selector_json)?,
                    metadata_json: parse_optional_json(&zone.metadata_json)?,
                })
            })
            .collect()
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

fn parse_uuid(value: &str, field: &str) -> Result<Uuid, CpClientError> {
    Uuid::parse_str(value).map_err(|error| {
        CpClientError::Internal(format!("could not parse {field} as UUID: {error}"))
    })
}

fn parse_optional_json(value: &str) -> Result<Option<serde_json::Value>, CpClientError> {
    if value.is_empty() {
        return Ok(None);
    }

    serde_json::from_str(value).map(Some).map_err(Into::into)
}
