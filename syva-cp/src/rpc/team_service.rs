//! TeamService — gRPC surface backed by `TransactionalWriter` + read helpers.
//!
//! Handlers are thin: translate the proto request to writer/read inputs,
//! call through, translate the domain result back to proto. No SQL here.

use crate::db::types::{Actor, Team};
use crate::read;
use crate::write::{team::CreateTeamInput, TransactionalWriter};
use sqlx::postgres::PgPool;
use syva_proto::syva_control::v1::team_service_server::TeamService;
use syva_proto::syva_control::v1::{
    get_team_request::Identifier, CreateTeamRequest, CreateTeamResponse, GetTeamRequest,
    GetTeamResponse, ListTeamsRequest, ListTeamsResponse, Team as TeamProto,
};
use tonic::{Request, Response, Status};
use uuid::Uuid;

pub struct TeamServiceImpl {
    pub pool: PgPool,
}

#[tonic::async_trait]
impl TeamService for TeamServiceImpl {
    async fn create_team(
        &self,
        request: Request<CreateTeamRequest>,
    ) -> Result<Response<CreateTeamResponse>, Status> {
        record_request("CreateTeam");

        let req = request.into_inner();

        // Auth wiring lands in a later session. For now every call is a
        // dev actor so events/audit still populate the required columns.
        let actor = dev_actor();

        let writer = TransactionalWriter::new(&self.pool);
        let team = writer
            .create_team(
                CreateTeamInput {
                    name: req.name,
                    display_name: non_empty(req.display_name),
                },
                &actor,
            )
            .await?;

        Ok(Response::new(CreateTeamResponse {
            team: Some(to_proto(team)),
        }))
    }

    async fn get_team(
        &self,
        request: Request<GetTeamRequest>,
    ) -> Result<Response<GetTeamResponse>, Status> {
        record_request("GetTeam");

        let req = request.into_inner();
        let team = match req.identifier {
            Some(Identifier::Id(id)) => {
                let uuid = Uuid::parse_str(&id)
                    .map_err(|_| Status::invalid_argument("invalid team id"))?;
                read::team::get_team(&self.pool, uuid).await?
            }
            Some(Identifier::Name(name)) => {
                read::team::get_team_by_name(&self.pool, &name).await?
            }
            None => return Err(Status::invalid_argument("identifier required")),
        };

        Ok(Response::new(GetTeamResponse {
            team: Some(to_proto(team)),
        }))
    }

    async fn list_teams(
        &self,
        request: Request<ListTeamsRequest>,
    ) -> Result<Response<ListTeamsResponse>, Status> {
        record_request("ListTeams");

        let req = request.into_inner();
        // Default to 50 when caller passes 0 / unset; the read helper
        // clamps to [1, 500] anyway.
        let limit = if req.limit <= 0 { 50 } else { req.limit };
        let teams = read::team::list_teams(&self.pool, limit).await?;
        Ok(Response::new(ListTeamsResponse {
            teams: teams.into_iter().map(to_proto).collect(),
        }))
    }
}

fn record_request(method: &'static str) {
    ::metrics::counter!(
        "syva_cp_grpc_requests_total",
        "service" => "TeamService",
        "method" => method
    )
    .increment(1);
}

fn dev_actor() -> Actor {
    Actor {
        actor_type: "user".into(),
        actor_id: "dev".into(),
        team_id: None,
        subject_type: "user".into(),
        subject_id: "dev".into(),
    }
}

fn non_empty(s: String) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn to_proto(team: Team) -> TeamProto {
    TeamProto {
        id: team.id.to_string(),
        name: team.name,
        display_name: team.display_name.unwrap_or_default(),
        status: team.status,
        created_at_unix_nanos: team
            .created_at
            .timestamp_nanos_opt()
            .unwrap_or_default(),
        updated_at_unix_nanos: team
            .updated_at
            .timestamp_nanos_opt()
            .unwrap_or_default(),
        version: team.version,
        caused_by_event_id: team
            .caused_by_event_id
            .map(|id| id.to_string())
            .unwrap_or_default(),
    }
}
