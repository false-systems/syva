use crate::policy::FilePolicy;
use anyhow::Result;
use syva_cp_client::{CreateZoneArgs, UpdateZoneArgs, ZoneSnapshot};
use uuid::Uuid;

pub fn policy_to_create_args(
    team_id: Uuid,
    name: &str,
    policy: &FilePolicy,
) -> Result<CreateZoneArgs> {
    Ok(CreateZoneArgs {
        team_id,
        name: name.to_string(),
        display_name: policy.display_name.clone(),
        policy_json: serde_json::to_value(&policy.policy)?,
        summary_json: None,
        selector_json: policy.selector.clone(),
        metadata_json: None,
    })
}

pub fn policy_to_update_args(
    snapshot: &ZoneSnapshot,
    policy: &FilePolicy,
) -> Result<Option<UpdateZoneArgs>> {
    let desired_policy_json = serde_json::to_value(&policy.policy)?;
    let desired_selector_json = policy.selector.clone();

    let policy_matches = snapshot
        .current_policy_json
        .as_ref()
        .map(|current| current == &desired_policy_json)
        .unwrap_or(false);
    let selector_matches = snapshot.selector_json == desired_selector_json;

    // ZoneService::UpdateZone does not currently accept display_name updates.
    // Ignore display_name drift here so the adapter does not generate a
    // perpetual no-op update loop it can never resolve.
    if policy_matches && selector_matches {
        return Ok(None);
    }

    Ok(Some(UpdateZoneArgs {
        zone_id: snapshot.zone_id,
        if_version: snapshot.version,
        policy_json: Some(desired_policy_json),
        selector_json: desired_selector_json,
        metadata_json: None,
    }))
}
