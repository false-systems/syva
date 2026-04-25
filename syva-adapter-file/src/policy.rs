use crate::types::ZonePolicy;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FilePolicy {
    #[serde(default)]
    pub display_name: Option<String>,

    #[serde(default)]
    pub selector: Option<JsonValue>,

    #[serde(flatten)]
    pub policy: ZonePolicy,
}

pub fn load_policies_from_dir(dir: &Path) -> Result<HashMap<String, FilePolicy>> {
    let mut policies = HashMap::new();

    if !dir.exists() {
        tracing::warn!(
            dir = %dir.display(),
            "policy directory does not exist; no zones will be reconciled"
        );
        return Ok(policies);
    }

    let entries = std::fs::read_dir(dir)
        .with_context(|| format!("read_dir {}", dir.display()))?;

    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("toml") {
            continue;
        }

        let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
            continue;
        };
        if stem.is_empty() {
            continue;
        }

        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("read {}", path.display()))?;
        let policy: FilePolicy = toml::from_str(&text)
            .with_context(|| format!("parse {}", path.display()))?;
        policy.policy.validate(stem)?;
        policies.insert(stem.to_string(), policy);
    }

    Ok(policies)
}
