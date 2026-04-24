use crate::db::types::{node_from_row, Node, NodeLabels};
use crate::error::CpError;
use sqlx::postgres::PgPool;
use sqlx::Row;
use std::collections::BTreeMap;
use uuid::Uuid;

pub async fn get_node(pool: &PgPool, node_id: Uuid) -> Result<(Node, NodeLabels), CpError> {
    let row = sqlx::query("SELECT * FROM nodes WHERE id = $1")
        .bind(node_id)
        .fetch_optional(pool)
        .await?
        .ok_or(CpError::NotFound {
            resource: "node",
            identifier: node_id.to_string(),
        })?;

    let node = node_from_row(&row);
    let labels = load_labels(pool, node_id).await?;
    Ok((node, labels))
}

pub async fn get_node_by_name(
    pool: &PgPool,
    node_name: &str,
) -> Result<(Node, NodeLabels), CpError> {
    let row = sqlx::query("SELECT * FROM nodes WHERE node_name = $1")
        .bind(node_name)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| CpError::NotFound {
            resource: "node",
            identifier: node_name.to_string(),
        })?;

    let node = node_from_row(&row);
    let labels = load_labels(pool, node.id).await?;
    Ok((node, labels))
}

pub async fn list_nodes(
    pool: &PgPool,
    status_filter: Option<&str>,
    limit: i64,
) -> Result<Vec<(Node, NodeLabels)>, CpError> {
    let limit = limit.clamp(1, 500);
    let rows = match status_filter {
        Some(status) => {
            sqlx::query("SELECT * FROM nodes WHERE status = $1 ORDER BY created_at DESC LIMIT $2")
                .bind(status)
                .bind(limit)
                .fetch_all(pool)
                .await?
        }
        None => {
            sqlx::query("SELECT * FROM nodes ORDER BY created_at DESC LIMIT $1")
                .bind(limit)
                .fetch_all(pool)
                .await?
        }
    };

    let nodes: Vec<Node> = rows.into_iter().map(|row| node_from_row(&row)).collect();
    let node_ids: Vec<Uuid> = nodes.iter().map(|node| node.id).collect();
    let mut labels_by_node = load_labels_for_nodes(pool, &node_ids).await?;

    let mut out = Vec::with_capacity(nodes.len());
    for node in nodes {
        let labels = labels_by_node.remove(&node.id).unwrap_or_default();
        out.push((node, labels));
    }

    Ok(out)
}

pub async fn load_labels(pool: &PgPool, node_id: Uuid) -> Result<NodeLabels, CpError> {
    let rows = sqlx::query("SELECT key, value FROM node_labels WHERE node_id = $1")
        .bind(node_id)
        .fetch_all(pool)
        .await?;

    Ok(rows
        .into_iter()
        .map(|row| {
            (
                row.get::<String, _>("key"),
                row.get::<String, _>("value"),
            )
        })
        .collect::<BTreeMap<_, _>>())
}

async fn load_labels_for_nodes(
    pool: &PgPool,
    node_ids: &[Uuid],
) -> Result<BTreeMap<Uuid, NodeLabels>, CpError> {
    let mut labels_by_node = node_ids
        .iter()
        .copied()
        .map(|node_id| (node_id, BTreeMap::new()))
        .collect::<BTreeMap<_, _>>();

    if node_ids.is_empty() {
        return Ok(labels_by_node);
    }

    let rows = sqlx::query(
        "SELECT node_id, key, value FROM node_labels WHERE node_id = ANY($1)",
    )
    .bind(node_ids)
    .fetch_all(pool)
    .await?;

    for row in rows {
        let node_id = row.get::<Uuid, _>("node_id");
        let key = row.get::<String, _>("key");
        let value = row.get::<String, _>("value");

        labels_by_node
            .entry(node_id)
            .or_default()
            .extend(std::iter::once((key, value)));
    }

    Ok(labels_by_node)
}
