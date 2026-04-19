//! TransactionalWriter — the single entry point for all mutating operations.
//!
//! Every mutating operation in syva-cp follows the rules in
//! `docs/adr/0003-transactional-write-discipline.md`:
//!
//! 1. Single transaction per operation.
//! 2. Canonical write order: event → resource → history → audit.
//! 3. No external I/O inside the transaction — gather all external data
//!    first, validate it, then BEGIN.
//! 4. Optimistic locking on versioned resources via a `version` column
//!    in the WHERE clause of UPDATE.
//! 5. Advisory locks for zone-scoped serialization (lands with zones).
//! 6. All mutations go through this module. No `sqlx::query!(... INSERT/
//!    UPDATE/DELETE ...)` anywhere else in the crate — enforced by the
//!    `check-write-discipline` xtask in CI.
//! 7. Every event carries a causal predecessor via `caused_by_event_id`.
//!    The one exception is origin events (a CreateTeam has no parent).
//! 8. Audit is structural: a row lands for every accepted write, every
//!    rejected write (with `result = 'denied' | 'failed'`), and every
//!    read of sensitive resources.
//! 9. Append-only enforcement at the database layer — see the triggers
//!    migration.
//! 10. Transaction duration is a monitored SLO via
//!     `crate::metrics::record_transaction_duration`.
//!
//! **Do not add mutating code outside this module.** The
//! `check-write-discipline` xtask and the CI job that runs it exist to
//! catch regressions.

use sqlx::postgres::PgPool;

pub mod team;

pub struct TransactionalWriter<'a> {
    pub(crate) pool: &'a PgPool,
}

impl<'a> TransactionalWriter<'a> {
    pub fn new(pool: &'a PgPool) -> Self {
        Self { pool }
    }
}
