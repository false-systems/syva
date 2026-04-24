//! Engine modules — pure computation (no DB I/O).
//!
//! Functions here are pure functions of their inputs. DB writes live in
//! `crate::write`. The engine produces what should happen; the writer
//! applies it inside a transaction.

pub mod assignment;
