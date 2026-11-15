//! zcode-core: protocol core ported from the Go zcode-proxy.
//!
//! Port contract: byte-faithful semantics with the Go test tables as the
//! acceptance gate. Each module's doc comment names its Go origin file and
//! the invariants that must not drift.

pub mod account;
pub mod aggregate;
pub mod autoreset;
pub mod bizcode;
pub mod classify;
pub mod cooldown;
pub mod egress;
pub mod estimate;
pub mod gateway;
pub mod models;
pub mod selection;
pub mod sse;

pub use account::{selectable, AccountStatus};
pub use aggregate::{aggregate_anthropic_stream, StreamUsage};
pub use autoreset::*;
pub use bizcode::*;
pub use classify::*;
pub use cooldown::*;
pub use egress::*;
pub use estimate::*;
pub use gateway::*;
pub use models::{canonical_model_name, normalize_model_name};
pub use selection::*;
pub use sse::{SseEvent, SseParser};
