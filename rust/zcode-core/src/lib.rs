//! zcode-core: protocol core ported from the Go zcode-proxy.
//!
//! Port contract: byte-faithful semantics with the Go test tables as the
//! acceptance gate. Each module's doc comment names its Go origin file and
//! the invariants that must not drift.

pub mod aggregate;
pub mod bizcode;
pub mod estimate;
pub mod models;
pub mod sse;

pub use aggregate::{aggregate_anthropic_stream, StreamUsage};
pub use bizcode::*;
pub use estimate::*;
pub use models::{canonical_model_name, normalize_model_name};
pub use sse::{SseEvent, SseParser};
