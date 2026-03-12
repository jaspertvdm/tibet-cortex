//! TIBET Cortex Airlock — Zero plaintext lifetime processing
//!
//! The Airlock ensures data is NEVER plaintext outside a controlled scope:
//! - Memory is mlock'd (pinned, never swapped to disk)
//! - All buffers are zeroized on drop
//! - Processing happens within a closure — plaintext cannot escape
//! - Audit tokens are generated for every airlock session
//!
//! ```text
//! ┌─── AIRLOCK ────────────────────────┐
//! │  1. Data IN (encrypted envelope)   │
//! │  2. Decrypt WITHIN airlock         │
//! │  3. Process (closure scope)        │
//! │  4. Result OUT (re-encrypted)      │
//! │  5. WIPE — zero all plaintext      │
//! └────────────────────────────────────┘
//! ```

mod secure_mem;
mod session;

pub use session::{Airlock, AirlockSession, AirlockConfig};
pub use secure_mem::LockedBuffer;
