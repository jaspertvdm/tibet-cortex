//! TIBET Cortex Core — Types, tokens, and crypto primitives
//!
//! The foundation of TIBET Cortex: zero-trust AI knowledge processing.

pub mod envelope;
pub mod tibet;
pub mod crypto;
pub mod error;

pub use envelope::{Envelope, EnvelopeBlock};
pub use tibet::{TibetToken, Provenance};
pub use crypto::{KeyPair, ContentHash};
pub use error::CortexError;
