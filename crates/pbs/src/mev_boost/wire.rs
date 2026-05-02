//! Fork-name ↔ wire-byte mapping for the Builder API WebSocket extension.
//!
//! ARCH v3.2 §2.3: Electra=1, Fulu=2, Gloas=3. Pre-Electra forks and byte 0
//! are invalid on the wire. This mapping MUST match Helix's
//! `helix/crates/relay/src/api/proposer/websocket/wire.rs` exactly.

use lh_types::ForkName;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum WireForkError {
    #[error("pre-Electra fork not supported on the WebSocket wire: {0:?}")]
    UnsupportedFork(ForkName),
    #[error("unknown wire fork discriminant: {0}")]
    UnknownDiscriminant(u8),
}

// ---------------------------------------------------------------------------
// Fork name <-> u8
// ---------------------------------------------------------------------------

pub fn fork_name_to_u8(fork: ForkName) -> Result<u8, WireForkError> {
    match fork {
        ForkName::Electra => Ok(1),
        ForkName::Fulu => Ok(2),
        ForkName::Gloas => Ok(3),
        other => Err(WireForkError::UnsupportedFork(other)),
    }
}

pub fn fork_name_from_u8(v: u8) -> Result<ForkName, WireForkError> {
    match v {
        1 => Ok(ForkName::Electra),
        2 => Ok(ForkName::Fulu),
        3 => Ok(ForkName::Gloas),
        other => Err(WireForkError::UnknownDiscriminant(other)),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fork_name_roundtrip_supported() {
        for fork in [ForkName::Electra, ForkName::Fulu, ForkName::Gloas] {
            let byte = fork_name_to_u8(fork).expect("supported fork must encode");
            let back = fork_name_from_u8(byte).expect("valid byte must decode");
            assert_eq!(fork, back);
        }
    }

    #[test]
    fn fork_name_to_u8_electra_is_one() {
        assert_eq!(fork_name_to_u8(ForkName::Electra).unwrap(), 1);
        assert_eq!(fork_name_to_u8(ForkName::Fulu).unwrap(), 2);
        assert_eq!(fork_name_to_u8(ForkName::Gloas).unwrap(), 3);
    }

    #[test]
    fn fork_name_pre_electra_rejected() {
        for fork in [
            ForkName::Base,
            ForkName::Altair,
            ForkName::Bellatrix,
            ForkName::Capella,
            ForkName::Deneb,
        ] {
            assert!(
                matches!(fork_name_to_u8(fork), Err(WireForkError::UnsupportedFork(_))),
                "pre-Electra fork {fork:?} must be rejected"
            );
        }
    }

    #[test]
    fn fork_name_from_u8_zero_rejected() {
        assert!(matches!(fork_name_from_u8(0), Err(WireForkError::UnknownDiscriminant(0))));
    }

    #[test]
    fn fork_name_from_u8_unknown_rejected() {
        for byte in [4u8, 5, 99, 255] {
            assert!(
                matches!(fork_name_from_u8(byte), Err(WireForkError::UnknownDiscriminant(_))),
                "byte {byte} must be rejected"
            );
        }
    }
}
