//! Fork-name ↔ wire-byte adapters for the Builder API WebSocket extension.
//!
//! ARCH v3.2 §2.3: Electra=1, Fulu=2, Gloas=3. Fork encoding is delegated
//! to ws_wire::framing. Callers receive `WireError` instead of a local error.

use lh_types::ForkName;
use ws_wire::WireError;

// ---------------------------------------------------------------------------
// Fork name <-> u8 (thin adapters delegating to ws_wire)
// ---------------------------------------------------------------------------

pub fn fork_name_to_u8(fork: ForkName) -> Result<u8, WireError> {
    use ForkName::*;
    let name = match fork {
        Electra => "electra",
        Fulu => "fulu",
        Gloas => "gloas",
        _other => return Err(WireError::InvalidForkByte(0)),
    };
    ws_wire::framing::fork_name_to_u8(name)
}

pub fn fork_name_from_u8(v: u8) -> Result<ForkName, WireError> {
    match ws_wire::framing::fork_name_from_u8(v)? {
        "electra" => Ok(ForkName::Electra),
        "fulu" => Ok(ForkName::Fulu),
        "gloas" => Ok(ForkName::Gloas),
        _ => unreachable!("ws_wire only returns known fork names"),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use ws_wire::WireError;

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
                matches!(fork_name_to_u8(fork), Err(WireError::InvalidForkByte(_))),
                "pre-Electra fork {fork:?} must be rejected"
            );
        }
    }

    #[test]
    fn fork_name_from_u8_zero_rejected() {
        assert!(matches!(fork_name_from_u8(0), Err(WireError::InvalidForkByte(0))));
    }

    #[test]
    fn fork_name_from_u8_unknown_rejected() {
        for byte in [4u8, 5, 99, 255] {
            assert!(
                matches!(fork_name_from_u8(byte), Err(WireError::InvalidForkByte(_))),
                "byte {byte} must be rejected"
            );
        }
    }
}
