//! Conversion layer between lh_types native types and ws-wire wire types.
//! See ARCH.md §12 for the full conversion specification.
//!
//! Full field-by-field conversion is TBD — currently provides
//! fork-name mapping and stub conversions that compile.

use lh_types::ForkName;
use crate::mev_boost::ws_messages::*;
use ssz_types::VariableList;

// ---------------------------------------------------------------------------
// Fork name <-> u8
// ---------------------------------------------------------------------------

pub fn fork_name_to_u8(fork: ForkName) -> u8 {
    match fork {
        ForkName::Deneb => 0,
        ForkName::Electra => 1,
        ForkName::Fulu => 2,
        _ => 0, // Base/Altair/Bellatrix/Capella/Gloas → 0
    }
}

pub fn fork_name_from_u8(v: u8) -> eyre::Result<ForkName> {
    match v {
        0 => Ok(ForkName::Deneb),
        1 => Ok(ForkName::Electra),
        2 => Ok(ForkName::Fulu),
        _ => Err(eyre::eyre!("unknown wire fork discriminant: {v}")),
    }
}

// ---------------------------------------------------------------------------
// Validator registration conversion (stubs — full impl TBD)
// ---------------------------------------------------------------------------

/// Build a wire ValidatorRegistration batch from raw registrations.
/// Full conversion from lh_types::SignedValidatorRegistrationData is TBD.
pub fn build_registration_batch(
    regs: Vec<WireSignedValidatorRegistration>,
) -> ValidatorRegistration {
    ValidatorRegistration { registrations: VariableList::from(regs) }
}

// ---------------------------------------------------------------------------
// Bid conversion (stubs — full SSZ roundtrip TBD)
// ---------------------------------------------------------------------------

/// Build a wire BidPush from slot, parent_hash, fork, and pre-encoded SSZ bytes.
pub fn build_bid_push(
    slot: u64,
    parent_hash: [u8; 32],
    fork: ForkName,
    signed_bid_ssz: Vec<u8>,
) -> BidPush {
    BidPush { slot, parent_hash, fork_name: fork_name_to_u8(fork), signed_bid_ssz: VariableList::from(signed_bid_ssz) }
}

// ---------------------------------------------------------------------------
// Submit block conversion
// ---------------------------------------------------------------------------

/// Build a wire SubmitBlockRequest.
pub fn build_submit_block_request(fork: ForkName, body_ssz: Vec<u8>) -> SubmitBlockRequest {
    SubmitBlockRequest { fork_name: fork_name_to_u8(fork), body_ssz: VariableList::from(body_ssz) }
}

/// Build a wire SubmitBlockAck from a status byte.
pub fn build_submit_block_ack(status: u8) -> SubmitBlockAck {
    SubmitBlockAck { status }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fork_name_roundtrip() {
        assert_eq!(fork_name_from_u8(fork_name_to_u8(ForkName::Electra)).unwrap(), ForkName::Electra);
        assert_eq!(fork_name_from_u8(fork_name_to_u8(ForkName::Fulu)).unwrap(), ForkName::Fulu);
        assert_eq!(fork_name_from_u8(fork_name_to_u8(ForkName::Deneb)).unwrap(), ForkName::Deneb);
    }

    #[test]
    fn fork_name_unknown_rejected() {
        assert!(fork_name_from_u8(255).is_err());
    }

    #[test]
    fn non_electra_defaults_to_zero() {
        assert_eq!(fork_name_to_u8(ForkName::Base), 0);
    }
}
