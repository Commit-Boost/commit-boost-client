//! Output that a closed pipe cannot abort: `println!` panics on a write error,
//! which would stop a run between two keys

use std::{fmt::Display, io::Write};

pub fn out(line: impl Display) {
    let _ = writeln!(std::io::stdout().lock(), "{line}");
}

pub fn err(line: impl Display) {
    let _ = writeln!(std::io::stderr().lock(), "{line}");
}
