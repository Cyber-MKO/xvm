//! Gap records: calls the personality does not implement (CLAUDE.md rule 4).
//!
//! Every gap names the module that asked for it. The runtime adds the agent
//! identity when it writes the log.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GapKind {
    /// A static import the resolver could not bind.
    Import,
    /// A `GetProcAddress` lookup that found nothing.
    ProcAddress,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Gap {
    pub module: String,
    pub kind: GapKind,
    pub dll: String,
    pub symbol: String,
}

impl fmt::Display for Gap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self.kind {
            GapKind::Import => "import",
            GapKind::ProcAddress => "GetProcAddress",
        };
        write!(
            f,
            "gap {kind} {}!{} from {}",
            self.dll, self.symbol, self.module
        )
    }
}
