use serde::{Deserialize, Serialize};

use crate::elf::{PF_X, PT_GNU_RELRO, PT_GNU_STACK};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RelroLevel {
    None,
    Partial,
    Full,
}

impl RelroLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            RelroLevel::None => "None",
            RelroLevel::Partial => "Partial",
            RelroLevel::Full => "Full",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityReport {
    pub pie: bool,
    pub pie_detail: String,
    pub nx: bool,
    pub has_gnu_stack: bool,
    pub relro: RelroLevel,
    pub has_gnu_relro: bool,
    pub bind_now: bool,
    pub canary: bool,
    pub fortify: bool,
    pub fortified_count: usize,
    pub stripped: bool,
}

impl SecurityReport {

    pub fn rows(&self) -> Vec<(String, String, bool)> {
        self.detailed_rows()
            .into_iter()
            .map(|r| (r.label, r.mark, r.passed))
            .collect()
    }

    pub fn detailed_rows(&self) -> Vec<CheckRow> {
        let relro_mark = match self.relro {
            RelroLevel::Full => "✓",
            RelroLevel::Partial => "◐",
            RelroLevel::None => "✗",
        };
        vec![
            CheckRow {
                label: "PIE".into(),
                mark: if self.pie { "✓".into() } else { "✗".into() },
                reason: if self.pie {
                    "Enabled".into()
                } else {
                    "Disabled".into()
                },
                passed: self.pie,
            },
            CheckRow {
                label: "NX".into(),
                mark: if self.nx { "✓".into() } else { "✗".into() },
                reason: if self.nx {
                    "Enabled".into()
                } else if self.has_gnu_stack {
                    "Executable stack".into()
                } else {
                    "No GNU_STACK".into()
                },
                passed: self.nx,
            },
            CheckRow {
                label: "RELRO".into(),
                mark: relro_mark.into(),
                reason: match self.relro {
                    RelroLevel::Full => "Full".into(),
                    RelroLevel::Partial => "Partial (no BIND_NOW)".into(),
                    RelroLevel::None => "None".into(),
                },
                passed: self.relro != RelroLevel::None,
            },
            CheckRow {
                label: "Canary".into(),
                mark: if self.canary { "✓".into() } else { "✗".into() },
                reason: if self.canary {
                    "Detected".into()
                } else {
                    "Not detected".into()
                },
                passed: self.canary,
            },
            CheckRow {
                label: "Fortify".into(),
                mark: if self.fortify { "✓".into() } else { "✗".into() },
                reason: if self.fortify {
                    format!("{} function(s)", self.fortified_count)
                } else {
                    "Not detected".into()
                },
                passed: self.fortify,
            },
            CheckRow {
                label: "Stripped".into(),
                mark: if self.stripped { "✓".into() } else { "✗".into() },
                reason: if self.stripped {
                    "Symbols stripped".into()
                } else {
                    "Symbol table present".into()
                },

                passed: self.stripped,
            },
        ]
    }

    pub fn score(&self) -> (usize, usize) {
        let passed = self.detailed_rows().iter().filter(|r| r.passed).count();
        (passed, 6)
    }
}

#[derive(Debug, Clone)]
pub struct CheckRow {
    pub label: String,
    pub mark: String,
    pub reason: String,
    pub passed: bool,
}

const DF_BIND_NOW: u64 = 0x0000_0008;
const DF_1_NOW: u64 = 0x0000_0001;

pub fn analyze(
    elf: &goblin::elf::Elf,
    all_symbols: &[crate::symbols::SymbolInfo],
    section_names: &[String],
) -> SecurityReport {

    let is_dyn = elf.header.e_type == 3;
    let pie_detail = match elf.header.e_type {
        2 => "EXEC (no PIE)".into(),
        3 => "DYN (PIE)".into(),
        1 => "REL".into(),
        _ => format!("type={}", elf.header.e_type),
    };

    let mut has_gnu_stack = false;
    let mut nx = false;
    for ph in &elf.program_headers {
        if ph.p_type == PT_GNU_STACK {
            has_gnu_stack = true;
            nx = (ph.p_flags & PF_X) == 0;
            break;
        }
    }

    let has_gnu_relro = elf.program_headers.iter().any(|ph| ph.p_type == PT_GNU_RELRO);
    let bind_now = has_bind_now(elf);
    let relro = if !has_gnu_relro {
        RelroLevel::None
    } else if bind_now {
        RelroLevel::Full
    } else {
        RelroLevel::Partial
    };

    let canary = all_symbols
        .iter()
        .any(|s| s.name.contains("__stack_chk_fail"));

    let fortified_count = all_symbols
        .iter()
        .filter(|s| {
            s.name.ends_with("_chk")
                || s.name.contains("_chk@")
                || s.name.contains("__memcpy_chk")
                || s.name.contains("__strcpy_chk")
        })
        .count();
    let fortify = fortified_count > 0;

    let has_symtab_section = section_names.iter().any(|n| n == ".symtab");
    let stripped = !has_symtab_section && elf.syms.len() == 0;

    SecurityReport {
        pie: is_dyn,
        pie_detail,
        nx,
        has_gnu_stack,
        relro,
        has_gnu_relro,
        bind_now,
        canary,
        fortify,
        fortified_count,
        stripped,
    }
}

fn has_bind_now(elf: &goblin::elf::Elf) -> bool {
    if let Some(dynamic) = &elf.dynamic {
        let flags = dynamic.info.flags as u64;
        let flags_1 = dynamic.info.flags_1 as u64;
        if (flags & DF_BIND_NOW) != 0 {
            return true;
        }
        if (flags_1 & DF_1_NOW) != 0 {
            return true;
        }
    }
    false
}
