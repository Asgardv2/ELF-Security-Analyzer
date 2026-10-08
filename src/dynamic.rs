use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicView {

    pub needed: Vec<String>,
    pub rpaths: Vec<String>,
    pub runpaths: Vec<String>,
    pub soname: Option<String>,

    pub flags: Vec<String>,

    pub flags_1: Vec<String>,
    pub flags_raw: u64,
    pub flags_1_raw: u64,
    pub bind_now: bool,
}

const DF_ORIGIN: u64 = 0x0000_0001;
const DF_SYMBOLIC: u64 = 0x0000_0002;
const DF_TEXTREL: u64 = 0x0000_0004;
const DF_BIND_NOW: u64 = 0x0000_0008;
const DF_STATIC_TLS: u64 = 0x0000_0010;

const DF_1_NOW: u64 = 0x0000_0001;
const DF_1_GLOBAL: u64 = 0x0000_0002;
const DF_1_GROUP: u64 = 0x0000_0004;
const DF_1_NODELETE: u64 = 0x0000_0008;
const DF_1_LOADFLTR: u64 = 0x0000_0010;
const DF_1_INITFIRST: u64 = 0x0000_0020;
const DF_1_NOOPEN: u64 = 0x0000_0040;
const DF_1_ORIGIN: u64 = 0x0000_0080;
const DF_1_DIRECT: u64 = 0x0000_0100;
const DF_1_TRANS: u64 = 0x0000_0200;
const DF_1_INTERPOSE: u64 = 0x0000_0400;
const DF_1_NODEFLIB: u64 = 0x0000_0800;
const DF_1_NODUMP: u64 = 0x0000_1000;
const DF_1_CONFALT: u64 = 0x0000_2000;
const DF_1_ENDFILTEE: u64 = 0x0000_4000;
const DF_1_DISPRELDNE: u64 = 0x0000_8000;
const DF_1_DISPRELPND: u64 = 0x0001_0000;
const DF_1_NODIRECT: u64 = 0x0002_0000;
const DF_1_IGNMULDEF: u64 = 0x0004_0000;
const DF_1_NOKSYMS: u64 = 0x0008_0000;
const DF_1_NOHDR: u64 = 0x0010_0000;
const DF_1_EDITED: u64 = 0x0020_0000;
const DF_1_NORELOC: u64 = 0x0040_0000;
const DF_1_SYMINTPOSE: u64 = 0x0080_0000;
const DF_1_GLOBAUDIT: u64 = 0x0100_0000;
const DF_1_SINGLETON: u64 = 0x0200_0000;
const DF_1_STUB: u64 = 0x0400_0000;
const DF_1_PIE: u64 = 0x0800_0000;

const DF_TABLE: &[(u64, &str)] = &[
    (DF_ORIGIN, "ORIGIN"),
    (DF_SYMBOLIC, "SYMBOLIC"),
    (DF_TEXTREL, "TEXTREL"),
    (DF_BIND_NOW, "BIND_NOW"),
    (DF_STATIC_TLS, "STATIC_TLS"),
];

const DF_1_TABLE: &[(u64, &str)] = &[
    (DF_1_NOW, "NOW"),
    (DF_1_GLOBAL, "GLOBAL"),
    (DF_1_GROUP, "GROUP"),
    (DF_1_NODELETE, "NODELETE"),
    (DF_1_LOADFLTR, "LOADFLTR"),
    (DF_1_INITFIRST, "INITFIRST"),
    (DF_1_NOOPEN, "NOOPEN"),
    (DF_1_ORIGIN, "ORIGIN"),
    (DF_1_DIRECT, "DIRECT"),
    (DF_1_TRANS, "TRANS"),
    (DF_1_INTERPOSE, "INTERPOSE"),
    (DF_1_NODEFLIB, "NODEFLIB"),
    (DF_1_NODUMP, "NODUMP"),
    (DF_1_CONFALT, "CONFALT"),
    (DF_1_ENDFILTEE, "ENDFILTEE"),
    (DF_1_DISPRELDNE, "DISPRELDNE"),
    (DF_1_DISPRELPND, "DISPRELPND"),
    (DF_1_NODIRECT, "NODIRECT"),
    (DF_1_IGNMULDEF, "IGNMULDEF"),
    (DF_1_NOKSYMS, "NOKSYMS"),
    (DF_1_NOHDR, "NOHDR"),
    (DF_1_EDITED, "EDITED"),
    (DF_1_NORELOC, "NORELOC"),
    (DF_1_SYMINTPOSE, "SYMINTPOSE"),
    (DF_1_GLOBAUDIT, "GLOBAUDIT"),
    (DF_1_SINGLETON, "SINGLETON"),
    (DF_1_STUB, "STUB"),
    (DF_1_PIE, "PIE"),
];

fn decode(value: u64, table: &[(u64, &str)]) -> Vec<String> {
    let mut out: Vec<String> = table
        .iter()
        .filter(|(bit, _)| value & bit != 0)
        .map(|(_, name)| name.to_string())
        .collect();

    let known: u64 = table.iter().map(|(bit, _)| bit).fold(0, |a, b| a | b);
    let unknown = value & !known;
    if unknown != 0 {
        out.push(format!("0x{:x}", unknown));
    }
    out
}

pub fn decode_flags(flags: u64) -> Vec<String> {
    decode(flags, DF_TABLE)
}

pub fn decode_flags_1(flags_1: u64) -> Vec<String> {
    decode(flags_1, DF_1_TABLE)
}

pub fn collect(elf: &goblin::elf::Elf) -> DynamicView {
    let (flags_raw, flags_1_raw) = match &elf.dynamic {
        Some(d) => (d.info.flags as u64, d.info.flags_1 as u64),
        None => (0, 0),
    };
    let bind_now = (flags_raw & DF_BIND_NOW) != 0 || (flags_1_raw & DF_1_NOW) != 0;
    DynamicView {
        needed: elf.libraries.iter().map(|s| s.to_string()).collect(),
        rpaths: elf.rpaths.iter().map(|s| s.to_string()).collect(),
        runpaths: elf.runpaths.iter().map(|s| s.to_string()).collect(),
        soname: elf.soname.map(|s| s.to_string()),
        flags: decode_flags(flags_raw),
        flags_1: decode_flags_1(flags_1_raw),
        flags_raw,
        flags_1_raw,
        bind_now,
    }
}
