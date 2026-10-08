use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolInfo {
    pub name: String,
    pub value: u64,
    pub size: u64,
    pub kind: String,
    pub bind: String,
    pub section: String,
    pub is_import: bool,
    pub is_function: bool,
}

fn bind_name(b: u8) -> &'static str {
    match b {
        0 => "LOCAL",
        1 => "GLOBAL",
        2 => "WEAK",
        10 => "LOOS",
        12 => "HIOS",
        13 => "LOPROC",
        15 => "HIPROC",
        _ => "UNKNOWN",
    }
}

fn type_name(t: u8) -> &'static str {
    match t {
        0 => "NOTYPE",
        1 => "OBJECT",
        2 => "FUNC",
        3 => "SECTION",
        4 => "FILE",
        5 => "COMMON",
        6 => "TLS",
        7 => "RELC",
        8 => "SRELC",
        10 => "LOOS",
        12 => "HIOS",
        13 => "LOPROC",
        15 => "HIPROC",
        _ => "UNKNOWN",
    }
}

fn shndx_name(shndx: usize) -> String {
    match shndx as u16 {
        0 => "UND".into(),
        0xff00 => "LORESERVE".into(),
        0xfff1 => "ABS".into(),
        0xfff2 => "COMMON".into(),
        _ => format!("{}", shndx),
    }
}

fn push_sym(
    out: &mut Vec<SymbolInfo>,
    st_name: usize,
    st_value: u64,
    st_size: u64,
    st_info: u8,
    st_shndx: usize,
    name: Option<&str>,
) {
    let bind = st_info >> 4;
    let typ = st_info & 0xf;
    let nm = name.unwrap_or("<bad-str>").to_string();
    if nm.is_empty() {
        return;
    }
    let _ = st_name;
    out.push(SymbolInfo {
        name: nm,
        value: st_value,
        size: st_size,
        kind: type_name(typ).to_string(),
        bind: bind_name(bind).to_string(),
        section: shndx_name(st_shndx),
        is_import: st_shndx == 0 && st_value == 0,
        is_function: typ == 2,
    });
}

pub fn collect_symbols(elf: &goblin::elf::Elf) -> Vec<SymbolInfo> {
    let mut out = Vec::new();
    for sym in elf.syms.iter() {
        let name = elf.strtab.get_at(sym.st_name);
        push_sym(
            &mut out,
            sym.st_name,
            sym.st_value,
            sym.st_size,
            sym.st_info,
            sym.st_shndx,
            name,
        );
    }
    for sym in elf.dynsyms.iter() {
        let name = elf.dynstrtab.get_at(sym.st_name);
        push_sym(
            &mut out,
            sym.st_name,
            sym.st_value,
            sym.st_size,
            sym.st_info,
            sym.st_shndx,
            name,
        );
    }
    out
}

pub fn collect_imports(elf: &goblin::elf::Elf) -> Vec<SymbolInfo> {
    let mut out = Vec::new();
    for sym in elf.dynsyms.iter() {
        if sym.st_shndx != 0 {
            continue;
        }
        let name = elf.dynstrtab.get_at(sym.st_name);

        if name.map(|n| n.is_empty()).unwrap_or(true) {
            continue;
        }
        push_sym(
            &mut out,
            sym.st_name,
            sym.st_value,
            sym.st_size,
            sym.st_info,
            sym.st_shndx,
            name,
        );
    }
    out
}

pub fn collect_exports(elf: &goblin::elf::Elf) -> Vec<SymbolInfo> {
    let mut out = Vec::new();
    for sym in elf.dynsyms.iter() {
        if sym.st_shndx == 0 {
            continue;
        }
        let name = elf.dynstrtab.get_at(sym.st_name);
        if name.map(|n| n.is_empty()).unwrap_or(true) {
            continue;
        }
        push_sym(
            &mut out,
            sym.st_name,
            sym.st_value,
            sym.st_size,
            sym.st_info,
            sym.st_shndx,
            name,
        );
    }
    out
}

pub fn collect_libraries(elf: &goblin::elf::Elf) -> Vec<String> {
    elf.libraries.iter().map(|s| s.to_string()).collect()
}
