use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionInfo {
    pub index: usize,
    pub name: String,
    pub type_name: String,
    pub type_raw: u32,
    pub flags: String,
    pub flags_raw: u64,
    pub addr: u64,
    pub offset: u64,
    pub size: u64,
}

pub fn collect(elf: &goblin::elf::Elf) -> Vec<SectionInfo> {
    elf.section_headers
        .iter()
        .enumerate()
        .map(|(i, sh)| {
            let name = elf
                .shdr_strtab
                .get_at(sh.sh_name)
                .unwrap_or("<bad-str>")
                .to_string();
            SectionInfo {
                index: i,
                name,
                type_name: section_type_name(sh.sh_type).to_string(),
                type_raw: sh.sh_type,
                flags: section_flags_string(sh.sh_flags),
                flags_raw: sh.sh_flags,
                addr: sh.sh_addr,
                offset: sh.sh_offset,
                size: sh.sh_size,
            }
        })
        .collect()
}

pub fn section_type_name(t: u32) -> &'static str {
    match t {
        0 => "NULL",
        1 => "PROGBITS",
        2 => "SYMTAB",
        3 => "STRTAB",
        4 => "RELA",
        5 => "HASH",
        6 => "DYNAMIC",
        7 => "NOTE",
        8 => "NOBITS",
        9 => "REL",
        10 => "SHLIB",
        11 => "DYNSYM",
        12 => "INIT_ARRAY",
        13 => "FINI_ARRAY",
        14 => "PREINIT_ARRAY",
        15 => "GROUP",
        16 => "SYMTAB_SHNDX",
        17 => "NUM",
        0x6fff_ff00 => "GNU_ATTRIBUTES",
        0x6fff_ff01 => "GNU_HASH",
        0x6fff_ff02 => "GNU_LIBLIST",
        0x6fff_ff03 => "CHECKSUM",
        0x6fff_ff04 => "SUNW_move",
        0x6fff_ff05 => "SUNW_COMDAT",
        0x6fff_ff06 => "SUNW_syminfo",
        0x6fff_ff07 => "GNU_verdef",
        0x6fff_ff08 => "GNU_verneed",
        0x6fff_ff09 => "GNU_versym",
        _ => "UNKNOWN",
    }
}

pub fn section_flags_string(flags: u64) -> String {
    let mut s = String::new();
    if flags & 0x1 != 0 {
        s.push('W');
    }
    if flags & 0x2 != 0 {
        s.push('A');
    }
    if flags & 0x4 != 0 {
        s.push('X');
    }
    if flags & 0x10 != 0 {
        s.push('M');
    }
    if flags & 0x20 != 0 {
        s.push('S');
    }
    if flags & 0x40 != 0 {
        s.push('I');
    }
    if flags & 0x80 != 0 {
        s.push('L');
    }
    if flags & 0x100 != 0 {
        s.push('O');
    }
    if flags & 0x200 != 0 {
        s.push('G');
    }
    if flags & 0x400 != 0 {
        s.push('T');
    }
    if s.is_empty() {
        s.push('-');
    }
    s
}
