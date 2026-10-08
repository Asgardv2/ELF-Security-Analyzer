use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ElfError {
    #[error("not an ELF file (bad magic)")]
    BadMagic,
    #[error("this is a Windows PE/DOS binary (MZ magic) — elfscope analyzes ELF files (Linux/Unix)")]
    IsPeBinary,
    #[error("file too small ({0} bytes), need >= 64 for ELF header")]
    TooSmall(usize),
    #[error("unsupported ELF class/data: {0}")]
    Unsupported(&'static str),
    #[error("goblin parse error: {0}")]
    Goblin(#[from] goblin::error::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElfHeaderInfo {
    pub magic: String,
    pub class: String,
    pub data: String,
    pub version: String,
    pub os_abi: String,
    pub abi_version: u8,
    pub file_type: String,
    pub file_type_raw: u16,
    pub machine: String,
    pub machine_code: u16,
    pub entry_point: u64,
    pub ph_offset: u64,
    pub sh_offset: u64,
    pub flags: u32,
    pub header_size: u16,
    pub ph_entry_size: u16,
    pub ph_count: u16,
    pub sh_entry_size: u16,
    pub sh_count: u16,
    pub sh_str_index: u16,
    pub is_64bit: bool,
    pub is_little_endian: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramHeaderInfo {
    pub index: usize,
    pub type_name: String,
    pub type_raw: u32,
    pub flags: String,
    pub flags_raw: u32,
    pub offset: u64,
    pub vaddr: u64,
    pub paddr: u64,
    pub filesz: u64,
    pub memsz: u64,
    pub align: u64,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

pub fn parse_header_raw(bytes: &[u8]) -> Result<ElfHeaderInfo, ElfError> {
    if bytes.len() < 64 {
        return Err(ElfError::TooSmall(bytes.len()));
    }
    if bytes[0] == b'M' && bytes[1] == b'Z' {
        return Err(ElfError::IsPeBinary);
    }
    if bytes[0] != 0x7f || bytes[1] != b'E' || bytes[2] != b'L' || bytes[3] != b'F' {
        return Err(ElfError::BadMagic);
    }
    let class = bytes[4];
    let data = bytes[5];
    let ei_version = bytes[6];
    let os_abi = bytes[7];
    let abi_version = bytes[8];

    let is_64bit = match class {
        1 => false,
        2 => true,
        _ => return Err(ElfError::Unsupported("unknown EI_CLASS")),
    };
    let le = match data {
        1 => true,
        2 => false,
        _ => return Err(ElfError::Unsupported("unknown EI_DATA")),
    };

    let u16_at = |off: usize| -> u16 {
        let b = [bytes[off], bytes[off + 1]];
        if le {
            u16::from_le_bytes(b)
        } else {
            u16::from_be_bytes(b)
        }
    };
    let u32_at = |off: usize| -> u32 {
        let b = [bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]];
        if le {
            u32::from_le_bytes(b)
        } else {
            u32::from_be_bytes(b)
        }
    };
    let u64_at = |off: usize| -> u64 {
        let b = [
            bytes[off],
            bytes[off + 1],
            bytes[off + 2],
            bytes[off + 3],
            bytes[off + 4],
            bytes[off + 5],
            bytes[off + 6],
            bytes[off + 7],
        ];
        if le {
            u64::from_le_bytes(b)
        } else {
            u64::from_be_bytes(b)
        }
    };

    let file_type_raw = u16_at(16);
    let machine_code = u16_at(18);
    let (entry_point, ph_offset, sh_offset, flags, hs, phe, phn, she, shn, shstrndx) = if is_64bit {
        (
            u64_at(24),
            u64_at(32),
            u64_at(40),
            u32_at(48),
            u16_at(52),
            u16_at(54),
            u16_at(56),
            u16_at(58),
            u16_at(60),
            u16_at(62),
        )
    } else {
        (
            u32_at(24) as u64,
            u32_at(28) as u64,
            u32_at(32) as u64,
            u32_at(36),
            u16_at(40),
            u16_at(42),
            u16_at(44),
            u16_at(46),
            u16_at(48),
            u16_at(50),
        )
    };

    Ok(ElfHeaderInfo {
        magic: "7f 45 4c 46".to_string(),
        class: if is_64bit { "ELF64".into() } else { "ELF32".into() },
        data: if le {
            "little-endian".into()
        } else {
            "big-endian".into()
        },
        version: format!("{} (current)", ei_version),
        os_abi: os_abi_name(os_abi).to_string(),
        abi_version,
        file_type: file_type_name(file_type_raw).to_string(),
        file_type_raw,
        machine: machine_name(machine_code).to_string(),
        machine_code,
        entry_point,
        ph_offset,
        sh_offset,
        flags,
        header_size: hs,
        ph_entry_size: phe,
        ph_count: phn,
        sh_entry_size: she,
        sh_count: shn,
        sh_str_index: shstrndx,
        is_64bit,
        is_little_endian: le,
    })
}

pub fn architecture_label(header: &ElfHeaderInfo) -> String {
    format!(
        "{} ({}, {})",
        header.machine, header.class, header.data
    )
}

pub fn parse_goblin(bytes: &[u8]) -> Result<goblin::elf::Elf<'_>, ElfError> {
    match goblin::Object::parse(bytes)? {
        goblin::Object::Elf(elf) => Ok(elf),
        _ => Err(ElfError::BadMagic),
    }
}

pub fn program_headers(elf: &goblin::elf::Elf) -> Vec<ProgramHeaderInfo> {
    elf.program_headers
        .iter()
        .enumerate()
        .map(|(i, ph)| {
            let r = ph.p_flags & 4 != 0;
            let w = ph.p_flags & 2 != 0;
            let x = ph.p_flags & 1 != 0;
            ProgramHeaderInfo {
                index: i,
                type_name: ph_type_name(ph.p_type).to_string(),
                type_raw: ph.p_type,
                flags: ph_flags_string(ph.p_flags),
                flags_raw: ph.p_flags,
                offset: ph.p_offset,
                vaddr: ph.p_vaddr,
                paddr: ph.p_paddr,
                filesz: ph.p_filesz,
                memsz: ph.p_memsz,
                align: ph.p_align,
                readable: r,
                writable: w,
                executable: x,
            }
        })
        .collect()
}

pub fn file_type_name(t: u16) -> &'static str {
    match t {
        0 => "NONE (none)",
        1 => "REL (relocatable)",
        2 => "EXEC (executable)",
        3 => "DYN (shared object / PIE)",
        4 => "CORE (core dump)",
        _ => "UNKNOWN",
    }
}

pub fn machine_name(m: u16) -> &'static str {
    match m {
        0 => "None",
        1 => "M32",
        2 => "SPARC",
        3 => "x86",
        4 => "68k",
        5 => "88k",
        7 => "860",
        8 => "MIPS",
        10 => "MIPS RS3 LE",
        20 => "PowerPC",
        21 => "PowerPC64",
        22 => "S390",
        40 => "ARM",
        42 => "SuperH",
        50 => "IA-64",
        62 => "x86-64",
        183 => "AArch64",
        189 => "MicroBlaze",
        243 => "RISC-V",
        252 => "BPF",
        _ => "Unknown",
    }
}

pub fn os_abi_name(a: u8) -> &'static str {
    match a {
        0 => "System V",
        1 => "HP-UX",
        2 => "NetBSD",
        3 => "Linux",
        4 => "GNU Hurd",
        6 => "Solaris",
        7 => "AIX",
        8 => "IRIX",
        9 => "FreeBSD",
        10 => "Tru64",
        11 => "Novell Modesto",
        12 => "OpenBSD",
        13 => "OpenVMS",
        14 => "NonStop",
        15 => "AROS",
        16 => "FenixOS",
        17 => "Nuxi CloudABI",
        18 => "Stratus OpenVOS",
        97 => "ARM AEABI",
        255 => "Standalone",
        _ => "Unknown",
    }
}

pub fn ph_type_name(t: u32) -> &'static str {
    match t {
        0 => "NULL",
        1 => "LOAD",
        2 => "DYNAMIC",
        3 => "INTERP",
        4 => "NOTE",
        5 => "SHLIB",
        6 => "PHDR",
        7 => "TLS",
        0x6474_e550 => "GNU_EH_FRAME",
        0x6474_e551 => "GNU_STACK",
        0x6474_e552 => "GNU_RELRO",
        0x6474_e553 => "GNU_PROPERTY",
        0x6474_e554 => "GNU_MINSIGSTKSZ",
        0x6fff_fffa => "MIPS_ABIFLAGS",
        0x6fff_fffb => "MIPS_AFLAGS",
        _ => "UNKNOWN",
    }
}

pub fn ph_flags_string(f: u32) -> String {
    let mut s = String::new();
    s.push(if f & 4 != 0 { 'R' } else { ' ' });
    s.push(if f & 2 != 0 { 'W' } else { ' ' });
    s.push(if f & 1 != 0 { 'E' } else { ' ' });
    s
}

pub const PT_GNU_STACK: u32 = 0x6474_e551;
pub const PT_GNU_RELRO: u32 = 0x6474_e552;
pub const PF_X: u32 = 1;
