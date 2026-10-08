use anyhow::{Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::{
    dynamic::{self, DynamicView},
    elf,
    sections::{self, SectionInfo},
    security::{self, SecurityReport},
    symbols::{self, SymbolInfo},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisReport {
    pub file: String,
    pub size: u64,
    pub header: elf::ElfHeaderInfo,
    pub architecture: String,
    pub entry_point: u64,
    pub interpreter: Option<String>,
    pub libraries: Vec<String>,
    pub program_headers: Vec<elf::ProgramHeaderInfo>,
    pub sections: Vec<SectionInfo>,
    pub symbols: Vec<SymbolInfo>,
    pub imports: Vec<SymbolInfo>,
    pub exports: Vec<SymbolInfo>,
    pub dynamic: DynamicView,
    pub security: SecurityReport,
}

pub fn analyze_file(path: &Path) -> Result<AnalysisReport> {
    let label = path.display().to_string();
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::with_template("{spinner:.cyan} {msg}")
            .unwrap_or_else(|_| ProgressStyle::default_spinner()),
    );
    pb.enable_steady_tick(Duration::from_millis(60));
    pb.set_message(format!("Reading {}", label));

    let bytes = std::fs::read(path)
        .with_context(|| format!("cannot read file '{}'", path.display()))?;
    pb.set_message(format!("Parsing ELF ({} bytes)…", bytes.len()));
    let report = analyze_bytes(&label, &bytes)?;
    pb.finish_and_clear();
    Ok(report)
}

pub fn analyze_bytes(file_label: &str, bytes: &[u8]) -> Result<AnalysisReport> {

    let header = elf::parse_header_raw(bytes)
        .with_context(|| format!("'{}' is not a valid ELF", file_label))?;
    let architecture = elf::architecture_label(&header);

    let goblin_elf = elf::parse_goblin(bytes)?;
    let program_headers = elf::program_headers(&goblin_elf);
    let sections = sections::collect(&goblin_elf);
    let symbols = symbols::collect_symbols(&goblin_elf);
    let imports = symbols::collect_imports(&goblin_elf);
    let exports = symbols::collect_exports(&goblin_elf);
    let libraries = symbols::collect_libraries(&goblin_elf);
    let dynamic = dynamic::collect(&goblin_elf);
    let interpreter = goblin_elf.interpreter.map(|s| s.to_string());
    let section_names: Vec<String> = sections.iter().map(|s| s.name.clone()).collect();
    let security = security::analyze(&goblin_elf, &symbols, &section_names);

    Ok(AnalysisReport {
        file: file_label.to_string(),
        size: bytes.len() as u64,
        entry_point: header.entry_point,
        header,
        architecture,
        interpreter,
        libraries,
        program_headers,
        sections,
        symbols,
        imports,
        exports,
        dynamic,
        security,
    })
}

#[allow(dead_code)]
pub fn analyze_path_buf(path: PathBuf) -> Result<AnalysisReport> {
    analyze_file(&path)
}
