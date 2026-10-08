use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "elfscope",
    version,
    about = "ELF Security Analyzer — pure-Rust ELF reader (goblin MVP)",
    long_about = "Analyze ELF binaries: header, arch, entry, sections, \
program headers, symbols, imports and checksec-style security mitigations.\n\n\
Examples:\n  \
elfscope ./binary --security\n  \
elfscope ./binary --sections\n  \
elfscope ./binary --symbols\n  \
elfscope ./binary --imports\n  \
elfscope ./binary --json\n  \
elfscope ./binary --tui"
)]
pub struct Cli {

    #[arg(value_name = "BINARY")]
    pub binary: PathBuf,

    #[arg(long)]
    pub json: bool,

    #[arg(long)]
    pub security: bool,

    #[arg(long)]
    pub sections: bool,

    #[arg(long)]
    pub symbols: bool,

    #[arg(long)]
    pub imports: bool,

    #[arg(long)]
    pub exports: bool,

    #[arg(long)]
    pub dynamic: bool,

    #[arg(long)]
    pub tree: bool,

    #[arg(long, alias = "program-headers")]
    pub headers: bool,

    #[arg(long)]
    pub tui: bool,

    #[arg(long)]
    pub no_window: bool,
}

impl Cli {

    pub fn has_filter(&self) -> bool {
        self.security
            || self.sections
            || self.symbols
            || self.imports
            || self.exports
            || self.dynamic
            || self.headers
            || self.tree
    }
}
