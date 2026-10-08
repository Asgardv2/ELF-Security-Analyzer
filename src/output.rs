use crate::{
    UI::Window_UI::window_frame,
    analyzer::AnalysisReport,
    cli::Cli,
    dynamic::DynamicView,
    sections::SectionInfo,
    security::SecurityReport,
    symbols::SymbolInfo,
};

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

pub const DIVIDER: &str = "────────────────────────────────────────";

#[allow(dead_code)]
fn tick(ok: bool) -> &'static str {
    if ok {
        "✓"
    } else {
        "✗"
    }
}

fn table_row(cells: &[String], widths: &[usize]) -> String {
    cells
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let w = widths.get(i).copied().unwrap_or(12);
            if c.len() >= w {
                c.clone()
            } else {
                format!("{}{}", c, " ".repeat(w - c.len()))
            }
        })
        .collect::<Vec<_>>()
        .join("  ")
}

pub fn type_short(file_type_raw: u16) -> &'static str {
    match file_type_raw {
        1 => "REL",
        2 => "EXEC",
        3 => "DYN",
        4 => "CORE",
        _ => "UNKNOWN",
    }
}

pub fn report_header(r: &AnalysisReport) -> String {
    let mut s = String::new();
    s.push_str(&format!("ELFscope v{}\n", version()));
    s.push_str(DIVIDER);
    s.push('\n');
    s.push_str(&format!("File:      {}\n", r.file));
    s.push_str(&format!("Arch:      {}\n", r.header.machine));
    s.push_str(&format!("Type:      {}\n", type_short(r.header.file_type_raw)));
    s.push_str(&format!("Entry:     0x{:x}\n", r.entry_point));
    s.push_str(&format!(
        "Endian:    {}\n",
        if r.header.is_little_endian {
            "Little"
        } else {
            "Big"
        }
    ));
    s.push_str(&format!("OS ABI:    {}\n", r.header.os_abi));
    s.push_str(DIVIDER);
    s.push('\n');
    s
}

pub fn tree_text(r: &AnalysisReport) -> String {
    let mut s = String::from("elfscope\n");
    let (score, total) = r.security.score();

    s.push_str("├── ELF Header\n");
    s.push_str(&format!("│   ├── Architecture: {}\n", r.architecture));
    s.push_str(&format!("│   ├── Entry point:  0x{:x}\n", r.entry_point));
    s.push_str(&format!(
        "│   ├── Type:         {}\n",
        r.header.file_type
    ));
    s.push_str(&format!(
        "│   └── Class:        {}\n",
        if r.header.is_64bit { "64-bit" } else { "32-bit" }
    ));

    s.push_str(&format!("├── Security (score {}/{})\n", score, total));
    let rows = r.security.detailed_rows();
    for (i, row) in rows.iter().enumerate() {
        let edge = if i + 1 == rows.len() {
            "└──"
        } else {
            "├──"
        };
        s.push_str(&format!(
            "│   {} {}: {} {}\n",
            edge, row.label, row.mark, row.reason
        ));
    }

    s.push_str(&format!("├── Sections ({})\n", r.sections.len()));
    if r.sections.is_empty() {
        s.push_str("│   └── (no section headers)\n");
    } else {
        const SHOWN: usize = 8;
        let shown = r.sections.len().min(SHOWN);
        for (i, sec) in r.sections.iter().take(shown).enumerate() {
            let last = i + 1 == shown && r.sections.len() <= SHOWN;
            let edge = if last { "└──" } else { "├──" };
            s.push_str(&format!("│   {} {}\n", edge, sec.name));
        }
        if r.sections.len() > SHOWN {
            s.push_str(&format!("│   └── … ({} more)\n", r.sections.len() - SHOWN));
        }
    }

    s.push_str("├── Symbols\n");
    s.push_str(&format!("│   ├── Imports ({})\n", r.imports.len()));
    s.push_str(&format!("│   └── Exports ({})\n", r.exports.len()));

    s.push_str("└── Dynamic\n");
    let needed = if r.dynamic.needed.is_empty() {
        "(none)".to_string()
    } else if r.dynamic.needed.len() <= 3 {
        r.dynamic.needed.join(", ")
    } else {
        format!(
            "{}, … ({} more)",
            r.dynamic.needed[..3].join(", "),
            r.dynamic.needed.len() - 3
        )
    };
    s.push_str(&format!("    ├── NEEDED: {}\n", needed));
    let rpath = search_path_line(&r.dynamic);
    s.push_str(&format!("    ├── RPATH/RUNPATH: {}\n", rpath));
    let flags = flags_line(&r.dynamic);
    s.push_str(&format!("    └── FLAGS: {}\n", flags));
    s
}

fn search_path_line(d: &DynamicView) -> String {
    let mut parts: Vec<String> = Vec::new();
    if !d.rpaths.is_empty() {
        parts.push(format!("RPATH={}", d.rpaths.join(":")));
    }
    if !d.runpaths.is_empty() {
        parts.push(format!("RUNPATH={}", d.runpaths.join(":")));
    }
    if parts.is_empty() {
        "(none)".into()
    } else {
        parts.join(" ")
    }
}

fn flags_line(d: &DynamicView) -> String {
    let mut parts: Vec<String> = Vec::new();
    parts.extend(d.flags.iter().cloned());
    parts.extend(d.flags_1.iter().cloned());
    if parts.is_empty() {
        "(none)".into()
    } else {
        parts.join(" ")
    }
}

pub fn overview_text(r: &AnalysisReport) -> String {
    let mut s = report_header(r);
    s.push('\n');
    s.push_str(&tree_text(r));
    s
}

pub fn security_text(sec: &SecurityReport) -> String {
    security_detail(sec)
}

pub fn security_detail(sec: &SecurityReport) -> String {
    let rows = sec.detailed_rows();
    let w0 = rows
        .iter()
        .map(|r| r.label.len())
        .max()
        .unwrap_or(8)
        .max(8);
    let mut s = String::from("Security\n");
    s.push_str(DIVIDER);
    s.push('\n');
    for row in &rows {
        s.push_str(&format!("{:<w$}  {}  {}\n", row.label, row.mark, row.reason, w = w0));
    }
    let (score, total) = sec.score();
    s.push_str(&format!("\nSecurity score: {} / {}\n", score, total));
    s.push_str(DIVIDER);
    s.push('\n');
    s
}

pub fn security_table(sec: &SecurityReport) -> String {
    let rows = sec.detailed_rows();
    let w0 = rows
        .iter()
        .map(|r| r.label.len())
        .max()
        .unwrap_or(7)
        .max(8);
    let mut s = String::from("A security check:\n");
    for row in &rows {
        s.push_str(&format!("  {:<w$} {}  {}\n", row.label, row.mark, row.reason, w = w0));
    }
    let (score, total) = sec.score();
    s.push_str(&format!("  Security score: {} / {}\n", score, total));
    s
}

pub fn human_size(n: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * 1024;
    if n < KB {
        format!("{} B", n)
    } else if n < MB {
        format!("{:.1} KB", n as f64 / KB as f64)
    } else {
        format!("{:.1} MB", n as f64 / MB as f64)
    }
}

pub fn section_perm_short(flags: u64) -> String {
    let mut s = String::new();
    if flags & 0x2 != 0 {
        s.push('R');
    }
    if flags & 0x1 != 0 {
        s.push('W');
    }
    if flags & 0x4 != 0 {
        s.push('X');
    }
    if s.is_empty() {
        s.push('-');
    }
    s
}

pub fn sections_text(sections: &[SectionInfo]) -> String {
    let shown: Vec<&SectionInfo> = sections.iter().filter(|s| !s.name.is_empty()).collect();
    if shown.is_empty() {
        return "No section headers (stripped or object without shdrs).\n".into();
    }
    let name_w = shown
        .iter()
        .map(|s| s.name.chars().count())
        .max()
        .unwrap_or(8)
        .max(8)
        + 2;
    let mut s = String::from("Sections\n");
    s.push_str(DIVIDER);
    s.push('\n');
    for sh in shown {
        let name = format!("{}{}", sh.name, " ".repeat(name_w.saturating_sub(sh.name.chars().count())));
        let addr = format!("0x{:x}", sh.addr);
        let addr = format!("{}{}", addr, " ".repeat(12usize.saturating_sub(addr.len())));
        let size = human_size(sh.size);
        let size = format!("{}{}", size, " ".repeat(9usize.saturating_sub(size.len())));
        s.push_str(&format!("{}{}{}  {}\n", name, addr, size, section_perm_short(sh.flags_raw)));
    }
    s
}

pub fn symbols_text(symbols: &[SymbolInfo], limit: usize) -> String {
    if symbols.is_empty() {
        return "No symbols (fully stripped?).\n".into();
    }
    let widths = [30, 12, 10, 9, 8, 8];
    let mut s = String::new();
    s.push_str(&table_row(
        &["Name", "Value", "Size", "Type", "Bind", "Sec"]
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>(),
        &widths,
    ));
    s.push('\n');
    s.push_str(&"-".repeat(widths.iter().sum::<usize>() + 10));
    s.push('\n');
    for sym in symbols.iter().take(limit) {
        let mut name = sym.name.clone();
        if name.len() > 30 {
            name.truncate(30);
        }
        s.push_str(&table_row(
            &[
                name,
                format!("0x{:x}", sym.value),
                format!("0x{:x}", sym.size),
                sym.kind.clone(),
                sym.bind.clone(),
                sym.section.clone(),
            ],
            &widths,
        ));
        s.push('\n');
    }
    if symbols.len() > limit {
        s.push_str(&format!("… ({} more, use --json for full list)\n", symbols.len() - limit));
    }
    s
}

pub fn symbols_grouped(imports: &[SymbolInfo], exports: &[SymbolInfo]) -> String {
    let mut s = String::from("Symbols\n");
    s.push_str(DIVIDER);
    s.push('\n');
    s.push_str("Imports:\n");
    if imports.is_empty() {
        s.push_str("  (none)\n");
    } else {
        for imp in imports {
            s.push_str(&format!("  {}\n", imp.name));
        }
    }
    s.push('\n');
    s.push_str("Exports:\n");
    if exports.is_empty() {
        s.push_str("  (none)\n");
    } else {
        for exp in exports {
            s.push_str(&format!("  {}\n", exp.name));
        }
    }
    s
}

pub fn imports_text(imports: &[SymbolInfo], libraries: &[String]) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "Libraries (DT_NEEDED): {}\n",
        if libraries.is_empty() {
            "-".into()
        } else {
            libraries.join(", ")
        }
    ));
    s.push('\n');
    if imports.is_empty() {
        s.push_str("No dynamic imports (static binary?).\n");
        return s;
    }
    for imp in imports {
        s.push_str(&format!("  {}\n", imp.name));
    }
    s
}

pub fn exports_text(exports: &[SymbolInfo]) -> String {
    if exports.is_empty() {
        return "No dynamic exports.\n".into();
    }
    let mut s = String::new();
    for exp in exports {
        s.push_str(&format!("  {} (0x{:x})\n", exp.name, exp.value));
    }
    s
}

pub fn dependencies_text(d: &DynamicView) -> String {
    let mut s = String::from("Dependencies\n");
    s.push_str(DIVIDER);
    s.push('\n');
    if d.needed.is_empty() {
        s.push_str("(none — static binary?)\n");
    } else {
        for lib in &d.needed {
            s.push_str(&format!("{}\n", lib));
        }
    }
    s.push('\n');
    s.push_str(&format!("{:<9} {}\n", "RPATH", rpath_mark(&d.rpaths)));
    s.push_str(&format!("{:<9} {}\n", "RUNPATH", rpath_mark(&d.runpaths)));
    s
}

fn rpath_mark(paths: &[String]) -> String {
    if paths.is_empty() {
        "✗ None".into()
    } else {
        format!("✓ {}", paths.join(":"))
    }
}

pub fn dynamic_text(d: &DynamicView) -> String {
    let mut s = String::from("Dynamic:\n");
    s.push_str(&format!(
        "  NEEDED:   {}\n",
        if d.needed.is_empty() {
            "-".into()
        } else {
            d.needed.join(", ")
        }
    ));
    s.push_str(&format!(
        "  SONAME:   {}\n",
        d.soname.as_deref().unwrap_or("-")
    ));
    s.push_str(&format!(
        "  RPATH:    {}\n",
        if d.rpaths.is_empty() {
            "-".into()
        } else {
            d.rpaths.join(":")
        }
    ));
    s.push_str(&format!(
        "  RUNPATH:  {}\n",
        if d.runpaths.is_empty() {
            "-".into()
        } else {
            d.runpaths.join(":")
        }
    ));
    s.push_str(&format!(
        "  FLAGS:    {} (0x{:x})\n",
        if d.flags.is_empty() {
            "-".into()
        } else {
            d.flags.join(" ")
        },
        d.flags_raw
    ));
    s.push_str(&format!(
        "  FLAGS_1:  {} (0x{:x})\n",
        if d.flags_1.is_empty() {
            "-".into()
        } else {
            d.flags_1.join(" ")
        },
        d.flags_1_raw
    ));
    s
}

pub fn headers_text(r: &AnalysisReport) -> String {
    let h = &r.header;
    let mut s = String::new();
    s.push_str("ELF header:\n");
    s.push_str(&format!("  Magic:      {}\n", h.magic));
    s.push_str(&format!("  Class:      {}\n", h.class));
    s.push_str(&format!("  Data:       {}\n", h.data));
    s.push_str(&format!("  OS/ABI:     {}\n", h.os_abi));
    s.push_str(&format!("  Type:       {} ({})\n", h.file_type, h.file_type_raw));
    s.push_str(&format!("  Machine:    {} ({})\n", h.machine, h.machine_code));
    s.push_str(&format!("  Entry:      0x{:x}\n", h.entry_point));
    s.push_str(&format!("  PH off:     0x{:x} ({} entries)\n", h.ph_offset, h.ph_count));
    s.push_str(&format!("  SH off:     0x{:x} ({} entries)\n", h.sh_offset, h.sh_count));
    s.push('\n');
    s.push_str("Program headers:\n");
    let widths = [5, 14, 6, 12, 12, 10, 10];
    s.push_str(&table_row(
        &["Idx", "Type", "Flags", "Vaddr", "Offset", "Filesz", "Memsz"]
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>(),
        &widths,
    ));
    s.push('\n');
    for ph in &r.program_headers {
        s.push_str(&table_row(
            &[
                ph.index.to_string(),
                ph.type_name.clone(),
                ph.flags.clone(),
                format!("0x{:x}", ph.vaddr),
                format!("0x{:x}", ph.offset),
                format!("0x{:x}", ph.filesz),
                format!("0x{:x}", ph.memsz),
            ],
            &widths,
        ));
        s.push('\n');
    }
    s
}

pub fn full_text(r: &AnalysisReport) -> String {
    let mut s = String::new();
    s.push_str(&report_header(r));
    s.push('\n');
    s.push_str(&tree_text(r));
    s.push('\n');
    s.push_str(&security_detail(&r.security));
    s.push('\n');
    s.push_str(&headers_text(r));
    s.push('\n');
    s.push_str(&sections_text(&r.sections));
    s.push('\n');
    s.push_str(&symbols_grouped(&r.imports, &r.exports));
    s.push('\n');
    s.push_str("All symbols (first 50):\n");
    s.push_str(&symbols_text(&r.symbols, 50));
    s.push('\n');
    s.push_str(&dependencies_text(&r.dynamic));
    s
}

pub fn security_json(sec: &SecurityReport) -> serde_json::Value {
    let (score, _) = sec.score();
    serde_json::json!({
        "pie": sec.pie,
        "nx": sec.nx,
        "relro": sec.relro.as_str(),
        "canary": sec.canary,
        "fortify": sec.fortify,
        "stripped": sec.stripped,
        "score": score,
    })
}

pub fn print_json(report: &AnalysisReport) {
    println!(
        "{}",
        serde_json::to_string_pretty(report).unwrap_or_else(|_| "{}".into())
    );
}

fn framed(title: &str, body: String, no_window: bool) {
    if no_window {
        print!("{}", body);
    } else {
        println!("{}", window_frame(title, &body));
    }
}

pub fn dispatch(report: &AnalysisReport, cli: &Cli) {

    if cli.json && cli.security && !cli.sections && !cli.symbols && !cli.imports
        && !cli.exports && !cli.dynamic && !cli.headers && !cli.tree
    {
        println!("{}", serde_json::to_string_pretty(&security_json(&report.security)).unwrap());
        return;
    }
    if cli.json {
        print_json(report);
        return;
    }
    if cli.tui {
        if let Err(e) = crate::UI::Window_UI::run_tui(report) {
            eprintln!("TUI error: {:#} — falling back to plain output", e);
            print!("{}", full_text(report));
        }
        return;
    }
    let title = format!("elfscope: {}", report.file);

    if cli.has_filter() {
        let mut parts: Vec<String> = Vec::new();
        if cli.tree {
            parts.push(tree_text(report));
        }
        if cli.security {
            parts.push(security_table(&report.security));
        }
        if cli.headers {
            parts.push(headers_text(report));
        }
        if cli.sections {
            parts.push(sections_text(&report.sections));
        }
        if cli.symbols {
            parts.push(symbols_grouped(&report.imports, &report.exports));
        }
        if cli.imports {
            parts.push("Imports:\n".to_string() + &imports_text(&report.imports, &report.libraries));
        }
        if cli.exports {
            parts.push("Exports:\n".to_string() + &exports_text(&report.exports));
        }
        if cli.dynamic {
            parts.push(dependencies_text(&report.dynamic));
        }
        framed(&title, parts.join("\n"), cli.no_window);
        return;
    }
    framed(&title, full_text(report), cli.no_window);
}
