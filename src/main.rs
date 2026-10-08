use anyhow::Result;
use clap::Parser;
use std::io::{IsTerminal, Write};
use std::path::PathBuf;

use elfscope::{analyzer, cli::Cli, output};

fn main() -> Result<()> {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {

            let no_args = std::env::args_os().len() <= 1;
            if no_args && std::io::stdin().is_terminal() {
                return run_double_click_flow();
            }
            e.exit();
        }
    };
    let report = analyzer::analyze_file(&cli.binary)?;
    output::dispatch(&report, &cli);
    Ok(())
}

fn run_double_click_flow() -> Result<()> {
    use elfscope::UI::Window_UI::window_frame;

    let banner = "\
elfscope — ELF Security Analyzer (pure-Rust ELF reader)

Usage (from a terminal):
  elfscope <BINARY> --security
  elfscope <BINARY> --sections
  elfscope <BINARY> --symbols
  elfscope <BINARY> --imports
  elfscope <BINARY> --headers
  elfscope <BINARY> --json
  elfscope <BINARY> --tui";
    println!("{}", window_frame("elfscope", banner));

    print!("Path to ELF binary (Enter to quit): ");
    std::io::stdout().flush().ok();
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).ok();
    let input = input.trim().trim_matches('"');
    if input.is_empty() {
        return Ok(());
    }

    let cli = Cli {
        binary: PathBuf::from(input),
        json: false,
        security: false,
        sections: false,
        symbols: false,
        imports: false,
        exports: false,
        dynamic: false,
        tree: false,
        headers: false,
        tui: false,
        no_window: false,
    };
    match analyzer::analyze_file(&cli.binary) {
        Ok(report) => output::dispatch(&report, &cli),
        Err(err) => eprintln!("Error: {:#}", err),
    }

    print!("\nPress Enter to close...");
    std::io::stdout().flush().ok();
    let mut _wait = String::new();
    std::io::stdin().read_line(&mut _wait).ok();
    Ok(())
}
