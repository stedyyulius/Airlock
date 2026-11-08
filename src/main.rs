#![forbid(unsafe_code)]

mod archive;
mod fetch;
mod source;
mod text;

use archive::{Limits, read_archive};
use source::Source;
use std::error::Error;
use std::process::ExitCode;
use text::{Untrusted, escape};

// Exit code 0 will mean a completed scan with no findings, and 1 will mean
// findings. Everything else means no verdict. Nothing may exit 0 until checks
// exist: `airlock scan <url> && npm install` must not carry on after a run that
// checked nothing.
const EXIT_NO_VERDICT: u8 = 2;
const USAGE: &str = "usage: airlock scan <repository-url>";
const MAX_SKIPPED_SHOWN: usize = 20;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    match args.as_slice() {
        [command, url] if command == "scan" => {
            if let Err(error) = scan(url) {
                // Library errors can quote bytes from the archive, such as file
                // names, so all error text is escaped here.
                eprintln!("error: {}", escape(&error.to_string()));
            }
        }
        _ => eprintln!("{USAGE}"),
    }
    ExitCode::from(EXIT_NO_VERDICT)
}

fn scan(url: &str) -> Result<(), Box<dyn Error>> {
    let source = Source::parse(url)?;
    let archive_url = source.archive_url();
    println!("downloading {archive_url}");

    let reader = fetch::open_archive(&archive_url)?;

    let mut largest: Option<(Untrusted, usize)> = None;
    let summary = read_archive(reader, &Limits::default(), |file| {
        let size = file.contents.len();
        if largest.as_ref().is_none_or(|(_, most)| size > *most) {
            largest = Some((file.path, size));
        }
    })?;

    if let Some(commit) = &summary.commit {
        println!("commit: {commit}");
    }
    println!("read {} files ({} bytes)", summary.files, summary.bytes);
    if let Some((path, size)) = largest {
        println!("largest file read: {path} ({size} bytes)");
    }

    if summary.skipped_total > 0 {
        println!("not read: {} entries", summary.skipped_total);
        for skipped in summary.skipped.iter().take(MAX_SKIPPED_SHOWN) {
            println!("  {}: {}", skipped.path, skipped.reason);
        }
        let shown = summary.skipped.len().min(MAX_SKIPPED_SHOWN) as u64;
        if summary.skipped_total > shown {
            println!("  ...and {} more", summary.skipped_total - shown);
        }
    }

    println!("no checks are implemented yet, so this is not a verdict");
    Ok(())
}
