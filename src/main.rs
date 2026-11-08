#![forbid(unsafe_code)]

mod archive;
mod fetch;
mod network;
mod opaque;
mod report;
mod source;
mod text;

use archive::{Limits, read_archive};
use report::{Kind, Report};
use source::Source;
use std::error::Error;
use std::process::ExitCode;
use text::escape;

// Exit code 0 will mean a completed scan with no findings, and 1 will mean
// findings. Everything else means no verdict. Nothing may exit 0 until checks
// exist: `airlock scan <url> && npm install` must not carry on after a run that
// checked nothing.
const EXIT_NO_VERDICT: u8 = 2;
const USAGE: &str = "usage: airlock scan <repository-url>";

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

    let mut report = Report::new();
    let summary = read_archive(reader, &Limits::default(), |file| {
        network::scan(&file, &mut report);
        opaque::scan(&file, &mut report);
    })?;

    for skipped in &summary.skipped {
        let subject = format!("{}: {}", skipped.path.raw(), skipped.reason);
        report.add(Kind::NotRead, "", &subject, None);
    }
    report.note_not_listed(summary.skipped_total - summary.skipped.len() as u64);

    if let Some(commit) = &summary.commit {
        println!("commit: {commit}");
    }
    println!("read {} files ({} bytes)", summary.files, summary.bytes);
    print!("{report}");
    Ok(())
}
