#![forbid(unsafe_code)]

mod archive;
mod fetch;
mod network;
mod opaque;
mod refs;
mod report;
mod saved;
mod source;
mod text;

use archive::{Limits, read_archive};
use report::{Kind, Report};
use source::Target;
use std::error::Error;
use std::fmt::Write;
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
    let target = Target::parse(url)?;
    let source = &target.source;

    let resolved = match &target.view {
        Some(view) => Some(refs::resolve(source, view)?),
        None => None,
    };
    let archive_url = match &resolved {
        Some(resolved) => source.archive_url_at(&resolved.commit),
        None => source.archive_url(),
    };
    let folder = resolved.as_ref().and_then(|found| found.folder.as_deref());

    println!("downloading {archive_url}");
    let reader = fetch::open_archive(&archive_url)?;

    let mut report = Report::new();
    let mut files = 0;
    let mut bytes = 0;

    let summary = read_archive(reader, &Limits::default(), |file| {
        if !is_in_folder(file.path.raw(), folder) {
            return;
        }
        files += 1;
        bytes += file.contents.len() as u64;

        network::scan(&file, &mut report);
        opaque::scan(&file, &mut report);
    })?;

    // The host chose what to send, so check it sent what was asked for.
    if let Some(resolved) = &resolved {
        if summary
            .commit
            .as_ref()
            .is_some_and(|commit| *commit != resolved.commit)
        {
            return Err("the host sent a different commit than the one asked for".into());
        }
    }

    let mut not_read = 0;
    for skipped in &summary.skipped {
        if is_in_folder(skipped.path.raw(), folder) {
            not_read += 1;
            let subject = format!("{}: {}", skipped.path.raw(), skipped.reason);
            report.add(Kind::NotRead, "", &subject, None);
        }
    }
    report.note_not_listed(summary.skipped_total - summary.skipped.len() as u64);

    if let Some(folder) = folder {
        if files == 0 && not_read == 0 {
            return Err(format!("this commit has nothing at: {folder}").into());
        }
    }

    let mut results = String::new();
    if let Some(commit) = &summary.commit {
        writeln!(results, "commit: {commit}")?;
    }
    if let Some(resolved) = &resolved {
        writeln!(
            results,
            "{}: {}",
            resolved.reference_kind,
            escape(&resolved.reference)
        )?;
    }
    if let Some(folder) = folder {
        writeln!(results, "path: {}", escape(folder))?;
    }
    writeln!(results, "read {files} files ({bytes} bytes)")?;
    write!(results, "{report}")?;
    print!("{results}");

    match saved::save(&format!("scanned {archive_url}\n{results}")) {
        Ok(path) => {
            println!(
                "\nAirlock keeps one report file and each scan replaces it, \
                 so copy it if you want to keep it."
            );
            println!("To see this report in a file, go here: {}", path.display());
        }
        // The report is already on screen, so this doesn't fail the scan.
        Err(error) => eprintln!(
            "\ncould not save the report to a file: {}",
            escape(&error.to_string())
        ),
    }
    Ok(())
}

fn is_in_folder(path: &str, folder: Option<&str>) -> bool {
    match folder {
        None => true,
        Some(folder) => {
            path == folder
                || path
                    .strip_prefix(folder)
                    .is_some_and(|rest| rest.starts_with('/'))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn with_no_folder_every_path_counts() {
        assert!(is_in_folder("anything/at/all.js", None));
    }

    #[test]
    fn a_folder_covers_its_files_and_nothing_else() {
        let folder = Some("erc20-token-dapp");

        assert!(is_in_folder("erc20-token-dapp/package.json", folder));
        assert!(is_in_folder("erc20-token-dapp/src/a.js", folder));
        assert!(!is_in_folder("erc20-token-dapp-2/package.json", folder));
        assert!(!is_in_folder("other/erc20-token-dapp/a.js", folder));
        assert!(!is_in_folder("README.md", folder));
    }

    #[test]
    fn a_link_to_one_file_covers_just_that_file() {
        let folder = Some("src/a.js");

        assert!(is_in_folder("src/a.js", folder));
        assert!(!is_in_folder("src/a.jsx", folder));
    }
}
