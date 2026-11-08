#![forbid(unsafe_code)]

mod autorun;
mod behavior;
mod deps;
mod fetch;
mod git;
mod hidden;
mod links;
mod network;
mod obfuscation;
mod opaque;
mod osv;
mod refs;
mod report;
mod saved;
mod source;
mod text;

use autorun::AutoRun;
use deps::Dependencies;
use git::Limits;
use report::{Kind, PLAIN, Palette, Report, ScanInfo};
use source::Target;
use std::error::Error;
use std::process::ExitCode;
use text::escape;

// Exit code 0 means a completed scan with nothing to report, and even that isn't
// proof of safety. 1 means there are findings to review, and 2 means no result.
// `airlock scan <url> && npm install` therefore stops at any finding.
const EXIT_FINDINGS: u8 = 1;
const EXIT_NO_RESULT: u8 = 2;
const USAGE: &str = "usage: airlock scan <repository-url>";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    match args.as_slice() {
        [command, url] if command == "scan" => match scan(url) {
            Ok(false) => ExitCode::SUCCESS,
            Ok(true) => ExitCode::from(EXIT_FINDINGS),
            Err(error) => {
                // Library errors can quote bytes from the repository, such as file
                // names, so all error text is escaped here.
                eprintln!("error: {}", escape(&error.to_string()));
                ExitCode::from(EXIT_NO_RESULT)
            }
        },
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(EXIT_NO_RESULT)
        }
    }
}

/// Runs a scan and returns whether it found anything to report.
fn scan(url: &str) -> Result<bool, Box<dyn Error>> {
    let target = Target::parse(url)?;
    let source = &target.source;
    let name = source.name();

    let resolved = refs::resolve(source, target.view.as_deref())?;
    let folder = resolved.folder.as_deref();

    println!("reading {name} at commit {}", resolved.commit);

    let mut report = Report::new();
    let mut autorun = AutoRun::default();
    let mut dependencies = Dependencies::default();
    let mut files = 0;
    let mut bytes = 0;

    let summary = git::read_commit(
        source,
        &resolved.commit,
        folder,
        &Limits::default(),
        |file| {
            files += 1;
            bytes += file.contents.len() as u64;

            network::scan(&file, &mut report);
            behavior::scan(&file, &mut report);
            opaque::scan(&file, &mut report);
            obfuscation::scan(&file, &mut report);
            hidden::scan(&file, &mut report);
                autorun.scan(&file);
            dependencies.scan(&file, &mut report);
            },
    )?;

    for skipped in &summary.skipped {
        report.add_detail(
            Kind::NotRead,
            skipped.path.raw(),
            &format!("too large ({} bytes)", skipped.size),
        );
    }
    report.note_not_listed(summary.skipped_total - summary.skipped.len() as u64);
    links::report_links(&summary.links, &mut report);
    for submodule in &summary.submodules {
        report.add_detail(
            Kind::Submodule,
            submodule.path.raw(),
            &format!("pinned at commit {}", submodule.commit),
        );
    }

    if let Some(folder) = folder {
        let found_anything = files > 0
            || summary.skipped_total > 0
            || !summary.links.is_empty()
            || !summary.submodules.is_empty();
        if !found_anything {
            return Err(format!("this commit has nothing at: {folder}").into());
        }
    }

    autorun.finish(&mut report);

    println!("checking {} packages against OSV", dependencies.len());
    let packages_checked = dependencies.check_all(&mut report);

    let info = ScanInfo {
        name: &name,
        commit: Some(&resolved.commit),
        reference: (resolved.reference_kind == "branch" || resolved.reference_kind == "tag")
            .then_some((resolved.reference_kind, resolved.reference.as_str())),
        path: folder,
        files,
        bytes,
        packages_checked,
    };

    print!("\n{}", report.render(&info, Palette::for_terminal()));

    match saved::save(&report.render(&info, &PLAIN)) {
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
    Ok(report.has_findings())
}
