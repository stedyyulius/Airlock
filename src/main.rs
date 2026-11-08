mod source;

use source::Source;
use std::process::ExitCode;

// 0 and 1 are reserved for scan verdicts, so usage errors get their own code.
const EXIT_USAGE: u8 = 2;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let [command, url] = args.as_slice() else {
        eprintln!("usage: airlock scan <repository-url>");
        return ExitCode::from(EXIT_USAGE);
    };
    if command != "scan" {
        eprintln!("unknown command: {command}");
        eprintln!("usage: airlock scan <repository-url>");
        return ExitCode::from(EXIT_USAGE);
    }

    match Source::parse(url) {
        Ok(source) => {
            println!("would download: {}", source.archive_url());
            println!("scanning is not implemented yet");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(EXIT_USAGE)
        }
    }
}
