# Airlock

Check a repository for malicious code before it reaches your machine.

Paste a URL, and Airlock reads the repository in memory and lists what it finds,
so you can decide. It never clones the repository, saves it to your disk, or
runs any of its code.

> **Status: early development.** Airlock can flag known malicious packages and
> dangerous behavior, but it can't prove that code is safe, and it never says
> so. Do not rely on it alone to decide whether code is safe.

## Usage

```sh
cargo run -- scan https://github.com/owner/repo
cargo run -- scan https://gitlab.com/group/subgroup/project
cargo run -- scan https://bitbucket.org/workspace/repo
cargo run -- scan https://github.com/owner/repo/tree/main/some-folder
```

Airlock scans public repositories on these three sites. Private repositories and
self-hosted servers are not supported yet. A link to a branch or folder scans only
that branch or folder.

The report prints in your terminal, and the last line shows where to find a copy
in a file, `~/.airlock/report.txt`. Each scan replaces that file, so copy it if
you want to keep it. It holds only Airlock's report, never the repository's files.

To check dependencies, Airlock sends package names and versions to the public
[OSV database](https://osv.dev). It sends nothing else from the repository.

The exit code is 0 if there was nothing to report, 1 if there are findings to
review, and 2 if the scan couldn't finish.

Airlock is not published on any package registry yet. `cargo install airlock`
and `npm install airlock` install unrelated projects that happen to share the
name, so build from this repository.

## What it reports

**DANGER:** behavior that could harm your computer.

- Known malicious packages
- Code that downloads something and runs it
- Code that contacts the internet automatically when installed or opened
- Code that decodes hidden text and runs it
- Code that hides where it connects to
- Programs or archives disguised as another type of file

**WARNING:** not proven harmful, but check it.

- Other network calls and raw IP addresses
- Everything that runs automatically when installed or opened
- Dependencies with known security bugs
- Packages that have had malicious releases, when no exact version is set
- Anything Airlock couldn't read or check

**NOTE:** listed so you can see it, not checked for safety.

- Every other address in code, config, lockfiles and documentation

## Planned checks

- Obfuscated code
- Code that reads secrets and sends them elsewhere
- Suspicious packages, such as lookalikes of popular names

A scan can reduce your risk, but it can't prove that code is safe. Run code you
don't trust in an isolated environment, even if it scans clean.

## License

Licensed under either of

- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT License](LICENSE-MIT)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this work by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.
