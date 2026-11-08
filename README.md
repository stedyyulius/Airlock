# Airlock

Check a repository for malicious code before it reaches your machine.

Paste a URL, and Airlock reads the repository in memory and lists what it finds,
so you can decide. It never clones the repository, saves it to your disk, or
runs any of its code.

> **Status: early development.** Airlock lists the network addresses and
> unreadable files it finds, but gives no safety verdict yet. Do not rely on it
> to decide whether code is safe.

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

Airlock is not published on any package registry yet. `cargo install airlock`
and `npm install airlock` install unrelated projects that happen to share the
name, so build from this repository.

## Planned checks

- Known malicious dependencies
- Code that runs automatically on install, build or when a folder is opened
- Obfuscated code, and code that downloads and runs other code
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
