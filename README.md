# Airlock

Check a repository for malicious code before it reaches your machine.

Paste a URL, and Airlock reads the repository in memory and lists what it finds,
so you can decide. It never clones the repository, saves it to your disk, or
runs any of its code.

> **Status: early development.** Airlock can flag known malicious packages and
> dangerous behavior, but it can't prove that code is safe, and it never says
> so. Do not rely on it alone to decide whether code is safe.

## Usage

Airlock has no published releases yet, so for now you build it from this
repository, which takes [Rust](https://rustup.rs). Once releases exist, you'll be
able to download a single program and won't need Rust.

```sh
git clone https://github.com/stedyyulius/Airlock
cd Airlock
cargo build --release --locked
```

Then scan a repository, branch or folder:

```sh
./target/release/airlock scan https://github.com/owner/repo
./target/release/airlock scan https://gitlab.com/group/subgroup/project
./target/release/airlock scan https://bitbucket.org/workspace/repo
./target/release/airlock scan https://github.com/owner/repo/tree/main/some-folder
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

Your antivirus might flag your build, because the program contains text describing
what malware does, in order to search for it. Windows Defender did this during
development. Read the source and build it yourself if you're unsure, and please
open an issue if it happens. Don't turn your antivirus off for this.

## How it works

1. **It finds the commit.** Airlock asks the host which commit your link means,
   the same first step `git clone` takes.
2. **It reads that commit into memory.** It uses the git protocol over HTTPS, so
   it receives exactly what `git clone` would. It doesn't use the `.tar.gz` that
   hosts offer for download, because one line in a repository's `.gitattributes`
   can leave files out of that. Git names everything by a hash of its contents,
   and Airlock checks those hashes, so what it reads really is that commit.
3. **It checks each file as text, then frees it.** Nothing is written to disk.
4. **It looks up the dependencies** in the OSV database, by name and version.
5. **It prints the report**, and that report is the only thing it saves.

### Why reading into memory is safe

A repository can only hurt you if something runs or opens it. Once files are on
disk, plenty of things can: `npm install` runs scripts, an editor runs tasks when
you open the folder, and a hostile archive can even write outside its own folder.
Bytes in memory are only data. Airlock never makes files, so none of that can
happen, and nothing is left behind.

The bytes are still hostile, so they can try to attack Airlock itself. Sizes are
capped so a small download can't expand until memory runs out, anything Airlock
prints is escaped so a file name can't send commands to your terminal, and
Airlock contains no `unsafe` Rust. A limit that would leave the scan incomplete
stops the scan with an error, rather than letting it look complete.

## What it reports

**DANGER:** behavior that could harm your computer.

- Known malicious packages
- Code that downloads something and runs it
- Code that runs by itself on install, open or build, and contacts the internet
  or is disguised
- Code disguised so people can't read it, or hidden off the screen
- Code, commands and addresses hidden inside encoded text
- Invisible characters that change what the text says
- Code that collects passwords, keys or wallets and contacts the internet
- Code that gives someone remote control, destroys files, turns off security
  protections or mines cryptocurrency
- Programs, archives and scripts disguised as another type of file
- Packages installed from an unsafe address

**WARNING:** not proven harmful, but check it.

- Other network calls and raw IP addresses
- Everything that runs automatically when installed or opened, or when you build,
  test or start the project
- Instructions that AI coding tools will read and may follow
- Packages from outside the normal registry, and names imitating popular ones
- Services often used to host malware or receive stolen data
- Code that reads secrets, stays on the computer, hides its window, covers its
  tracks or watches the keyboard, screen or clipboard
- Installed packages and submodules, which package checks don't cover
- Dependencies with known security bugs
- Anything Airlock couldn't read or check

**NOTE:** listed so you can see it, not checked for safety.

- Every other address in code, config, lockfiles and documentation
- Minified code

## What it can't see

A scan can reduce your risk, but it can't prove that code is safe. Run code you
don't trust in an isolated environment, even if it scans clean.

- **What code downloads when it runs.** Airlock can flag the download, but the
  thing being downloaded isn't in the repository.
- **The code inside dependencies.** Packages are looked up by name and version, so
  a malicious package nobody has reported yet won't appear.
- **Submodules.** They're other repositories, so they're listed but not scanned.
- **Compiled programs.** They're listed, but not analyzed.
- **New tricks.** Airlock recognizes known patterns and doesn't understand what
  code really does. Attackers can read this source too.
- **Later commits.** The report covers one commit, and it names that commit.

## Planned checks

- Reading the code inside dependencies
- Following submodules
- Understanding more of what code does, rather than matching text

## License

Licensed under either of

- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT License](LICENSE-MIT)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this work by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.
