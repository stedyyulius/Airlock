# Airlock

Check a repository for malicious code before it reaches your machine.

Paste a repo URL, and Airlock reads the repository in memory and lists what it finds,
so you can decide. It never clones the repository, saves it to your disk, or
runs any of its code.

> **Status: early development.** Airlock can flag known malicious packages and
> dangerous behavior, but it can't prove that code is safe, and it never says
> so. Do not rely on it alone to decide whether code is safe.

## Install

Download the program for your computer and run it. It's one file, and you don't
need Rust or anything else installed.

| Computer | File |
|---|---|
| Linux, Intel or AMD | `airlock-linux-x86_64` |
| Linux, ARM | `airlock-linux-arm64` |
| Mac, Apple silicon | `airlock-macos-arm64` |
| Mac, Intel | `airlock-macos-x86_64` |
| Windows | `airlock-windows-x86_64.exe` |

On Linux or a Mac, swapping in the right file name:

```sh
curl -fsSL -o airlock https://github.com/stedyyulius/Airlock/releases/latest/download/airlock-linux-x86_64
chmod +x airlock
sudo mv airlock /usr/local/bin/
```

On Windows, download the file from the
[latest release](https://github.com/stedyyulius/Airlock/releases/latest), rename it
`airlock.exe`, and put it in a folder on your `PATH`.

There's no install script to pipe into a shell on purpose, since that's one of the
things Airlock warns about. To check that a download was really built from this
repository, run `gh attestation verify airlock --repo stedyyulius/Airlock`.

Other ways to get it:

```sh
# With Rust. The package is airlock-scan, and the command is airlock.
cargo install airlock-scan --locked

# With Docker. The image holds only the Airlock program.
docker run --rm -t --read-only --cap-drop=ALL ghcr.io/stedyyulius/airlock scan https://github.com/owner/repo
```

The Docker image doesn't save a copy of the report. To keep one, leave out `-t` and
add `> report.txt` to the end of the command.

## Usage

```sh
airlock scan https://github.com/owner/repo
airlock scan https://gitlab.com/group/subgroup/project
airlock scan https://bitbucket.org/workspace/repo
airlock scan https://github.com/owner/repo/tree/main/some-folder
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

`cargo install airlock` and `npm install airlock` install unrelated projects that
happen to share the name, so use the package name above.

Your antivirus might flag Airlock, because the program contains text describing
what malware does, in order to search for it. Windows Defender did this during
development. Read the source and build it yourself if you're unsure, and please
open an issue if it happens. Don't turn your antivirus off for this.

## How it works

1. **It finds the newest version.** A commit is a saved snapshot of every file in a
   repository. A link alone doesn't say which snapshot you mean, so Airlock asks
   the host which commit it points to, the same first step `git clone` takes.
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

## How it's been tested

Airlock has been run against
[rubenmarcus/malicious-repositories](https://github.com/rubenmarcus/malicious-repositories),
a public collection of real malicious projects, many of them from fake job interview
scams.

> **This is real malware. Don't clone, install, open or run any of it.** Airlock is
> safe to point at it, because it only reads the files in memory:
>
> ```sh
> airlock scan https://github.com/rubenmarcus/malicious-repositories/tree/main/munity-game
> ```

Results for v0.1.2, on commit
[`dc82f33`](https://github.com/rubenmarcus/malicious-repositories/tree/dc82f332dae0f4e9ea6bdc1d8341c7743c59913f) of
the collection. All 14 projects containing code get a DANGER, and the 15th,
`scammer-documents`, has no code to run.

| Project | What Airlock flags |
|---|---|
| `0xnfteth-horsepowerfi` | Hides where it connects to, in `server/controllers/userController.js` |
| `challenge-experiment-module` | Malicious package `rest-icon-orchestrator` |
| `coinpool-rental-platform1.0` | Malicious package `process-log` |
| `DEX-staking-project-ultrax` | Malicious package `vite-tsconsole-log` |
| `erc20-token-dapp` | Malicious packages `cdn-icon-fetch` and `cdn-icon-fetcher` |
| `golden-city` | Runs what it downloads, in `backend/controllers/userController.js` |
| `multify_staking` | Obfuscated `next.config.js`, which runs automatically |
| `munity-game` | Obfuscated code 908 spaces off screen, in `server/routes/paymentRoute.js` |
| `real_estate` | Runs what it downloads, in `server/controllers/userController.js` |
| `real_estate_new` | Runs what it downloads, in `server/controllers/paymentController.js` |
| `real-estate-rental-platform` | Runs what it downloads, in `server/controllers/paymentController.js` |
| `sarostech-assessment` | Runs what it downloads, in `server/config/getContract.js` |
| `trend-dev-preproduction` | Runs what it downloads, in `backend/controller.js` |
| `web3game` | Runs what it downloads, plus an obfuscated `server/middlewares/helpers/error.js` |

How far to trust this:

- **It doesn't show Airlock catches all malware.** A DANGER means it found at least
  one real sign, which isn't always every malicious part of a project.
- **Airlock was tuned on this collection.** Its checks were improved after missing
  two of these projects, so expect it to do less well on malware it hasn't seen.

It was also run on 47 widely used open source projects to look for false alarms. 33
got no DANGER. Most of the others really do what's flagged, such as piping a download
into a shell, or use a package listed as malicious, and a few are still false alarms.

Scanning Airlock's own repository shows many DANGER findings, because its source
contains the patterns it searches for. They're expected, and there's deliberately no
exception for this repository, because an attacker could copy its name.

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

A virtual machine is the safer choice for that. A Docker container still has the
network, plus any folders and secrets you give it, unless you turn those off. That
applies to running a suspicious repository. Airlock never runs what it scans.

- **What code downloads when it runs.** Airlock can flag the download, but the
  thing being downloaded isn't in the repository.
- **The code inside dependencies.** Packages are looked up by name and version, so
  a malicious package nobody has reported yet won't appear.
- **Submodules.** They're other repositories, so they're listed but not scanned.
- **Files attached to releases.** They're uploaded separately from the code, so a
  repository with clean code can still offer a malicious download.
- **Compiled programs.** They're listed, but not analyzed.
- **New tricks.** Airlock recognizes known patterns and doesn't understand what
  code really does. Attackers can read this source too.
- **Later commits.** The report covers one commit, and it names that commit.

## Planned checks

- Reading the code inside dependencies
- Following submodules
- Understanding more of what code does, rather than matching text

## Help improve it

Airlock gets better from real examples, so please
[open an issue](https://github.com/stedyyulius/Airlock/issues) if you know of:

- A malicious repository, package or trick that Airlock misses
- A false alarm on honest code

Send a link and the Airlock version, and say what the problem is. Please don't attach
malware or paste its code into the issue, and don't open it on a computer you care
about. If you're not sure it's malicious, say so.

## License

Licensed under either of

- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT License](LICENSE-MIT)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this work by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.
