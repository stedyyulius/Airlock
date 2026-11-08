# Airlock

Check a repository for malicious code before it reaches your machine.

Paste a URL, and Airlock reads the repository in memory without installing or
running anything.

> **Status: early development.** Airlock does not scan anything yet. Do not rely
> on it to decide whether code is safe.

## Usage

```sh
cargo run -- scan https://github.com/owner/repo
```

## Planned checks

- Known malicious dependencies
- Code that runs automatically on install, build or when a folder is opened
- Obfuscated code, and code that downloads and runs other code
- Code that reads secrets and sends them elsewhere
- Suspicious packages, such as lookalikes of popular names

GitHub comes first, with GitLab and Bitbucket to follow.

A scan can reduce your risk, but it can't prove that code is safe. Run code you
don't trust in an isolated environment, even if it scans clean.
