//! Spots package names that look like popular ones.
//!
//! A new typosquat isn't in any malware database yet, because nobody has reported
//! it, so a name like `axois` gets past that check. Comparing names against the
//! popular packages needs no database, and only ever produces a warning, because
//! plenty of honest packages have similar names.

/// Popular names are usually what attackers imitate, and an exact match means
/// the name is the real thing rather than an imitation.
const NPM: [&str; 96] = [
    "react",
    "react-dom",
    "react-router",
    "react-router-dom",
    "next",
    "vue",
    "angular",
    "svelte",
    "express",
    "fastify",
    "koa",
    "axios",
    "node-fetch",
    "request",
    "got",
    "superagent",
    "lodash",
    "underscore",
    "moment",
    "dayjs",
    "date-fns",
    "chalk",
    "colors",
    "color",
    "commander",
    "yargs",
    "minimist",
    "inquirer",
    "debug",
    "dotenv",
    "cross-env",
    "nodemon",
    "webpack",
    "webpack-cli",
    "rollup",
    "esbuild",
    "vite",
    "parcel",
    "babel-core",
    "typescript",
    "ts-node",
    "tslib",
    "eslint",
    "tslint",
    "prettier",
    "jest",
    "mocha",
    "chai",
    "sinon",
    "cypress",
    "playwright",
    "puppeteer",
    "tailwindcss",
    "postcss",
    "autoprefixer",
    "sass",
    "styled-components",
    "redux",
    "react-redux",
    "zustand",
    "mongoose",
    "mongodb",
    "mysql",
    "mysql2",
    "sequelize",
    "prisma",
    "redis",
    "ioredis",
    "socket.io",
    "socket.io-client",
    "bcrypt",
    "bcryptjs",
    "jsonwebtoken",
    "passport",
    "cors",
    "helmet",
    "body-parser",
    "cookie-parser",
    "multer",
    "uuid",
    "nanoid",
    "semver",
    "glob",
    "rimraf",
    "mkdirp",
    "fs-extra",
    "chokidar",
    "async",
    "ethers",
    "web3",
    "viem",
    "wagmi",
    "hardhat",
    "solc",
    "openai",
    "bitcoinjs-lib",
];
const PYPI: [&str; 56] = [
    "requests",
    "urllib3",
    "httpx",
    "aiohttp",
    "numpy",
    "pandas",
    "scipy",
    "matplotlib",
    "scikit-learn",
    "tensorflow",
    "torch",
    "keras",
    "transformers",
    "pillow",
    "opencv-python",
    "django",
    "flask",
    "fastapi",
    "uvicorn",
    "gunicorn",
    "celery",
    "pydantic",
    "sqlalchemy",
    "psycopg2",
    "pymysql",
    "redis",
    "boto3",
    "botocore",
    "cryptography",
    "pycryptodome",
    "paramiko",
    "pyyaml",
    "toml",
    "click",
    "rich",
    "tqdm",
    "colorama",
    "jinja2",
    "beautifulsoup4",
    "lxml",
    "selenium",
    "scrapy",
    "pytest",
    "setuptools",
    "wheel",
    "certifi",
    "idna",
    "python-dateutil",
    "python-dotenv",
    "openai",
    "anthropic",
    "langchain",
    "web3",
    "eth-account",
    "solana",
    "discord.py",
];
/// Short names are a letter away from far too many honest packages.
const MIN_NAME_CHARS: usize = 5;

/// Which popular package a name imitates, if it seems to imitate one.
pub fn imitated(ecosystem: &str, name: &str) -> Option<&'static str> {
    let popular: &[&'static str] = match ecosystem {
        "npm" => &NPM,
        "PyPI" => &PYPI,
        _ => return None,
    };
    let name = name.to_ascii_lowercase();
    if name.chars().count() < MIN_NAME_CHARS || popular.contains(&name.as_str()) {
        return None;
    }
    let plain = without_separators(&name);

    popular.iter().copied().find(|known| {
        known.chars().count() >= MIN_NAME_CHARS
            && (plain == without_separators(known) || is_one_typo_apart(&name, known))
    })
}

/// `cross-env` and `crossenv` read the same.
fn without_separators(name: &str) -> String {
    name.chars()
        .filter(|c| !matches!(c, '-' | '_' | '.'))
        .collect()
}

/// Whether one letter added, removed, changed or swapped with its neighbor turns
/// one name into the other.
fn is_one_typo_apart(a: &str, b: &str) -> bool {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (shorter, longer) = if a.len() <= b.len() {
        (&a, &b)
    } else {
        (&b, &a)
    };

    if longer.len() - shorter.len() > 1 {
        return false;
    }
    let start = shorter
        .iter()
        .zip(longer.iter())
        .take_while(|(x, y)| x == y)
        .count();
    if shorter.len() == longer.len() {
        if start == shorter.len() {
            return false;
        }
        let changed = shorter[start + 1..] == longer[start + 1..];
        let swapped = start + 1 < shorter.len()
            && shorter[start] == longer[start + 1]
            && shorter[start + 1] == longer[start]
            && shorter[start + 2..] == longer[start + 2..];
        changed || swapped
    } else {
        shorter[start..] == longer[start + 1..]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spots_common_kinds_of_typo() {
        for (name, expected) in [
            ("axois", "axios"),
            ("axioss", "axios"),
            ("lodahs", "lodash"),
            ("lodas", "lodash"),
            ("expres", "express"),
            ("mongose", "mongoose"),
            ("crossenv", "cross-env"),
            ("cross_env", "cross-env"),
            ("jsonwebtokn", "jsonwebtoken"),
            ("Webpackk", "webpack"),
        ] {
            assert_eq!(imitated("npm", name), Some(expected), "{name}");
        }
        for (name, expected) in [
            ("reqeusts", "requests"),
            ("requets", "requests"),
            ("python_dotenv", "python-dotenv"),
            ("beautifulsoup", "beautifulsoup4"),
        ] {
            assert_eq!(imitated("PyPI", name), Some(expected), "{name}");
        }
    }

    #[test]
    fn real_names_and_unrelated_names_are_fine() {
        for name in [
            "axios",
            "mysql2",
            "colors",
            "tslint",
            "eslint",
            "my-cool-package",
            "lodash-es",
            "react-dnd",
            // Too short to tell.
            "vuex",
            "ms",
        ] {
            assert_eq!(imitated("npm", name), None, "{name}");
        }
    }

    #[test]
    fn other_ecosystems_are_not_compared() {
        assert_eq!(imitated("crates.io", "axois"), None);
    }

    #[test]
    fn hostile_names_do_not_panic() {
        for name in ["", "é", "ééééé", "a", "\u{0}\u{0}\u{0}\u{0}\u{0}"] {
            imitated("npm", name);
        }
        imitated("npm", &"a".repeat(1_000_000));
    }
}
