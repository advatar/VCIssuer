//! Optional `.env` file support for local development, with **process-environment-wins** precedence.
//!
//! The crate is edition-2024 + `#![forbid(unsafe_code)]`, so `std::env::set_var` (which is `unsafe`
//! under edition 2024) is not available: we cannot inject a `.env` into the process environment.
//! Instead [`init`] parses the file once into a private store and [`var`] resolves a key by checking
//! the **process environment first** and only then the file. A `.env` therefore can never override a
//! variable already set by the launchd plist / systemd / shell export — trust anchors and secrets
//! provisioned by the operator always win over a developer file, and a stray or attacker-placed
//! `.env` in the working directory cannot shadow them.
//!
//! The file is read from `VCISSUER_DOTENV` if set, else `.env` in the current working directory.
//! Missing file ⇒ no-op (identical to reading the process environment directly), so production
//! deployments that set everything in the plist are unaffected and iProov still fails closed when
//! unconfigured. Values are never logged.

use std::collections::HashMap;
use std::sync::OnceLock;

static STORE: OnceLock<HashMap<String, String>> = OnceLock::new();

/// Parse `.env` contents into key/value pairs. Blank lines and `#` comments are skipped, an optional
/// `export ` prefix is stripped, the value is split on the first `=`, and a single pair of matching
/// surrounding quotes is removed. Malformed lines are skipped (fail-soft). Pure + unit-tested.
fn parse(contents: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for raw in contents.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() {
            continue;
        }
        let value = value.trim();
        let unquoted = if value.len() >= 2
            && ((value.starts_with('"') && value.ends_with('"'))
                || (value.starts_with('\'') && value.ends_with('\'')))
        {
            &value[1..value.len() - 1]
        } else {
            value
        };
        out.push((key.to_owned(), unquoted.to_owned()));
    }
    out
}

/// Read and parse a `.env` at `path`. `None` when the file is absent/unreadable (fail-soft).
fn read_and_parse(path: &str) -> Option<Vec<(String, String)>> {
    std::fs::read_to_string(path).ok().map(|c| parse(&c))
}

/// Load the `.env` file once into the store. Returns `(path, key_count)` when a file was read (for
/// the caller to log), or `None` when no file was present. Safe to call once; later calls are no-ops.
pub fn init() -> Option<(String, usize)> {
    let path = std::env::var("VCISSUER_DOTENV")
        .ok()
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| ".env".to_owned());
    let pairs = read_and_parse(&path);
    let map: HashMap<String, String> = pairs.clone().unwrap_or_default().into_iter().collect();
    let count = map.len();
    // First writer wins; ignore if already initialised (e.g. in tests).
    let _ = STORE.set(map);
    pairs.map(|_| (path, count))
}

/// Resolve a configuration key. The **process environment wins** (even if set to empty); only when a
/// key is entirely absent from the environment does the `.env` store supply a value. Behaves exactly
/// like `std::env::var(key).ok()` when no file was loaded.
#[must_use]
pub fn var(key: &str) -> Option<String> {
    match std::env::var(key) {
        Ok(value) => Some(value),
        // Present but not valid UTF-8: the variable IS set, so the file must NOT shadow it — return
        // None (caller treats it as unset/invalid) rather than falling back to the `.env` value.
        Err(std::env::VarError::NotUnicode(_)) => None,
        // Genuinely absent from the environment: only now may the dev `.env` supply a value.
        Err(std::env::VarError::NotPresent) => STORE.get().and_then(|map| map.get(key).cloned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_basic_pairs_and_skips_noise() {
        let pairs = parse(
            "# a comment\n\
             \n\
             ISSUER_URL=https://issuer.example\n\
             export MANDAMUS_IPROOV_API_KEY=abc123\n\
             # another\n\
             BAD LINE WITHOUT EQUALS\n\
             =novalue\n",
        );
        assert_eq!(
            pairs,
            vec![
                ("ISSUER_URL".to_owned(), "https://issuer.example".to_owned()),
                ("MANDAMUS_IPROOV_API_KEY".to_owned(), "abc123".to_owned()),
            ]
        );
    }

    #[test]
    fn strips_matching_surrounding_quotes_only() {
        let pairs = parse(
            "A=\"quoted value\"\n\
             B='single'\n\
             C=unquoted\n\
             D=\"unbalanced\n\
             E=mid\"dle\n",
        );
        assert_eq!(pairs[0], ("A".to_owned(), "quoted value".to_owned()));
        assert_eq!(pairs[1], ("B".to_owned(), "single".to_owned()));
        assert_eq!(pairs[2], ("C".to_owned(), "unquoted".to_owned()));
        // An unbalanced leading quote is preserved (not stripped).
        assert_eq!(pairs[3], ("D".to_owned(), "\"unbalanced".to_owned()));
        assert_eq!(pairs[4], ("E".to_owned(), "mid\"dle".to_owned()));
    }

    #[test]
    fn splits_on_first_equals_only() {
        // A base64/URL value containing '=' is preserved intact.
        let pairs = parse("MANDAMUS_IPROOV_BASE_URL=https://h/api/v2?x=1&y=2\n");
        assert_eq!(
            pairs[0],
            (
                "MANDAMUS_IPROOV_BASE_URL".to_owned(),
                "https://h/api/v2?x=1&y=2".to_owned()
            )
        );
    }

    #[test]
    fn var_falls_back_to_nothing_for_unset_key_without_file() {
        // A key set in neither the process env nor a loaded file resolves to None.
        assert!(var("VCISSUER_DEFINITELY_UNSET_KEY_9Z").is_none());
    }

    #[test]
    fn read_and_parse_round_trips_a_real_file_and_reports_absence() {
        let path = std::env::temp_dir().join(format!(
            "vcissuer-env-file-{}-{}.env",
            std::process::id(),
            line!()
        ));
        std::fs::write(
            &path,
            "# smoke\nISSUER_URL=https://issuer.example\nexport MANDAMUS_IPROOV_SECRET='shh'\n",
        )
        .expect("write temp .env");
        let pairs = read_and_parse(path.to_str().unwrap()).expect("file present");
        assert_eq!(
            pairs,
            vec![
                ("ISSUER_URL".to_owned(), "https://issuer.example".to_owned()),
                ("MANDAMUS_IPROOV_SECRET".to_owned(), "shh".to_owned()),
            ]
        );
        std::fs::remove_file(&path).ok();
        // A missing file is fail-soft (None), never a panic.
        assert!(read_and_parse(path.to_str().unwrap()).is_none());
    }
}
