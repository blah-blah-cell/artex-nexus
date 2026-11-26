use std::cmp::Ordering;

/// Comparable version supporting SemVer 2.0.0, optional `v` prefixes, dotted numeric tuples,
/// Maven release qualifiers (`.RELEASE`, `.Final`, `.GA`, `.RC1`, `.M1`, `.SNAPSHOT`), and
/// Python PEP 440 suffixes (`1.0a1`, `1.0b2`, `1.0rc1`, `1.0.dev1`, `1.0.post1`).
/// Rejects range operators (`^`, `~`, `>`, `<`, `*`, `|`) and git commit hashes.
#[derive(Debug, Clone, Eq)]
pub struct ParsedVersion {
    pub nums: Vec<u64>,
    pub prerelease: Option<String>,
    pub post: Option<u64>,
}

impl PartialEq for ParsedVersion {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

fn split_numeric_prefix(seg: &str) -> Option<(u64, &str)> {
    let digit_end = seg
        .bytes()
        .position(|b| !b.is_ascii_digit())
        .unwrap_or(seg.len());
    if digit_end == 0 {
        return None;
    }
    let num = seg[..digit_end].parse::<u64>().ok()?;
    Some((num, &seg[digit_end..]))
}

fn parse_pep440_or_maven_tail(tail: &str) -> Option<(Option<String>, Option<u64>)> {
    let low = tail.trim().to_ascii_lowercase();
    if low.is_empty() {
        return Some((None, None));
    }
    if matches!(low.as_str(), "release" | "final" | "ga") {
        return Some((None, None));
    }
    if let Some(rest) = low.strip_prefix("post") {
        let rest = rest.trim_start_matches(['.', '-', '_']);
        if rest.is_empty() {
            return Some((None, Some(0)));
        }
        if let Ok(n) = rest.parse::<u64>() {
            return Some((None, Some(n)));
        }
        return None;
    }
    if let Some(rest) = low.strip_prefix("sp")
        && let Ok(n) = rest.parse::<u64>()
    {
        return Some((None, Some(n)));
    }
    // PEP 440 / Maven pre-release qualifiers
    let normalized = if let Some(rest) = low.strip_prefix("alpha") {
        format!("alpha.{}", rest.trim_start_matches(['.', '-']))
    } else if let Some(rest) = low.strip_prefix("beta") {
        format!("beta.{}", rest.trim_start_matches(['.', '-']))
    } else if let Some(rest) = low.strip_prefix("rc") {
        format!("rc.{}", rest.trim_start_matches(['.', '-']))
    } else if let Some(rest) = low.strip_prefix("dev") {
        format!("0dev.{}", rest.trim_start_matches(['.', '-']))
    } else if low == "snapshot" {
        "0snapshot".to_string()
    } else if let Some(rest) = low.strip_prefix('a')
        && !rest.is_empty()
        && rest.bytes().all(|b| b.is_ascii_digit())
    {
        format!("alpha.{rest}")
    } else if let Some(rest) = low.strip_prefix('b')
        && !rest.is_empty()
        && rest.bytes().all(|b| b.is_ascii_digit())
    {
        format!("beta.{rest}")
    } else if let Some(rest) = low.strip_prefix('m')
        && !rest.is_empty()
        && rest.bytes().all(|b| b.is_ascii_digit())
    {
        format!("m.{rest}")
    } else {
        return None;
    };
    Some((Some(normalized.trim_end_matches('.').to_string()), None))
}

impl ParsedVersion {
    pub fn parse(raw: &str) -> Option<Self> {
        let mut s = raw.trim();
        if s.is_empty() {
            return None;
        }
        // Reject range expressions instead of pretending a lower bound is an installed version.
        if s.contains(['^', '~', '>', '<', '*', '|', ' ']) {
            return None;
        }
        s = s.trim_start_matches('=');
        if let Some(rest) = s.strip_prefix('v').or_else(|| s.strip_prefix('V')) {
            s = rest;
        }
        if s.is_empty() {
            return None;
        }
        // Strip build metadata (+...)
        let no_build = s.split('+').next().unwrap_or(s);
        let mut parts = no_build.splitn(2, '-');
        let core = parts.next().unwrap_or("");
        let mut prerelease = parts
            .next()
            .map(|p| p.trim().to_ascii_lowercase())
            .filter(|p| !p.is_empty());
        let mut post: Option<u64> = None;

        // Handle Maven dash qualifiers like 1.2.3-RELEASE / 1.2.3-Final / 1.2.3-GA / 1.2.3-SP1
        if let Some(ref pre) = prerelease
            && matches!(pre.as_str(), "release" | "final" | "ga")
        {
            prerelease = None;
        } else if let Some(ref pre) = prerelease
            && let Some(rest) = pre.strip_prefix("post")
            && let Ok(n) = rest.trim_start_matches(['.', '-']).parse::<u64>()
        {
            prerelease = None;
            post = Some(n);
        }

        // Reject bare hex git commit hashes (e.g., 9f8e7d6c5b4a3210) that have no dots and contain hex letters.
        if !core.contains('.')
            && core.len() >= 7
            && core.bytes().all(|b| b.is_ascii_hexdigit())
            && !core.bytes().all(|b| b.is_ascii_digit())
        {
            return None;
        }

        let segs: Vec<&str> = core.split('.').collect();
        let mut nums = Vec::new();
        for (idx, seg) in segs.iter().enumerate() {
            if seg.is_empty() {
                return None;
            }
            if seg.bytes().all(|b| b.is_ascii_digit()) {
                nums.push(seg.parse::<u64>().ok()?);
                continue;
            }
            // Only the final segment may carry a PEP 440 or Maven qualifier (e.g., 1.0a1, 1.0.post1, 1.2.3.RELEASE).
            if idx + 1 != segs.len() {
                return None;
            }
            if let Some((n, rest)) = split_numeric_prefix(seg) {
                nums.push(n);
                let (pre_q, post_q) = parse_pep440_or_maven_tail(rest)?;
                if prerelease.is_none() {
                    prerelease = pre_q;
                }
                if post.is_none() {
                    post = post_q;
                }
            } else {
                if nums.is_empty() {
                    return None;
                }
                let (pre_q, post_q) = parse_pep440_or_maven_tail(seg)?;
                if prerelease.is_none() {
                    prerelease = pre_q;
                }
                if post.is_none() {
                    post = post_q;
                }
            }
        }
        if nums.is_empty() {
            return None;
        }
        Some(Self {
            nums,
            prerelease,
            post,
        })
    }
}

fn cmp_prerelease(a: &str, b: &str) -> Ordering {
    let mut ai = a.split('.');
    let mut bi = b.split('.');
    loop {
        match (ai.next(), bi.next()) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(sa), Some(sb)) => {
                let ord = match (sa.parse::<u64>(), sb.parse::<u64>()) {
                    (Ok(na), Ok(nb)) => na.cmp(&nb),
                    // Per SemVer 2.0.0 §11.4.3: numeric identifiers sort lower than non-numeric.
                    (Ok(_), Err(_)) => Ordering::Less,
                    (Err(_), Ok(_)) => Ordering::Greater,
                    (Err(_), Err(_)) => sa.cmp(sb),
                };
                if ord != Ordering::Equal {
                    return ord;
                }
            }
        }
    }
}

impl Ord for ParsedVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        let max_len = self.nums.len().max(other.nums.len());
        for i in 0..max_len {
            let a = *self.nums.get(i).unwrap_or(&0);
            let b = *other.nums.get(i).unwrap_or(&0);
            match a.cmp(&b) {
                Ordering::Equal => continue,
                ord => return ord,
            }
        }
        match (&self.prerelease, &other.prerelease) {
            (None, None) => {}
            (Some(_), None) => return Ordering::Less,
            (None, Some(_)) => return Ordering::Greater,
            (Some(a), Some(b)) => {
                let ord = cmp_prerelease(a, b);
                if ord != Ordering::Equal {
                    return ord;
                }
            }
        }
        self.post.cmp(&other.post)
    }
}

impl PartialOrd for ParsedVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Evaluates whether `installed` falls inside OSV range `[introduced, fixed)`.
/// Returns `None` if any bound is unparseable (for example, a raw git commit hash).
pub fn is_version_affected(installed: &str, introduced: &str, fixed: &str) -> Option<bool> {
    let inst = ParsedVersion::parse(installed)?;

    let meets_intro = if introduced.trim().is_empty() || introduced.trim() == "0" {
        true
    } else {
        inst >= ParsedVersion::parse(introduced)?
    };
    if !meets_intro {
        return Some(false);
    }

    let f = fixed.trim();
    if f.is_empty() {
        return Some(true);
    }
    if let Some(last_aff) = f.strip_prefix("<=") {
        let la = ParsedVersion::parse(last_aff)?;
        return Some(inst <= la);
    }
    let fix = ParsedVersion::parse(f)?;
    Some(inst < fix)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evaluates_semver_and_osv_ranges() {
        assert_eq!(is_version_affected("4.17.15", "0", "4.17.21"), Some(true));
        assert_eq!(is_version_affected("4.17.21", "0", "4.17.21"), Some(false));
        assert_eq!(
            is_version_affected("4.18.0", "4.0.0", "4.18.0"),
            Some(false)
        );
        assert_eq!(is_version_affected("3.9.0", "4.0.0", "4.18.0"), Some(false));
        assert_eq!(
            is_version_affected("v1.2.3-rc1", "1.2.0", "1.2.3"),
            Some(true)
        );
        assert_eq!(is_version_affected("1.2.3", "1.2.0", "1.2.3"), Some(false));
    }

    #[test]
    fn supports_maven_and_pep440_suffixes() {
        assert_eq!(
            ParsedVersion::parse("1.2.3.RELEASE"),
            ParsedVersion::parse("1.2.3")
        );
        assert_eq!(
            ParsedVersion::parse("2.0.1.Final"),
            ParsedVersion::parse("2.0.1")
        );
        assert_eq!(
            is_version_affected("1.2.3.RELEASE", "1.0.0", "1.2.4"),
            Some(true)
        );
        assert_eq!(is_version_affected("1.0a1", "0", "1.0.0"), Some(true));
        assert!(ParsedVersion::parse("1.0a1").unwrap() < ParsedVersion::parse("1.0").unwrap());
        assert!(ParsedVersion::parse("1.0.post1").unwrap() > ParsedVersion::parse("1.0").unwrap());
        assert_eq!(is_version_affected("1.0.post1", "0", "1.0"), Some(false));
        assert_eq!(is_version_affected("1.0.post1", "0", "1.1"), Some(true));
    }

    #[test]
    fn rejects_git_hashes_and_ranges_and_orders_prereleases() {
        // OSV git commit hashes starting with digits must not parse as numeric versions.
        assert_eq!(ParsedVersion::parse("9f8e7d6c5b4a3210"), None);
        assert_eq!(
            is_version_affected("1.0.0", "9f8e7d6c5b4a3210", "2.0.0"),
            None
        );

        // Version range operators must not be silently coerced into exact versions.
        assert_eq!(ParsedVersion::parse(">=4.17.21"), None);
        assert_eq!(ParsedVersion::parse("^4.17.15"), None);
        assert_eq!(ParsedVersion::parse("~1.2.3"), None);

        // SemVer 2.0.0 numeric prerelease ordering: alpha.2 < alpha.10.
        let a2 = ParsedVersion::parse("1.0.0-alpha.2").unwrap();
        let a10 = ParsedVersion::parse("1.0.0-alpha.10").unwrap();
        assert!(a2 < a10);
        assert_eq!(
            is_version_affected("1.0.0-alpha.2", "0", "1.0.0-alpha.10"),
            Some(true)
        );
        assert_eq!(
            is_version_affected("1.0.0-alpha.10", "0", "1.0.0-alpha.2"),
            Some(false)
        );
    }
}
