use std::cmp::Ordering;

/// Comparable version supporting SemVer 2.0.0, optional `v` prefixes, and dotted numeric tuples.
/// Rejects range operators (`^`, `~`, `>`, `<`, `*`, `|`) and git commit hashes.
#[derive(Debug, Clone, Eq)]
pub struct ParsedVersion {
    pub nums: Vec<u64>,
    pub prerelease: Option<String>,
}

impl PartialEq for ParsedVersion {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
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
        let prerelease = parts
            .next()
            .map(|p| p.trim().to_lowercase())
            .filter(|p| !p.is_empty());

        let mut nums = Vec::new();
        for seg in core.split('.') {
            if seg.is_empty() || !seg.chars().all(|c| c.is_ascii_digit()) {
                return None;
            }
            nums.push(seg.parse::<u64>().ok()?);
        }
        if nums.is_empty() {
            return None;
        }
        Some(Self { nums, prerelease })
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
            (None, None) => Ordering::Equal,
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (Some(a), Some(b)) => cmp_prerelease(a, b),
        }
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
        assert_eq!(is_version_affected("4.18.0", "4.0.0", "4.18.0"), Some(false));
        assert_eq!(is_version_affected("3.9.0", "4.0.0", "4.18.0"), Some(false));
        assert_eq!(is_version_affected("v1.2.3-rc1", "1.2.0", "1.2.3"), Some(true));
        assert_eq!(is_version_affected("1.2.3", "1.2.0", "1.2.3"), Some(false));
    }

    #[test]
    fn rejects_git_hashes_and_ranges_and_orders_prereleases() {
        // OSV git commit hashes starting with digits must not parse as numeric versions.
        assert_eq!(ParsedVersion::parse("9f8e7d6c5b4a3210"), None);
        assert_eq!(is_version_affected("1.0.0", "9f8e7d6c5b4a3210", "2.0.0"), None);

        // Version range operators must not be silently coerced into exact versions.
        assert_eq!(ParsedVersion::parse(">=4.17.21"), None);
        assert_eq!(ParsedVersion::parse("^4.17.15"), None);
        assert_eq!(ParsedVersion::parse("~1.2.3"), None);

        // SemVer 2.0.0 numeric prerelease ordering: alpha.2 < alpha.10.
        let a2 = ParsedVersion::parse("1.0.0-alpha.2").unwrap();
        let a10 = ParsedVersion::parse("1.0.0-alpha.10").unwrap();
        assert!(a2 < a10);
        assert_eq!(is_version_affected("1.0.0-alpha.2", "0", "1.0.0-alpha.10"), Some(true));
        assert_eq!(is_version_affected("1.0.0-alpha.10", "0", "1.0.0-alpha.2"), Some(false));
    }
}
