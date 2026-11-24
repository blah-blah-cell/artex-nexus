use std::cmp::Ordering;

/// Parsed comparable version supporting semver, v-prefixed tags, and dotted numeric tuples.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ParsedVersion {
    pub nums: Vec<u64>,
    pub prerelease: Option<String>,
}

impl ParsedVersion {
    pub fn parse(raw: &str) -> Option<Self> {
        let trimmed = raw
            .trim()
            .trim_start_matches(['v', 'V', '=', '^', '~', '>', '<', ' ']);
        if trimmed.is_empty() || trimmed == "*" {
            return None;
        }
        // Strip build metadata (+...)
        let no_build = trimmed.split('+').next().unwrap_or(trimmed);
        let mut parts = no_build.splitn(2, '-');
        let core = parts.next().unwrap_or("");
        let prerelease = parts.next().map(|s| s.to_lowercase());

        let mut nums = Vec::new();
        for seg in core.split('.') {
            let digits: String = seg.chars().take_while(|c| c.is_ascii_digit()).collect();
            if digits.is_empty() {
                break;
            }
            nums.push(digits.parse::<u64>().ok()?);
        }
        if nums.is_empty() {
            return None;
        }
        Some(Self { nums, prerelease })
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
        // Per SemVer: 1.0.0-alpha < 1.0.0
        match (&self.prerelease, &other.prerelease) {
            (None, None) => Ordering::Equal,
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (Some(a), Some(b)) => a.cmp(b),
        }
    }
}

impl PartialOrd for ParsedVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Evaluate whether `installed` falls inside OSV range `[introduced, fixed)`.
/// Returns `Some(true)` if vulnerable, `Some(false)` if safe, `None` if unparseable.
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
        // No upper bound recorded -> affected from introduced onwards
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
}
