export interface CveStats {
  metadata?: Record<string, string>;
}

export interface CveResult {
  cve_id: string;
  cvss_score?: number;
  cvss_severity?: string;
  is_kev?: boolean;
  exploit_maturity?: string;
  title?: string;
  summary?: string;
  excerpt?: string;
  source?: string;
  url?: string;
}

export interface CveDetail {
  found: boolean;
  cve_id: string;
  cvss_score?: number;
  cvss_severity?: string;
  cvss_vector?: string;
  epss_score?: number;
  is_kev?: boolean;
  title?: string;
  description?: string;
  cwes?: string[];
  packages?: {
    ecosystem: string;
    package_name: string;
    introduced_ver: string;
    fixed_ver: string;
    advisory_id: string;
  }[];
  writeups?: {
    source: string;
    url: string;
    has_patch_diff: boolean;
    content_excerpt?: string;
  }[];
}

export interface PkgVuln {
  cve_id: string;
  advisory_id: string;
  fixed_ver: string;
  cvss_score?: number;
  cvss_severity: string;
  is_kev: boolean;
  title: string;
}

export interface LedgerEntry {
  seq: number;
  scope_id: string;
  finding_id: string;
  program: string;
  title: string;
  target: string;
  cwe: string;
  severity: string;
  sha256: string;
}

export interface PlaybookItem {
  path: string;
  title: string;
  bytes: number;
  preview: string;
}

export const NEXUS_TABS = ["overview", "cve", "semver", "ledger", "presets"] as const;
export type NexusTab = (typeof NEXUS_TABS)[number];

export function isNexusTab(val: string | null): val is NexusTab {
  return val !== null && (NEXUS_TABS as readonly string[]).includes(val);
}

export function safeHttpUrl(raw: string): string | null {
  try {
    const u = new URL(raw);
    return u.protocol === "https:" || u.protocol === "http:" ? u.toString() : null;
  } catch {
    return null;
  }
}
