"use client";

import * as React from "react";
import Link from "next/link";
import {
  BookOpenIcon,
  BotIcon,
  CheckCircle2Icon,
  DatabaseIcon,
  ExternalLinkIcon,
  KeyRoundIcon,
  PackageSearchIcon,
  PlugIcon,
  RefreshCwIcon,
  SearchIcon,
  ShieldCheckIcon,
  SparklesIcon,
  ZapIcon,
} from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { api } from "@/lib/api";
import type { Agent, LLMProfile, MCPServer, SkillItem } from "@/lib/types";

interface CveStats {
  metadata?: Record<string, string>;
}

interface CveResult {
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

interface CveDetail {
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
  packages?: { ecosystem: string; package_name: string; introduced_ver: string; fixed_ver: string; advisory_id: string }[];
  writeups?: { source: string; url: string; has_patch_diff: boolean; content_excerpt?: string }[];
}

interface PkgVuln {
  cve_id: string;
  advisory_id: string;
  fixed_ver: string;
  cvss_score?: number;
  cvss_severity: string;
  is_kev: boolean;
  title: string;
}

interface LedgerEntry {
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

interface PlaybookItem {
  path: string;
  title: string;
  bytes: number;
  preview: string;
}

function safeHttpUrl(raw: string): string | null {
  try {
    const u = new URL(raw);
    return u.protocol === "https:" || u.protocol === "http:" ? u.toString() : null;
  } catch {
    return null;
  }
}

export default function NexusHubPage() {
  const [tab, setTab] = React.useState("overview");
  const [nexusUrl, setNexusUrl] = React.useState("http://127.0.0.1:8088");

  // ARTEX state
  const [agents, setAgents] = React.useState<Agent[]>([]);
  const [mcps, setMcps] = React.useState<MCPServer[]>([]);
  const [profiles, setProfiles] = React.useState<LLMProfile[]>([]);
  const [skills, setSkills] = React.useState<SkillItem[]>([]);
  const [loadingArtex, setLoadingArtex] = React.useState(true);

  // Nexus CVE DB / Ledger / Playbooks state
  const [kbStats, setKbStats] = React.useState<CveStats | null>(null);
  const [kbOnline, setKbOnline] = React.useState(false);
  const [searchQ, setSearchQ] = React.useState("SSRF");
  const [searchMode, setSearchMode] = React.useState("cves");
  const [searchCwe, setSearchCwe] = React.useState("");
  const [minCvss, setMinCvss] = React.useState("4.0");
  const [kevOnly, setKevOnly] = React.useState(false);
  const [searchResults, setSearchResults] = React.useState<CveResult[]>([]);
  const [searchMeta, setSearchMeta] = React.useState("");
  const [selectedCve, setSelectedCve] = React.useState<CveDetail | null>(null);

  // SemVer checker
  const [eco, setEco] = React.useState("npm");
  const [pkgName, setPkgName] = React.useState("lodash");
  const [pkgVer, setPkgVer] = React.useState("4.17.15");
  const [pkgVulns, setPkgVulns] = React.useState<PkgVuln[]>([]);
  const [pkgStatus, setPkgStatus] = React.useState("");

  // Receipts & playbooks
  const [receipts, setReceipts] = React.useState<LedgerEntry[]>([]);
  const [chainValid, setChainValid] = React.useState<boolean | null>(null);
  const [playbooks, setPlaybooks] = React.useState<PlaybookItem[]>([]);

  // Provider-agnostic model routing form
  const [providerBaseUrl, setProviderBaseUrl] = React.useState("https://api.openai.com/v1");
  const [providerApiKey, setProviderApiKey] = React.useState("");
  const [plannerModel, setPlannerModel] = React.useState("");
  const [workerModel, setWorkerModel] = React.useState("");
  const [applyingPreset, setApplyingPreset] = React.useState(false);

  React.useEffect(() => {
    if (typeof window !== "undefined") {
      const saved = window.localStorage.getItem("artex_nexus_console_url");
      const autoUrl = saved || `http://${window.location.hostname}:8088`;
      setNexusUrl(autoUrl);
      const sp = new URLSearchParams(window.location.search);
      const reqTab = sp.get("tab");
      if (reqTab && ["overview", "cve", "semver", "ledger", "presets"].includes(reqTab)) {
        setTab(reqTab);
      }
    }
  }, []);

  const loadArtex = React.useCallback(async () => {
    setLoadingArtex(true);
    try {
      const [ag, mc, pr, sk] = await Promise.all([
        api.agents(),
        api.mcpServers(),
        api.llmProfiles(),
        api.skills(),
      ]);
      setAgents(ag);
      setMcps(mc);
      setProfiles(pr);
      setSkills(sk);
    } catch (e) {
      toast.error(`Failed loading ARTEX status: ${(e as Error).message}`);
    } finally {
      setLoadingArtex(false);
    }
  }, []);

  const loadNexusData = React.useCallback(async (baseUrl: string) => {
    const clean = baseUrl.replace(/\/+$/, "");
    try {
      const stRes = await fetch(`${clean}/api/stats`);
      if (!stRes.ok) throw new Error(`HTTP ${stRes.status}`);
      const stJson = (await stRes.json()) as CveStats;
      setKbStats(stJson);
      setKbOnline(true);

      const [rcRes, pbRes] = await Promise.all([
        fetch(`${clean}/api/receipts`)
          .then((r) => (r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`))))
          .catch(() => ({ count: 0, chain_valid: null, receipts: [] })),
        fetch(`${clean}/api/playbooks`)
          .then((r) => (r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`))))
          .catch(() => ({ count: 0, playbooks: [] })),
      ]);
      setReceipts(Array.isArray(rcRes.receipts) ? rcRes.receipts : []);
      setChainValid(typeof rcRes.chain_valid === "boolean" ? rcRes.chain_valid : null);
      setPlaybooks(Array.isArray(pbRes.playbooks) ? pbRes.playbooks : []);
    } catch {
      setKbOnline(false);
    }
  }, []);

  React.useEffect(() => {
    void loadArtex();
  }, [loadArtex]);

  React.useEffect(() => {
    if (nexusUrl) {
      void loadNexusData(nexusUrl);
    }
  }, [nexusUrl, loadNexusData]);

  async function runCveSearch(e?: React.FormEvent) {
    if (e) e.preventDefault();
    const clean = nexusUrl.replace(/\/+$/, "");
    setSearchMeta("Searching...");
    try {
      const qs = new URLSearchParams({
        q: searchQ.trim(),
        mode: searchMode,
        cwe: searchCwe.trim(),
        min_cvss: minCvss,
        kev: kevOnly ? "1" : "0",
      });
      const res = await fetch(`${clean}/api/search?${qs.toString()}`);
      const data = await res.json();
      if (data.error) {
        setSearchMeta(String(data.error));
        return;
      }
      setSearchResults(Array.isArray(data.results) ? data.results : []);
      setSearchMeta(`${data.count ?? 0} results in ${Number(data.elapsed_ms ?? 0).toFixed(2)} ms (${searchMode})`);
    } catch (err) {
      setSearchMeta(`Search failed: ${(err as Error).message}`);
    }
  }

  async function inspectCve(cveId: string) {
    const clean = nexusUrl.replace(/\/+$/, "");
    try {
      const res = await fetch(`${clean}/api/cve/${encodeURIComponent(cveId)}`);
      const data = (await res.json()) as CveDetail;
      setSelectedCve(data);
    } catch (err) {
      toast.error(`Failed loading ${cveId}: ${(err as Error).message}`);
    }
  }

  async function runPkgCheck(e: React.FormEvent) {
    e.preventDefault();
    const clean = nexusUrl.replace(/\/+$/, "");
    setPkgStatus("Checking...");
    try {
      const qs = new URLSearchParams({ ecosystem: eco, name: pkgName.trim(), version: pkgVer.trim() });
      const res = await fetch(`${clean}/api/package?${qs.toString()}`);
      const data = await res.json();
      if (data.error) {
        setPkgStatus(String(data.error));
        setPkgVulns([]);
        return;
      }
      const list: PkgVuln[] = Array.isArray(data.vulnerabilities) ? data.vulnerabilities : [];
      setPkgVulns(list);
      setPkgStatus(
        `${eco}/${pkgName}@${pkgVer} -> ${list.length} Medium+ match(es) in ${Number(data.elapsed_ms ?? 0).toFixed(2)} ms`,
      );
    } catch (err) {
      setPkgStatus(`Package check failed: ${(err as Error).message}`);
    }
  }

  async function refreshAllMcps() {
    let okCount = 0;
    for (const m of mcps.filter((x) => x.enabled)) {
      try {
        await api.refreshMcpServer(m.id);
        okCount++;
      } catch {
        // continue refreshing remaining servers
      }
    }
    toast.success(`Refreshed ${okCount} enabled MCP server(s)`);
    await loadArtex();
  }

  async function applyTieredModelRouting() {
    const pModel = plannerModel.trim();
    const wModel = workerModel.trim();
    const baseUrl = providerBaseUrl.trim();
    if (!pModel || !wModel) {
      toast.error("Enter both a planner model name and a worker model name.");
      return;
    }
    setApplyingPreset(true);
    try {
      const findByModel = (m: string) => profiles.find((p) => p.model === m && (!baseUrl || p.base_url === baseUrl));
      let plannerId = findByModel(pModel)?.id ? Number(findByModel(pModel)!.id) : 0;
      let workerId = findByModel(wModel)?.id ? Number(findByModel(wModel)!.id) : 0;

      if (!plannerId) {
        if (!providerApiKey.trim() || !baseUrl) {
          toast.error("Provide a provider base URL and API key to create missing profiles.");
          return;
        }
        const created = await api.saveLLMProfile({
          name: `Planner-${pModel}`,
          format: "openai",
          base_url: baseUrl,
          model: pModel,
          api_key: providerApiKey.trim(),
        });
        plannerId = created.id;
      }

      if (wModel === pModel) {
        workerId = plannerId;
      } else if (!workerId) {
        if (!providerApiKey.trim() || !baseUrl) {
          toast.error("Provide a provider base URL and API key to create missing profiles.");
          return;
        }
        const created = await api.saveLLMProfile({
          name: `Worker-${wModel}`,
          format: "openai",
          base_url: baseUrl,
          model: wModel,
          api_key: providerApiKey.trim(),
        });
        workerId = created.id;
      }

      await api.activateLLMProfile(String(workerId));
      await Promise.all([
        api.saveAgentConfig("planner", { llm_profile_id: plannerId }),
        api.saveAgentConfig("mainagent", { llm_profile_id: plannerId }),
        api.saveAgentConfig("worker", { llm_profile_id: workerId }),
        api.saveAgentConfig("goals", { llm_profile_id: workerId }),
        api.saveAgentConfig("auto", { llm_profile_id: workerId }),
        api.saveAgentConfig("pentest", { llm_profile_id: workerId }),
        api.saveAgentConfig("reporter", { llm_profile_id: workerId, max_turns: 15, run_seconds: 300 }),
        api.saveAgentConfig("retester", { llm_profile_id: workerId, max_turns: 25, run_seconds: 600 }),
      ]);
      setProviderApiKey("");
      toast.success(`Wired Planner/Main -> ${pModel} and Workers/Assistants -> ${wModel}`);
      await loadArtex();
    } catch (err) {
      toast.error(`Preset failed: ${(err as Error).message}`);
    } finally {
      setApplyingPreset(false);
    }
  }

  const profileMap = React.useMemo(() => {
    const m = new Map<string, LLMProfile>();
    for (const p of profiles) m.set(String(p.id), p);
    return m;
  }, [profiles]);

  const meta = kbStats?.metadata ?? {};

  return (
    <div className="flex flex-col gap-5 p-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 text-xl font-semibold tracking-tight">
            <DatabaseIcon className="size-5 text-violet-400" />
            ARTEX-Nexus Intelligence &amp; Multi-Agent Hub
          </h1>
          <p className="text-muted-foreground text-xs">
            Offline Medium+ CVE/OSV/KEV corpus, 4 Streamable HTTP MCP servers, Scope Guard ledger, and cost-tiered agent routing.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Input
            value={nexusUrl}
            onChange={(e) => {
              setNexusUrl(e.target.value);
              if (typeof window !== "undefined") {
                window.localStorage.setItem("artex_nexus_console_url", e.target.value);
              }
            }}
            className="h-8 w-56 font-mono text-xs"
            placeholder="http://127.0.0.1:8088"
          />
          <Badge variant="outline" className={kbOnline ? "border-emerald-500/50 text-emerald-500" : "border-amber-500/50 text-amber-500"}>
            {kbOnline ? "CVE Console Online" : "CVE Console Offline"}
          </Badge>
          <Button size="sm" variant="outline" onClick={() => { void loadArtex(); void loadNexusData(nexusUrl); }}>
            <RefreshCwIcon className="mr-1.5 size-3.5" /> Refresh
          </Button>
        </div>
      </div>

      {/* Top KPI Row */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
        <Card>
          <CardContent className="p-4">
            <div className="text-muted-foreground text-xs">Medium+ CVEs</div>
            <div className="mt-1 font-mono text-xl font-bold">{meta.total_cves ?? "—"}</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="text-muted-foreground text-xs">CISA KEVs</div>
            <div className="mt-1 font-mono text-xl font-bold text-rose-400">{meta.kev_count ?? "—"}</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="text-muted-foreground text-xs">Writeups / OSV Ranges</div>
            <div className="mt-1 font-mono text-xl font-bold">
              {meta.writeups_with_text ?? "—"} / {meta.total_packages ?? "—"}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="text-muted-foreground text-xs">Enabled MCPs</div>
            <div className="mt-1 font-mono text-xl font-bold text-emerald-400">
              {mcps.filter((m) => m.enabled).length} / {mcps.length}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="text-muted-foreground text-xs">Loaded Skills</div>
            <div className="mt-1 font-mono text-xl font-bold text-violet-400">{skills.length}</div>
          </CardContent>
        </Card>
      </div>

      <Tabs value={tab} onValueChange={setTab} className="w-full">
        <TabsList>
          <TabsTrigger value="overview"><BotIcon className="mr-1.5 size-3.5" /> Agents &amp; MCPs</TabsTrigger>
          <TabsTrigger value="cve"><SearchIcon className="mr-1.5 size-3.5" /> CVE &amp; Writeup Search</TabsTrigger>
          <TabsTrigger value="semver"><PackageSearchIcon className="mr-1.5 size-3.5" /> SemVer Check</TabsTrigger>
          <TabsTrigger value="ledger"><ShieldCheckIcon className="mr-1.5 size-3.5" /> Scope Ledger &amp; Playbooks</TabsTrigger>
          <TabsTrigger value="presets"><ZapIcon className="mr-1.5 size-3.5" /> Model Presets</TabsTrigger>
        </TabsList>

        {/* TAB 1: AGENTS & MCPs */}
        <TabsContent value="overview" className="mt-4 grid gap-4 lg:grid-cols-2">
          <Card>
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <CardTitle className="flex items-center gap-2 text-sm"><BotIcon className="size-4" /> Multi-Agent Routing Matrix</CardTitle>
                <Link href="/system/agents" className="text-muted-foreground hover:text-foreground flex items-center gap-1 text-xs">
                  Edit Agents <ExternalLinkIcon className="size-3" />
                </Link>
              </div>
              <CardDescription className="text-xs">Live role-to-model, MCP, and skill bindings from PostgreSQL.</CardDescription>
            </CardHeader>
            <CardContent className="grid gap-2">
              {loadingArtex && <div className="text-muted-foreground text-xs">Loading agents...</div>}
              {agents.map((a) => {
                const bound = a.llm_profile_id ? profileMap.get(String(a.llm_profile_id)) : undefined;
                return (
                  <div key={a.key} className="flex flex-wrap items-center justify-between gap-2 rounded-md border px-3 py-2 text-xs">
                    <div className="flex items-center gap-2">
                      <span className="font-semibold">{a.name}</span>
                      <code className="text-muted-foreground">{a.key}</code>
                    </div>
                    <div className="flex flex-wrap items-center gap-1.5">
                      <Badge variant="secondary" className="font-mono text-[10px]">
                        {bound ? bound.model : "inherits global default"}
                      </Badge>
                      <Badge variant="outline" className="text-[10px]">MCP {a.mcp_count ?? 0}</Badge>
                      <Badge variant="outline" className="text-[10px]">Skills {a.skill_count ?? 0}</Badge>
                    </div>
                  </div>
                );
              })}
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <CardTitle className="flex items-center gap-2 text-sm"><PlugIcon className="size-4" /> ARTEX-Nexus MCP Servers</CardTitle>
                <Button size="sm" variant="outline" className="h-7 text-xs" onClick={() => void refreshAllMcps()}>
                  <RefreshCwIcon className="mr-1 size-3" /> Refresh Tools
                </Button>
              </div>
              <CardDescription className="text-xs">Streamable HTTP MCP servers wired into planner, workers, and manager agent.</CardDescription>
            </CardHeader>
            <CardContent className="grid gap-2">
              {mcps.map((m) => (
                <div key={m.id} className="flex flex-wrap items-center justify-between gap-2 rounded-md border px-3 py-2 text-xs">
                  <div>
                    <div className="font-semibold">{m.name}</div>
                    <div className="text-muted-foreground font-mono text-[11px]">{m.url || m.transport}</div>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <Badge variant="outline" className={m.enabled ? "border-emerald-500/50 text-emerald-500" : "text-muted-foreground"}>
                      {m.enabled ? "Enabled" : "Disabled"}
                    </Badge>
                    <Badge variant="secondary" className="text-[10px]">{(m.tools ?? []).length} tools</Badge>
                  </div>
                </div>
              ))}
              <div className="mt-2 flex flex-wrap gap-1.5">
                {skills.map((s) => (
                  <Badge key={s.name} variant="outline" className="text-[10px]">
                    <SparklesIcon className="mr-1 size-2.5 text-violet-400" /> {s.name}
                  </Badge>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* TAB 2: CVE & WRITEUP SEARCH */}
        <TabsContent value="cve" className="mt-4 grid gap-4">
          <Card>
            <CardContent className="p-4">
              <form onSubmit={(e) => void runCveSearch(e)} className="flex flex-wrap items-center gap-2">
                <Input value={searchQ} onChange={(e) => setSearchQ(e.target.value)} placeholder="Search CVEs, products, or writeup excerpts..." className="min-w-56 flex-1" />
                <Select value={searchMode} onValueChange={setSearchMode}>
                  <SelectTrigger className="w-44"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="cves">CVEs (cves_fts)</SelectItem>
                    <SelectItem value="writeups">Writeups (writeups_fts)</SelectItem>
                  </SelectContent>
                </Select>
                <Input value={searchCwe} onChange={(e) => setSearchCwe(e.target.value)} placeholder="CWE-79" className="w-28" />
                <Select value={minCvss} onValueChange={setMinCvss}>
                  <SelectTrigger className="w-32"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="4.0">CVSS &ge; 4.0</SelectItem>
                    <SelectItem value="7.0">CVSS &ge; 7.0</SelectItem>
                    <SelectItem value="9.0">CVSS &ge; 9.0</SelectItem>
                  </SelectContent>
                </Select>
                <label className="flex items-center gap-1.5 text-xs">
                  <input type="checkbox" checked={kevOnly} onChange={(e) => setKevOnly(e.target.checked)} /> KEV only
                </label>
                <Button type="submit" size="sm"><SearchIcon className="mr-1.5 size-3.5" /> Search</Button>
              </form>
              {searchMeta && <div className="text-muted-foreground mt-2 text-xs">{searchMeta}</div>}
            </CardContent>
          </Card>

          <div className="grid gap-4 lg:grid-cols-2">
            <Card>
              <CardHeader className="pb-2"><CardTitle className="text-sm">Matches</CardTitle></CardHeader>
              <CardContent className="grid max-h-[520px] gap-2 overflow-y-auto">
                {searchResults.map((r, idx) => (
                  <button
                    key={`${r.cve_id}-${idx}`}
                    type="button"
                    onClick={() => void inspectCve(r.cve_id)}
                    className="hover:border-primary/50 rounded-md border p-3 text-left transition-colors"
                  >
                    <div className="flex flex-wrap items-center gap-1.5">
                      <code className="font-semibold text-violet-400">{r.cve_id}</code>
                      <Badge variant="secondary" className="text-[10px]">{r.cvss_severity} {r.cvss_score ?? ""}</Badge>
                      {r.is_kev && <Badge variant="destructive" className="text-[10px]">KEV</Badge>}
                      {r.exploit_maturity && r.exploit_maturity !== "NONE" && (
                        <Badge variant="outline" className="text-[10px]">{r.exploit_maturity}</Badge>
                      )}
                    </div>
                    {r.title && <div className="mt-1 text-xs font-medium">{r.title}</div>}
                    <div className="text-muted-foreground mt-0.5 line-clamp-2 text-xs">{r.summary || r.excerpt || r.url}</div>
                  </button>
                ))}
                {searchResults.length === 0 && (
                  <div className="text-muted-foreground text-xs">Run a query above (requires nexus-sync serve on :8088).</div>
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-2"><CardTitle className="text-sm">CVE &amp; Writeup Detail</CardTitle></CardHeader>
              <CardContent className="grid max-h-[520px] gap-3 overflow-y-auto text-xs">
                {!selectedCve && <div className="text-muted-foreground">Select a CVE on the left to inspect its vector, OSV ranges, and writeups.</div>}
                {selectedCve && selectedCve.found && (
                  <>
                    <div className="flex flex-wrap items-center gap-2">
                      <code className="text-base font-bold text-violet-400">{selectedCve.cve_id}</code>
                      <Badge variant="secondary">{selectedCve.cvss_severity} {selectedCve.cvss_score ?? ""}</Badge>
                      {selectedCve.is_kev && <Badge variant="destructive">CISA KEV</Badge>}
                      {(selectedCve.cwes ?? []).map((c) => <Badge key={c} variant="outline">{c}</Badge>)}
                    </div>
                    {selectedCve.title && <div className="font-medium">{selectedCve.title}</div>}
                    <p className="text-muted-foreground leading-relaxed">{selectedCve.description}</p>
                    {selectedCve.cvss_vector && <code className="text-muted-foreground block text-[11px]">{selectedCve.cvss_vector}</code>}
                    {(selectedCve.packages ?? []).length > 0 && (
                      <div className="grid gap-1">
                        <div className="font-semibold">OSV / GHSA Package Ranges</div>
                        {(selectedCve.packages ?? []).slice(0, 12).map((p, i) => (
                          <div key={i} className="rounded border px-2 py-1 font-mono text-[11px]">
                            {p.ecosystem}/{p.package_name} [{p.introduced_ver || "0"} → {p.fixed_ver || "unfixed"}] ({p.advisory_id})
                          </div>
                        ))}
                      </div>
                    )}
                    {(selectedCve.writeups ?? []).length > 0 && (
                      <div className="grid gap-1.5">
                        <div className="font-semibold">Writeups &amp; Patches ({selectedCve.writeups?.length})</div>
                        {(selectedCve.writeups ?? []).slice(0, 10).map((w, i) => (
                          <div key={i} className="rounded border p-2">
                            <div className="flex flex-wrap items-center gap-1.5">
                              <Badge variant="outline" className="text-[10px]">{w.source}</Badge>
                              {w.has_patch_diff && <Badge variant="secondary" className="text-[10px]">PATCH</Badge>}
                              {(() => {
                                const safeHref = safeHttpUrl(w.url);
                                return safeHref ? (
                                  <a href={safeHref} target="_blank" rel="noopener noreferrer" className="truncate text-sky-400 hover:underline">
                                    {safeHref}
                                  </a>
                                ) : (
                                  <span className="text-muted-foreground truncate font-mono">{w.url}</span>
                                );
                              })()}
                            </div>
                            {w.content_excerpt && (
                              <pre className="text-muted-foreground mt-1.5 max-h-28 overflow-auto whitespace-pre-wrap font-mono text-[11px]">
                                {w.content_excerpt.slice(0, 450)}
                              </pre>
                            )}
                          </div>
                        ))}
                      </div>
                    )}
                  </>
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* TAB 3: SEMVER PACKAGE CHECKER */}
        <TabsContent value="semver" className="mt-4">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm">Offline OSV/GHSA SemVer Package Check</CardTitle>
              <CardDescription className="text-xs">Match any fingerprinted library version against 43,000+ OSV/GHSA version ranges.</CardDescription>
            </CardHeader>
            <CardContent className="grid gap-3">
              <form onSubmit={(e) => void runPkgCheck(e)} className="flex flex-wrap items-center gap-2">
                <Select value={eco} onValueChange={setEco}>
                  <SelectTrigger className="w-32"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="npm">npm</SelectItem>
                    <SelectItem value="PyPI">PyPI</SelectItem>
                    <SelectItem value="Go">Go</SelectItem>
                    <SelectItem value="Maven">Maven</SelectItem>
                    <SelectItem value="crates.io">crates.io</SelectItem>
                    <SelectItem value="Packagist">Packagist</SelectItem>
                  </SelectContent>
                </Select>
                <Input value={pkgName} onChange={(e) => setPkgName(e.target.value)} placeholder="Package (e.g. lodash)" className="w-56" />
                <Input value={pkgVer} onChange={(e) => setPkgVer(e.target.value)} placeholder="Version (e.g. 4.17.15)" className="w-40" />
                <Button type="submit" size="sm">Check Version</Button>
              </form>
              {pkgStatus && <div className="text-muted-foreground text-xs">{pkgStatus}</div>}
              <div className="grid gap-2">
                {pkgVulns.map((v, i) => (
                  <div key={`${v.cve_id}-${i}`} className="flex flex-wrap items-center justify-between gap-2 rounded-md border p-3 text-xs">
                    <div>
                      <div className="flex items-center gap-2">
                        <code className="font-semibold text-violet-400">{v.cve_id}</code>
                        <Badge variant="secondary">{v.cvss_severity} {v.cvss_score ?? "KEV"}</Badge>
                        {v.is_kev && <Badge variant="destructive">KEV</Badge>}
                      </div>
                      <div className="mt-1">{v.title}</div>
                    </div>
                    <Badge variant="outline" className="font-mono text-[11px]">fix: {v.fixed_ver || "none"}</Badge>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* TAB 4: SCOPE LEDGER & PLAYBOOKS */}
        <TabsContent value="ledger" className="mt-4 grid gap-4 lg:grid-cols-2">
          <Card>
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <CardTitle className="flex items-center gap-2 text-sm"><ShieldCheckIcon className="size-4" /> Hash-Chained Evidence Ledger</CardTitle>
                <Badge
                  variant="outline"
                  className={
                    chainValid === true
                      ? "border-emerald-500/50 text-emerald-500"
                      : chainValid === false
                        ? "border-rose-500/50 text-rose-500"
                        : "text-muted-foreground"
                  }
                >
                  {chainValid === true ? "SHA-256 Chain Valid" : chainValid === false ? "Chain Tampered" : "Unavailable"}
                </Badge>
              </div>
              <CardDescription className="text-xs">Immutable receipts recorded by scope-guard-mcp (receipts.jsonl).</CardDescription>
            </CardHeader>
            <CardContent className="grid gap-2 text-xs">
              {receipts.length === 0 && <div className="text-muted-foreground">No evidence receipts recorded yet.</div>}
              {receipts.slice(-20).reverse().map((r) => (
                <div key={r.seq} className="rounded-md border p-2.5">
                  <div className="flex flex-wrap items-center gap-1.5">
                    <Badge variant="outline">#{r.seq}</Badge>
                    <Badge variant="secondary">{r.severity}</Badge>
                    <code className="font-semibold">{r.finding_id}</code>
                    <span className="text-muted-foreground">{r.cwe}</span>
                  </div>
                  <div className="mt-1 font-medium">{r.title}</div>
                  <div className="text-muted-foreground mt-0.5 font-mono text-[11px]">
                    {r.target} · sha256:{(r.sha256 ?? "").slice(0, 16)}
                  </div>
                </div>
              ))}
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="flex items-center gap-2 text-sm"><BookOpenIcon className="size-4" /> Security Playbooks &amp; Templates</CardTitle>
              <CardDescription className="text-xs">Knowledge playbooks and CNA/VDP disclosure templates wired into ARTEX agents.</CardDescription>
            </CardHeader>
            <CardContent className="grid gap-2 text-xs">
              {playbooks.length === 0 && <div className="text-muted-foreground">No playbooks loaded (start nexus-sync serve with --knowledge-dir).</div>}
              {playbooks.map((p) => (
                <div key={p.path} className="rounded-md border p-2.5">
                  <div className="font-semibold">{p.title}</div>
                  <div className="text-muted-foreground font-mono text-[11px]">{p.path} · {p.bytes} bytes</div>
                  <pre className="text-muted-foreground mt-1.5 max-h-24 overflow-auto whitespace-pre-wrap font-mono text-[11px]">
                    {p.preview}
                  </pre>
                </div>
              ))}
            </CardContent>
          </Card>
        </TabsContent>

        {/* TAB 5: PROVIDER-AGNOSTIC TIERED MODEL ROUTING */}
        <TabsContent value="presets" className="mt-4">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="flex items-center gap-2 text-sm"><KeyRoundIcon className="size-4" /> Tiered Multi-Agent Model Routing</CardTitle>
              <CardDescription className="text-xs">
                Bind Planner and Manager to a stronger reasoning model while running parallel Workers and Assistants on a faster, cheaper model (with turn caps on Reporter and Retester). Works with any OpenAI-compatible API endpoint.
              </CardDescription>
            </CardHeader>
            <CardContent className="grid max-w-xl gap-3">
              <div className="grid gap-1.5">
                <Label className="text-xs">OpenAI-Compatible Base URL</Label>
                <Input
                  value={providerBaseUrl}
                  onChange={(e) => setProviderBaseUrl(e.target.value)}
                  placeholder="https://api.openai.com/v1 or http://localhost:11434/v1"
                  className="font-mono text-xs"
                />
              </div>
              <div className="grid gap-1.5">
                <Label className="text-xs">Planner &amp; Main/Manager Model</Label>
                <Input
                  value={plannerModel}
                  onChange={(e) => setPlannerModel(e.target.value)}
                  placeholder="e.g. gpt-4.1, claude-sonnet-4, or local reasoning model"
                  className="font-mono text-xs"
                />
              </div>
              <div className="grid gap-1.5">
                <Label className="text-xs">Parallel Workers, Goals &amp; Assistants Model</Label>
                <Input
                  value={workerModel}
                  onChange={(e) => setWorkerModel(e.target.value)}
                  placeholder="e.g. gpt-4.1-mini, deepseek-chat, or fast local model"
                  className="font-mono text-xs"
                />
              </div>
              <div className="grid gap-1.5">
                <Label className="text-xs">Provider API Key (only needed when creating new profiles)</Label>
                <Input
                  type="password"
                  value={providerApiKey}
                  onChange={(e) => setProviderApiKey(e.target.value)}
                  placeholder="Optional if profiles with these model names already exist"
                  className="font-mono text-xs"
                />
              </div>
              <Button disabled={applyingPreset} onClick={() => void applyTieredModelRouting()} className="w-fit">
                <CheckCircle2Icon className="mr-1.5 size-4" />
                {applyingPreset ? "Applying..." : "Apply Tiered Multi-Agent Routing"}
              </Button>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
