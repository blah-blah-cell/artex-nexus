"use client";

import * as React from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import {
  BotIcon,
  DatabaseIcon,
  PackageSearchIcon,
  RefreshCwIcon,
  SearchIcon,
  ShieldCheckIcon,
  ZapIcon,
} from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { api } from "@/lib/api";
import type { Agent, LLMProfile, MCPServer, SkillItem } from "@/lib/types";
import { CveSearchTab } from "./components/cve-search-tab";
import { LedgerTab } from "./components/ledger-tab";
import { OverviewTab } from "./components/overview-tab";
import { RoutingTab } from "./components/routing-tab";
import { SemverTab } from "./components/semver-tab";
import {
  isNexusTab,
  type CveStats,
  type LedgerEntry,
  type NexusTab,
  type PlaybookItem,
} from "./types";

function NexusHubContent() {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const tabParam = searchParams.get("tab");

  const [tab, setTab] = React.useState<NexusTab>(() => (isNexusTab(tabParam) ? tabParam : "overview"));
  const [nexusUrl, setNexusUrl] = React.useState("http://127.0.0.1:8088");

  const [agents, setAgents] = React.useState<Agent[]>([]);
  const [mcps, setMcps] = React.useState<MCPServer[]>([]);
  const [profiles, setProfiles] = React.useState<LLMProfile[]>([]);
  const [skills, setSkills] = React.useState<SkillItem[]>([]);
  const [loadingArtex, setLoadingArtex] = React.useState(true);

  const [kbStats, setKbStats] = React.useState<CveStats | null>(null);
  const [kbOnline, setKbOnline] = React.useState(false);
  const [receipts, setReceipts] = React.useState<LedgerEntry[]>([]);
  const [chainValid, setChainValid] = React.useState<boolean | null>(null);
  const [playbooks, setPlaybooks] = React.useState<PlaybookItem[]>([]);

  React.useEffect(() => {
    if (isNexusTab(tabParam)) {
      setTab(tabParam);
    } else if (tabParam === null) {
      setTab("overview");
    }
  }, [tabParam]);

  React.useEffect(() => {
    if (typeof window !== "undefined") {
      const saved = window.localStorage.getItem("artex_nexus_console_url");
      setNexusUrl(saved || `http://${window.location.hostname}:8088`);
    }
  }, []);

  function handleTabChange(next: string) {
    if (!isNexusTab(next)) return;
    setTab(next);
    const qs = new URLSearchParams(searchParams.toString());
    if (next === "overview") {
      qs.delete("tab");
    } else {
      qs.set("tab", next);
    }
    const query = qs.toString();
    router.replace(query ? `${pathname}?${query}` : pathname, { scroll: false });
  }

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
            Offline Medium+ CVE/OSV/KEV corpus, 4 Streamable HTTP MCP servers, Scope Guard ledger, and tiered agent
            routing.
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
          <Badge
            variant="outline"
            className={kbOnline ? "border-emerald-500/50 text-emerald-500" : "border-amber-500/50 text-amber-500"}
          >
            {kbOnline ? "CVE Console Online" : "CVE Console Offline"}
          </Badge>
          <Button
            size="sm"
            variant="outline"
            onClick={() => {
              void loadArtex();
              void loadNexusData(nexusUrl);
            }}
          >
            <RefreshCwIcon className="mr-1.5 size-3.5" /> Refresh
          </Button>
        </div>
      </div>

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

      <Tabs value={tab} onValueChange={handleTabChange} className="w-full">
        <TabsList>
          <TabsTrigger value="overview">
            <BotIcon className="mr-1.5 size-3.5" /> Agents &amp; MCPs
          </TabsTrigger>
          <TabsTrigger value="cve">
            <SearchIcon className="mr-1.5 size-3.5" /> CVE &amp; Writeup Search
          </TabsTrigger>
          <TabsTrigger value="semver">
            <PackageSearchIcon className="mr-1.5 size-3.5" /> SemVer Check
          </TabsTrigger>
          <TabsTrigger value="ledger">
            <ShieldCheckIcon className="mr-1.5 size-3.5" /> Scope Ledger &amp; Playbooks
          </TabsTrigger>
          <TabsTrigger value="presets">
            <ZapIcon className="mr-1.5 size-3.5" /> Model Presets
          </TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="mt-4">
          <OverviewTab
            agents={agents}
            mcps={mcps}
            skills={skills}
            profileMap={profileMap}
            loadingArtex={loadingArtex}
            onRefreshMcps={refreshAllMcps}
          />
        </TabsContent>

        <TabsContent value="cve" className="mt-4">
          <CveSearchTab nexusUrl={nexusUrl} />
        </TabsContent>

        <TabsContent value="semver" className="mt-4">
          <SemverTab nexusUrl={nexusUrl} totalPackages={meta.total_packages} />
        </TabsContent>

        <TabsContent value="ledger" className="mt-4">
          <LedgerTab receipts={receipts} chainValid={chainValid} playbooks={playbooks} />
        </TabsContent>

        <TabsContent value="presets" className="mt-4">
          <RoutingTab profiles={profiles} onReloadArtex={loadArtex} />
        </TabsContent>
      </Tabs>
    </div>
  );
}

export default function NexusHubPage() {
  return (
    <React.Suspense fallback={<div className="text-muted-foreground p-6 text-xs">Loading ARTEX-Nexus Hub...</div>}>
      <NexusHubContent />
    </React.Suspense>
  );
}
