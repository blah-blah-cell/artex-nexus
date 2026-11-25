"use client";

import * as React from "react";
import Link from "next/link";
import { BotIcon, ExternalLinkIcon, PlugIcon, RefreshCwIcon, SparklesIcon } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import type { Agent, LLMProfile, MCPServer, SkillItem } from "@/lib/types";

interface OverviewTabProps {
  agents: Agent[];
  mcps: MCPServer[];
  skills: SkillItem[];
  profileMap: Map<string, LLMProfile>;
  loadingArtex: boolean;
  onRefreshMcps: () => Promise<void>;
}

export function OverviewTab({
  agents,
  mcps,
  skills,
  profileMap,
  loadingArtex,
  onRefreshMcps,
}: OverviewTabProps) {
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="flex items-center gap-2 text-sm">
              <BotIcon className="size-4" /> Multi-Agent Routing Matrix
            </CardTitle>
            <Link
              href="/system/agents"
              className="text-muted-foreground hover:text-foreground flex items-center gap-1 text-xs"
            >
              Edit Agents <ExternalLinkIcon className="size-3" />
            </Link>
          </div>
          <CardDescription className="text-xs">
            Live role-to-model, MCP, and skill bindings from PostgreSQL.
          </CardDescription>
        </CardHeader>
        <CardContent className="grid gap-2">
          {loadingArtex && <div className="text-muted-foreground text-xs">Loading agents...</div>}
          {agents.map((a) => {
            const bound = a.llm_profile_id ? profileMap.get(String(a.llm_profile_id)) : undefined;
            return (
              <div
                key={a.key}
                className="flex flex-wrap items-center justify-between gap-2 rounded-md border px-3 py-2 text-xs"
              >
                <div className="flex items-center gap-2">
                  <span className="font-semibold">{a.name}</span>
                  <code className="text-muted-foreground">{a.key}</code>
                </div>
                <div className="flex flex-wrap items-center gap-1.5">
                  <Badge variant="secondary" className="font-mono text-[10px]">
                    {bound ? bound.model : "inherits global default"}
                  </Badge>
                  <Badge variant="outline" className="text-[10px]">
                    MCP {a.mcp_count ?? 0}
                  </Badge>
                  <Badge variant="outline" className="text-[10px]">
                    Skills {a.skill_count ?? 0}
                  </Badge>
                </div>
              </div>
            );
          })}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="flex items-center gap-2 text-sm">
              <PlugIcon className="size-4" /> ARTEX-Nexus MCP Servers
            </CardTitle>
            <Button size="sm" variant="outline" className="h-7 text-xs" onClick={() => void onRefreshMcps()}>
              <RefreshCwIcon className="mr-1 size-3" /> Refresh Tools
            </Button>
          </div>
          <CardDescription className="text-xs">
            Streamable HTTP MCP servers wired into planner, workers, and manager agent.
          </CardDescription>
        </CardHeader>
        <CardContent className="grid gap-2">
          {mcps.map((m) => (
            <div
              key={m.id}
              className="flex flex-wrap items-center justify-between gap-2 rounded-md border px-3 py-2 text-xs"
            >
              <div>
                <div className="font-semibold">{m.name}</div>
                <div className="text-muted-foreground font-mono text-[11px]">{m.url || m.transport}</div>
              </div>
              <div className="flex items-center gap-1.5">
                <Badge
                  variant="outline"
                  className={m.enabled ? "border-emerald-500/50 text-emerald-500" : "text-muted-foreground"}
                >
                  {m.enabled ? "Enabled" : "Disabled"}
                </Badge>
                <Badge variant="secondary" className="text-[10px]">
                  {(m.tools ?? []).length} tools
                </Badge>
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
    </div>
  );
}
