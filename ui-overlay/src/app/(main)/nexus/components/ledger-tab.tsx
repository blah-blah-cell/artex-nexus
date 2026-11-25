"use client";

import * as React from "react";
import { BookOpenIcon, ShieldCheckIcon } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import type { LedgerEntry, PlaybookItem } from "../types";

interface LedgerTabProps {
  receipts: LedgerEntry[];
  chainValid: boolean | null;
  playbooks: PlaybookItem[];
}

export function LedgerTab({ receipts, chainValid, playbooks }: LedgerTabProps) {
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="flex items-center gap-2 text-sm">
              <ShieldCheckIcon className="size-4" /> Hash-Chained Evidence Ledger
            </CardTitle>
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
          <CardDescription className="text-xs">
            Immutable receipts recorded by scope-guard-mcp (receipts.jsonl).
          </CardDescription>
        </CardHeader>
        <CardContent className="grid gap-2 text-xs">
          {receipts.length === 0 && <div className="text-muted-foreground">No evidence receipts recorded yet.</div>}
          {receipts
            .slice(-20)
            .reverse()
            .map((r) => (
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
          <CardTitle className="flex items-center gap-2 text-sm">
            <BookOpenIcon className="size-4" /> Security Playbooks &amp; Templates
          </CardTitle>
          <CardDescription className="text-xs">
            Knowledge playbooks and CNA/VDP disclosure templates wired into ARTEX agents.
          </CardDescription>
        </CardHeader>
        <CardContent className="grid gap-2 text-xs">
          {playbooks.length === 0 && (
            <div className="text-muted-foreground">
              No playbooks loaded (start nexus-sync serve with --knowledge-dir).
            </div>
          )}
          {playbooks.map((p) => (
            <div key={p.path} className="rounded-md border p-2.5">
              <div className="font-semibold">{p.title}</div>
              <div className="text-muted-foreground font-mono text-[11px]">
                {p.path} · {p.bytes} bytes
              </div>
              <pre className="text-muted-foreground mt-1.5 max-h-24 overflow-auto whitespace-pre-wrap font-mono text-[11px]">
                {p.preview}
              </pre>
            </div>
          ))}
        </CardContent>
      </Card>
    </div>
  );
}
