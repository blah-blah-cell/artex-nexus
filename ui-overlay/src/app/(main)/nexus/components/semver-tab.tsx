"use client";

import * as React from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import type { PkgVuln } from "../types";

interface SemverTabProps {
  nexusUrl: string;
  totalPackages?: string;
}

export function SemverTab({ nexusUrl, totalPackages }: SemverTabProps) {
  const [eco, setEco] = React.useState("npm");
  const [pkgName, setPkgName] = React.useState("lodash");
  const [pkgVer, setPkgVer] = React.useState("4.17.15");
  const [pkgVulns, setPkgVulns] = React.useState<PkgVuln[]>([]);
  const [pkgStatus, setPkgStatus] = React.useState("");

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

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-sm">Offline OSV/GHSA SemVer Package Check</CardTitle>
        <CardDescription className="text-xs">
          Match any fingerprinted library version against{" "}
          {totalPackages ? `${totalPackages} indexed` : "indexed"} OSV/GHSA version ranges.
        </CardDescription>
      </CardHeader>
      <CardContent className="grid gap-3">
        <form onSubmit={(e) => void runPkgCheck(e)} className="flex flex-wrap items-center gap-2">
          <Select value={eco} onValueChange={setEco}>
            <SelectTrigger className="w-32">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="npm">npm</SelectItem>
              <SelectItem value="PyPI">PyPI</SelectItem>
              <SelectItem value="Go">Go</SelectItem>
              <SelectItem value="Maven">Maven</SelectItem>
              <SelectItem value="crates.io">crates.io</SelectItem>
              <SelectItem value="Packagist">Packagist</SelectItem>
            </SelectContent>
          </Select>
          <Input
            value={pkgName}
            onChange={(e) => setPkgName(e.target.value)}
            placeholder="Package (e.g. lodash)"
            className="w-56"
          />
          <Input
            value={pkgVer}
            onChange={(e) => setPkgVer(e.target.value)}
            placeholder="Version (e.g. 4.17.15)"
            className="w-40"
          />
          <Button type="submit" size="sm">
            Check Version
          </Button>
        </form>
        {pkgStatus && <div className="text-muted-foreground text-xs">{pkgStatus}</div>}
        <div className="grid gap-2">
          {pkgVulns.map((v, i) => (
            <div
              key={`${v.cve_id}-${i}`}
              className="flex flex-wrap items-center justify-between gap-2 rounded-md border p-3 text-xs"
            >
              <div>
                <div className="flex items-center gap-2">
                  <code className="font-semibold text-violet-400">{v.cve_id}</code>
                  <Badge variant="secondary">
                    {v.cvss_severity} {v.cvss_score ?? "KEV"}
                  </Badge>
                  {v.is_kev && <Badge variant="destructive">KEV</Badge>}
                </div>
                <div className="mt-1">{v.title}</div>
              </div>
              <Badge variant="outline" className="font-mono text-[11px]">
                fix: {v.fixed_ver || "none"}
              </Badge>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
