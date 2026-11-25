"use client";

import * as React from "react";
import { CheckCircle2Icon, KeyRoundIcon } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api } from "@/lib/api";
import type { LLMProfile } from "@/lib/types";

interface RoutingTabProps {
  profiles: LLMProfile[];
  onReloadArtex: () => Promise<void>;
}

export function RoutingTab({ profiles, onReloadArtex }: RoutingTabProps) {
  const [providerBaseUrl, setProviderBaseUrl] = React.useState("https://api.openai.com/v1");
  const [providerApiKey, setProviderApiKey] = React.useState("");
  const [plannerModel, setPlannerModel] = React.useState("");
  const [workerModel, setWorkerModel] = React.useState("");
  const [applyingPreset, setApplyingPreset] = React.useState(false);

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
      const existingPlanner = findByModel(pModel);
      const existingWorker = findByModel(wModel);
      let plannerId = existingPlanner?.id ? Number(existingPlanner.id) : 0;
      let workerId = existingWorker?.id ? Number(existingWorker.id) : 0;

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
      await onReloadArtex();
    } catch (err) {
      toast.error(`Preset failed: ${(err as Error).message}`);
    } finally {
      setApplyingPreset(false);
    }
  }

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-sm">
          <KeyRoundIcon className="size-4" /> Tiered Multi-Agent Model Routing
        </CardTitle>
        <CardDescription className="text-xs">
          Bind Planner and Manager to a stronger reasoning model while running parallel Workers and Assistants on a
          faster, cheaper model (with turn caps on Reporter and Retester). Works with any OpenAI-compatible API
          endpoint.
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
  );
}
