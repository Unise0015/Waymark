"use client";

import { useState, useEffect, useRef } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { scans, connectScanWS, ScanJob, ToolRun, exports } from "@/lib/api";
import { LearnMore } from "@/components/LearnMore";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || `http://${typeof window !== 'undefined' ? window.location.hostname : 'localhost'}:8000/api/v1`;

interface DecisionItem {
  id: string;
  type: "agent_decision" | "scope_filter" | "error" | "finding_discovered" | string;
  timestamp: string;
  observation?: string;
  reasoning?: string;
  action_chosen?: string;
  education_note?: string | null;
  learnMoreId?: string | null;
  excluded?: string[];
  severity: "normal" | "scope" | "error";
}

function extractLearnMoreId(
  action?: string | null,
  educationNote?: string | null,
  observation?: string | null
): string | null {
  const actionLower = (action || "").toLowerCase();
  // 1. Check the specific action first to avoid AI hallucinations matching the wrong tool
  if (actionLower.includes("subfinder")) return "tool:subfinder";
  if (actionLower.includes("httpx")) return "tool:httpx";
  if (actionLower.includes("ffuf")) return "tool:ffuf";
  if (actionLower.includes("nuclei")) return "tool:nuclei";
  if (actionLower.includes("katana")) return "tool:katana";
  if (actionLower.includes("naabu")) return "tool:naabu";
  
  // 2. Fallbacks for concepts
  const combined = `${action || ""} ${educationNote || ""} ${observation || ""}`.toLowerCase();
  if (combined.includes("scope") || combined.includes("out-of-scope") || combined.includes("boundary") || combined.includes("authorization")) {
    return "concept:scope";
  }
  if (combined.includes("roi") || combined.includes("priorit") || combined.includes("score")) {
    return "concept:roi_scoring";
  }
  
  return null;
}

function formatDuration(startedAt?: string | null, completedAt?: string | null): string | null {
  if (!startedAt || !completedAt) return null;
  const start = new Date(startedAt).getTime();
  const end = new Date(completedAt).getTime();
  const diffSec = Math.max(0, Math.floor((end - start) / 1000));
  if (diffSec < 1) return "< 1s";
  if (diffSec < 60) return `${diffSec}s`;
  const mins = Math.floor(diffSec / 60);
  const secs = diffSec % 60;
  return `${mins}m ${secs}s`;
}

function formatTime(timestamp?: string): string {
  if (!timestamp) return "";
  try {
    const d = new Date(timestamp);
    if (isNaN(d.getTime())) return timestamp;
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  } catch {
    return timestamp;
  }
}


function generateHackerAnalysis(toolName: string, stdout: string, resultCount: number): string {
  const name = (toolName || "").toLowerCase();
  if (resultCount === 0 && !stdout) return "Nothing found this time. Target might be locked down, out of scope, or behind a WAF.";
  
  if (name.includes('subfinder')) {
    return `I pulled ${resultCount} subdomains from passive OSINT sources (crt.sh, virustotal, etc.). We haven't touched the target directly yet, so we're completely stealthy. Next step is probing these to see which ones actually resolve and host a web server.`;
  }
  if (name.includes('httpx')) {
    return `Out of the subdomains we fed it, ${resultCount} are running live web servers. I've mapped the status codes and tech stacks. Pay close attention to any 403s (potential bypass opportunities) and 200s running outdated tech (like old PHP or exposed admin panels).`;
  }
  if (name.includes('katana')) {
    return `Crawled and discovered ${resultCount} hidden paths and endpoints. Look closely for API endpoints, hidden parameters, or juicy JS files that might leak secrets.`;
  }
  if (name.includes('nuclei')) {
    return `Hit! Nuclei flagged ${resultCount} potential vulnerabilities using community templates. Don't take these as gospel—verify the high/critical ones manually by checking the 'matched-at' URLs. Automation finds the door, you have to pick the lock.`;
  }
  if (name.includes('ffuf')) {
    return `Fuzzing discovered ${resultCount} directories or files. Keep an eye out for backup files (.bak), config files, or unauthenticated /admin paths that the crawler missed.`;
  }
  if (name.includes('dnsx') || name.includes('naabu')) {
    return `Infrastructure mapping complete. Found ${resultCount} data points. This is useful for finding origin IPs behind CDNs or discovering unprotected management ports (SSH, FTP, Database) on non-standard ports.`;
  }
  
  return `Tool completed with ${resultCount} results. Review the parsed output below for anything interesting.`;
}

export default function ScanJobDetailPage() {

  const params = useParams();
  const rawId = params?.id;
  const scanId = typeof rawId === "string" ? rawId : Array.isArray(rawId) ? rawId[0] : "";

  const [scanJob, setScanJob] = useState<ScanJob | null>(null);
  const [toolRuns, setToolRuns] = useState<ToolRun[]>([]);
  const [decisions, setDecisions] = useState<DecisionItem[]>([]);
  const [scanResults, setScanResults] = useState<any>(null);
  const [selectedToolRun, setSelectedToolRun] = useState<any>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [wsConnected, setWsConnected] = useState<boolean>(false);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [feedbackMessage, setFeedbackMessage] = useState<{ text: string; type: "success" | "error" } | null>(null);

  const decisionEndRef = useRef<HTMLDivElement>(null);
  const wsRef = useRef<WebSocket | null>(null);

  // Auto-scroll Agent Decision Trail on new items
  useEffect(() => {
    if (decisionEndRef.current) {
      decisionEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [decisions]);

  // Initial Data Fetching
  const fetchScanData = async () => {
    if (!scanId) return;
    try {
      setError(null);
      const [jobData, runsData, resultsData] = await Promise.all([
        scans.get(scanId),
        scans.toolRuns(scanId).catch(() => [] as ToolRun[]),
        scans.results(scanId).catch(() => null),
      ]);
      setScanJob(jobData);
      setToolRuns(Array.isArray(runsData) ? runsData : []);
      setScanResults(resultsData);

      const API_BASE_CLIENT = typeof window !== 'undefined' ? `http://${window.location.hostname}:8000/api/v1` : 'http://localhost:8000/api/v1';
      fetch(`${API_BASE_CLIENT}/scans/${scanId}/results`)
        .then(r => r.json())
        .then(data => setScanResults(data))
        .catch(() => {});


      // Fetch historical decisions if available
      try {
        const res = await fetch(`${API_BASE}/agent/decisions/${scanId}`);
        if (res.ok) {
          const pastDecisions = await res.json();
          if (Array.isArray(pastDecisions) && pastDecisions.length > 0) {
            setDecisions((prev) => {
              const existingIds = new Set(prev.map((d) => d.id));
              const newItems: DecisionItem[] = pastDecisions
                .filter((d: { id?: string }) => !d.id || !existingIds.has(d.id))
                .map((d: {
                  id?: string;
                  timestamp?: string;
                  observation?: string;
                  reasoning?: string;
                  action_chosen?: string;
                  education_note?: string | null;
                }) => ({
                  id: d.id || `past-${Math.random()}`,
                  type: "agent_decision",
                  timestamp: d.timestamp || new Date().toISOString(),
                  observation: d.observation,
                  reasoning: d.reasoning,
                  action_chosen: d.action_chosen,
                  education_note: d.education_note,
                  severity: "normal",
                  learnMoreId: extractLearnMoreId(d.action_chosen, d.education_note, d.observation),
                }));
              return [...newItems, ...prev];
            });
          }
        }
      } catch {
        // past decisions endpoint not mandatory
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to load scan details";
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScanData();
  }, [scanId]);

  // WebSocket Live Updates
  useEffect(() => {
    if (!scanId) return;

    let isMounted = true;

    const handleMessage = (event: Record<string, unknown>) => {
      if (!isMounted) return;
      const type = event.type as string;
      const data = (event.data || {}) as Record<string, unknown>;

      if (type === "tool_run_update") {
        const toolRunId = data.tool_run_id ? String(data.tool_run_id) : undefined;
        const toolName = data.tool ? String(data.tool).toLowerCase() : "";
        const statusVal = data.status ? String(data.status) : "running";
        const resultCountVal = typeof data.result_count === "number" ? data.result_count : undefined;

        setToolRuns((prev) => {
          const idx = prev.findIndex(
            (t) =>
              (toolRunId && t.id === toolRunId) ||
              (toolName && t.plugin_name.toLowerCase() === toolName)
          );

          if (idx !== -1) {
            const nextList = [...prev];
            const current = nextList[idx];
            nextList[idx] = {
              ...current,
              status: statusVal,
              result_count: resultCountVal !== undefined ? resultCountVal : current.result_count,
              started_at: current.started_at || (statusVal === "running" ? new Date().toISOString() : null),
              completed_at: ["success", "failed", "timeout", "skipped"].includes(statusVal)
                ? current.completed_at || new Date().toISOString()
                : current.completed_at,
            };
            return nextList;
          } else if (data.tool) {
            const newRun: ToolRun = {
              id: toolRunId || `tool-${Date.now()}`,
              plugin_name: String(data.tool),
              status: statusVal,
              execution_order: prev.length + 1,
              started_at: new Date().toISOString(),
              completed_at: ["success", "failed", "timeout", "skipped"].includes(statusVal)
                ? new Date().toISOString()
                : null,
              result_count: resultCountVal !== undefined ? resultCountVal : 0,
            };
            return [...prev, newRun];
          }
          return prev;
        });
      } else if (type === "agent_decision") {
        const observation = data.observation ? String(data.observation) : "Analyzing target landscape...";
        const reasoning = data.reasoning ? String(data.reasoning) : "Evaluating reconnaissance ROI...";
        const actionChosen = data.action_chosen ? String(data.action_chosen) : "Proceeding with analysis plan";
        const educationNote = data.education_note ? String(data.education_note) : null;
        const timestamp = data.timestamp ? String(data.timestamp) : new Date().toISOString();

        const newItem: DecisionItem = {
          id: data.id ? String(data.id) : `decision-${Date.now()}-${Math.random()}`,
          type: "agent_decision",
          timestamp,
          observation,
          reasoning,
          action_chosen: actionChosen,
          education_note: educationNote,
          learnMoreId: extractLearnMoreId(actionChosen, educationNote, observation),
          severity: "normal",
        };
        setDecisions((prev) => [...prev, newItem]);
      } else if (type === "scope_filter") {
        const excluded = Array.isArray(data.excluded) ? (data.excluded as string[]) : [];
        const count = excluded.length;
        const msg = data.message ? String(data.message) : `Filtered ${count} out-of-scope targets`;

        const newScopeItem: DecisionItem = {
          id: `scope-${Date.now()}-${Math.random()}`,
          type: "scope_filter",
          timestamp: new Date().toISOString(),
          observation: msg,
          reasoning: "Strict scope compliance enforcement: Out-of-scope targets or third-party redirects must not be probed to ensure zero unauthorized traffic.",
          action_chosen: `Quarantined and pruned ${count > 0 ? `${count} targets (${excluded.slice(0, 3).join(", ")}${count > 3 ? "..." : ""})` : "out-of-scope targets"}`,
          education_note: "Scope defines exactly what you are authorized to test. Probing out-of-scope assets is a violation of program policies and computer crime laws.",
          learnMoreId: "concept:scope",
          excluded,
          severity: "scope",
        };
        setDecisions((prev) => [...prev, newScopeItem]);
      } else if (type === "scan_complete") {
        setScanJob((prev) =>
          prev ? { ...prev, status: "completed", completed_at: new Date().toISOString() } : null
        );
        const completeItem: DecisionItem = {
          id: `complete-${Date.now()}`,
          type: "agent_decision",
          timestamp: new Date().toISOString(),
          observation: "Reconnaissance execution lifecycle finished.",
          reasoning: "All scheduled tools, analysis tiers, and triage routines have executed successfully.",
          action_chosen: "Scan marked as completed. Discovered subdomains and findings persisted.",
          education_note: "Recon is continuous. Periodically re-run scans to catch newly spun-up staging environments and altered attack surfaces.",
          severity: "normal",
        };
        setDecisions((prev) => [...prev, completeItem]);
        // Auto-refresh the results tables when the scan finishes!
        fetchScanData();
      } else if (type === "connection_established") {
        setWsConnected(true);
      }
    };

    try {
      const ws = connectScanWS(
        scanId,
        handleMessage,
        () => {
          if (isMounted) setWsConnected(false);
        }
      );
      wsRef.current = ws;
      setWsConnected(true);
    } catch {
      setWsConnected(false);
    }

    return () => {
      isMounted = false;
      if (wsRef.current) {
        try {
          wsRef.current.close();
        } catch {
          // ignore close error
        }
        wsRef.current = null;
      }
    };
  }, [scanId]);

  // Scan Controls
  const handleTogglePause = async () => {
    if (!scanJob) return;
    const isCurrentlyPaused = scanJob.is_paused || scanJob.status === "paused";
    setActionLoading(isCurrentlyPaused ? "resume" : "pause");
    setFeedbackMessage(null);
    try {
      if (isCurrentlyPaused) {
        const res = await scans.resume(scanJob.id);
        setScanJob((prev) => (prev ? { ...prev, is_paused: false, status: "running" } : null));
        setFeedbackMessage({ text: res.message || "Scan resumed successfully", type: "success" });
      } else {
        const res = await scans.pause(scanJob.id);
        setScanJob((prev) => (prev ? { ...prev, is_paused: true, status: "paused" } : null));
        setFeedbackMessage({ text: res.message || "Scan paused successfully", type: "success" });
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to toggle scan pause state";
      setFeedbackMessage({ text: msg, type: "error" });
    } finally {
      setActionLoading(null);
    }
  };

  const handleSkipTool = async () => {
    if (!scanJob) return;
    setActionLoading("skip");
    setFeedbackMessage(null);
    try {
      const res = await scans.skipTool(scanJob.id);
      setFeedbackMessage({ text: res.message || "Skipped active tool", type: "success" });
      const updatedRuns = await scans.toolRuns(scanJob.id);
      setToolRuns(Array.isArray(updatedRuns) ? updatedRuns : []);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to skip current tool";
      setFeedbackMessage({ text: msg, type: "error" });
    } finally {
      setActionLoading(null);
    }
  };

  const handleCancelScan = async () => {
    if (!scanJob) return;
    if (!confirm("Are you sure you want to cancel this scan? All queued tool runs will be stopped.")) {
      return;
    }
    setActionLoading("cancel");
    setFeedbackMessage(null);
    try {
      const res = await scans.cancel(scanJob.id);
      setScanJob((prev) => (prev ? { ...prev, status: "cancelled", is_paused: false } : null));
      setFeedbackMessage({ text: res.message || "Scan cancelled", type: "success" });
      const updatedRuns = await scans.toolRuns(scanJob.id);
      setToolRuns(Array.isArray(updatedRuns) ? updatedRuns : []);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to cancel scan";
      setFeedbackMessage({ text: msg, type: "error" });
    } finally {
      setActionLoading(null);
    }
  };

  const getStatusIcon = (status: string) => {
    const s = (status || "").toLowerCase();
    if (s === "success" || s === "completed") {
      return <span className="text-base" title="Success">✅</span>;
    }
    if (s === "running" || s === "in_progress") {
      return (
        <span className="inline-block animate-spin text-base" title="Running">
          🔄
        </span>
      );
    }
    if (s === "failed" || s === "error" || s === "timeout") {
      return <span className="text-base" title="Failed">❌</span>;
    }
    if (s === "skipped") {
      return <span className="text-base" title="Skipped">⏭️</span>;
    }
    return <span className="text-base" title="Queued">⏳</span>;
  };

  const getProfileBadge = (profile: string) => {
    const p = (profile || "").toLowerCase();
    if (p === "stealth") {
      return (
        <span className="inline-flex items-center gap-1 rounded-full bg-emerald-50 px-2.5 py-0.5 text-xs font-semibold text-emerald-700 border border-emerald-200">
          🥷 Stealth
        </span>
      );
    }
    if (p === "autonomous") {
      return (
        <span className="inline-flex items-center gap-1 rounded-full bg-purple-50 px-2.5 py-0.5 text-xs font-semibold text-purple-700 border border-purple-200">
          🤖 Autonomous
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1 rounded-full bg-blue-50 px-2.5 py-0.5 text-xs font-semibold text-blue-700 border border-blue-200">
        ⚡ Standard
      </span>
    );
  };

  const getScanStatusBadge = (status: string, isPaused?: boolean) => {
    if (isPaused || status === "paused") {
      return (
        <span className="inline-flex items-center gap-1 rounded-full bg-amber-50 px-2.5 py-0.5 text-xs font-semibold text-amber-700 border border-amber-200">
          ⏸️ Paused
        </span>
      );
    }
    const s = (status || "").toLowerCase();
    if (s === "running" || s === "in_progress") {
      return (
        <span className="inline-flex items-center gap-1 rounded-full bg-blue-50 px-2.5 py-0.5 text-xs font-semibold text-blue-700 border border-blue-200 animate-pulse">
          🔄 Running
        </span>
      );
    }
    if (s === "completed") {
      return (
        <span className="inline-flex items-center gap-1 rounded-full bg-green-50 px-2.5 py-0.5 text-xs font-semibold text-green-700 border border-green-200">
          ✅ Completed
        </span>
      );
    }
    if (s === "failed") {
      return (
        <span className="inline-flex items-center gap-1 rounded-full bg-red-50 px-2.5 py-0.5 text-xs font-semibold text-red-700 border border-red-200">
          ❌ Failed
        </span>
      );
    }
    if (s === "cancelled") {
      return (
        <span className="inline-flex items-center gap-1 rounded-full bg-gray-100 px-2.5 py-0.5 text-xs font-semibold text-gray-700 border border-gray-300">
          🛑 Cancelled
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1 rounded-full bg-yellow-50 px-2.5 py-0.5 text-xs font-semibold text-yellow-700 border border-yellow-200">
        ⏳ Queued
      </span>
    );
  };

  const isScanTerminal =
    scanJob?.status === "completed" || scanJob?.status === "cancelled" || scanJob?.status === "failed";

  return (
    <div className="min-h-screen bg-gray-50 pl-56">

      <main className="max-w-7xl mx-auto px-6 py-8">
        {/* Breadcrumb & Navigation */}
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 pb-6 border-b border-gray-200">
          <div>
            <div className="flex items-center gap-2 text-xs font-medium text-gray-500 mb-1">
              <Link href="/scans" className="hover:text-indigo-600 transition-colors">
                Scans
              </Link>
              <span>/</span>
              <span className="text-gray-800 font-mono">
                {scanId ? `${scanId.slice(0, 8)}...` : "Details"}
              </span>
            </div>
            <h1 className="text-2xl font-bold tracking-tight text-gray-900 flex items-center gap-3">
              <span>🔍</span> Scan Job Details
              {scanJob && (
                <span className="font-mono text-sm font-normal text-gray-500 bg-gray-100 px-2.5 py-0.5 rounded-md border border-gray-200">
                  {scanJob.id}
                </span>
              )}
            </h1>
          </div>

          <div className="flex items-center gap-3">
            {/* Live Connection Badge */}
            <span
              className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-medium border ${
                wsConnected
                  ? "bg-emerald-50 text-emerald-700 border-emerald-200"
                  : "bg-gray-100 text-gray-600 border-gray-300"
              }`}
            >
              <span
                className={`h-2 w-2 rounded-full ${
                  wsConnected ? "bg-emerald-500 animate-pulse" : "bg-gray-400"
                }`}
              />
              {wsConnected ? "WebSocket Connected" : "Connecting..."}
            </span>

            <a 
              href={exports.scanReport(scanId)} 
              target="_blank"
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-sm font-medium text-white bg-indigo-600 rounded-lg hover:bg-indigo-700 shadow-sm"
            >
              📄 Download Report
            </a>
            <a 
              href={exports.rawLogs(scanId)} 
              target="_blank"
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-lg hover:bg-gray-50 shadow-sm transition-colors"
            >
              📋 Export Logs
            </a>
            <button
              onClick={fetchScanData}
              className="inline-flex items-center gap-1.5 rounded-lg border border-gray-300 bg-white px-3 py-1.5 text-xs font-medium text-gray-700 shadow-sm hover:bg-gray-50 hover:border-gray-400 transition-colors"
            >
              <span>🔄</span> Refresh
            </button>
          </div>
        </div>

        {/* Feedback alert */}
        {feedbackMessage && (
          <div
            className={`mt-4 rounded-lg p-3 text-xs font-medium flex items-center justify-between border ${
              feedbackMessage.type === "success"
                ? "bg-green-50 text-green-800 border-green-200"
                : "bg-red-50 text-red-800 border-red-200"
            }`}
          >
            <span>{feedbackMessage.text}</span>
            <button
              onClick={() => setFeedbackMessage(null)}
              className="ml-3 text-gray-400 hover:text-gray-700 font-bold"
            >
              ✕
            </button>
          </div>
        )}

        {/* Error Alert */}
        {error && (
          <div className="mt-6 rounded-lg bg-red-50 border border-red-200 p-4 text-sm text-red-700 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span>⚠️</span>
              <span>{error}</span>
            </div>
            <button
              onClick={fetchScanData}
              className="text-xs font-semibold text-red-800 underline hover:text-red-900"
            >
              Retry
            </button>
          </div>
        )}

        {/* Loading State */}
        {loading && !scanJob ? (
          <div className="mt-8 grid grid-cols-1 lg:grid-cols-3 gap-6 animate-pulse">
            <div className="lg:col-span-1 rounded-xl bg-white p-6 border border-gray-200 h-96 space-y-4">
              <div className="h-6 bg-gray-200 rounded w-1/2"></div>
              <div className="h-4 bg-gray-200 rounded w-3/4"></div>
              <div className="space-y-3 pt-4">
                {[1, 2, 3, 4].map((i) => (
                  <div key={i} className="h-12 bg-gray-100 rounded-lg"></div>
                ))}
              </div>
            </div>
            <div className="lg:col-span-2 rounded-xl bg-white p-6 border border-gray-200 h-96 space-y-4">
              <div className="h-6 bg-gray-200 rounded w-1/3"></div>
              <div className="space-y-3 pt-4">
                {[1, 2, 3].map((i) => (
                  <div key={i} className="h-24 bg-gray-100 rounded-lg"></div>
                ))}
              </div>
            </div>
          </div>
        ) : (
          /* Main Two-Panel Layout */
          <div className="mt-8 grid grid-cols-1 lg:grid-cols-3 gap-6 items-start">
            {/* ══════════════════════════════════════════════════════════════ */}
            {/* LEFT PANEL — Tool Timeline (1/3 width on lg)                   */}
            {/* ══════════════════════════════════════════════════════════════ */}
            <div className="lg:col-span-1 flex flex-col rounded-xl border border-gray-200 bg-white shadow-sm overflow-hidden">
              {/* Tool Progress Header */}
              <div className="border-b border-gray-200 p-5 bg-gradient-to-b from-gray-50/70 to-white">
                <div className="flex items-center justify-between">
                  <h2 className="text-lg font-bold text-gray-900 flex items-center gap-2">
                    <span>📊</span> Tool Progress
                  </h2>
                  {scanJob && getScanStatusBadge(scanJob.status, scanJob.is_paused)}
                </div>

                {/* Scan Metadata Badges */}
                {scanJob && (
                  <div className="mt-3 flex flex-wrap items-center gap-2">
                    {getProfileBadge(scanJob.profile)}

                    <span className="inline-flex items-center gap-1 rounded-full bg-gray-100 px-2.5 py-0.5 text-xs font-semibold text-gray-700 border border-gray-200">
                      ⚡ Rate limit: {scanJob.rate_limit || 10} req/s
                    </span>

                    {scanJob.current_tier && (
                      <span className="inline-flex items-center gap-1 rounded-full bg-indigo-50 px-2.5 py-0.5 text-xs font-semibold text-indigo-700 border border-indigo-200">
                        🎯 Tier: {scanJob.current_tier}
                      </span>
                    )}
                  </div>
                )}
              </div>

              {/* Tool Runs List */}
              <div className="p-4 space-y-3 max-h-[560px] overflow-y-auto">
                {toolRuns.length === 0 ? (
                  <div className="rounded-lg border border-dashed border-gray-200 p-6 text-center text-gray-400">
                    <p className="text-2xl">⏳</p>
                    <p className="mt-2 text-xs font-medium">No tool runs recorded yet</p>
                    <p className="text-[11px] text-gray-400 mt-0.5">
                      The execution governor will queue tools automatically.
                    </p>
                  </div>
                ) : (
                  toolRuns.map((run, index) => {
                    const duration = formatDuration(run.started_at, run.completed_at);
                    const isRunning = (run.status || "").toLowerCase() === "running";

                    return (
                      <div
                        key={run.id || index}
                        onClick={() => {
                          const fullRun = scanResults?.tool_runs?.find((tr: any) => tr.id === run.id) || run;
                          setSelectedToolRun(fullRun);
                        }}
                        className={`rounded-lg border p-3 cursor-pointer transition-all ${

                          isRunning
                            ? "border-indigo-300 bg-indigo-50/30 shadow-sm ring-1 ring-indigo-200"
                            : "border-gray-200 bg-white hover:border-gray-300"
                        }`}
                      >
                        <div className="flex items-center justify-between gap-2">
                          <div className="flex items-center gap-2.5 min-w-0">
                            <span className="shrink-0">{getStatusIcon(run.status)}</span>
                            <span className="font-mono text-sm font-semibold text-gray-900 truncate">
                              {run.plugin_name}
                            </span>
                          </div>

                          <div className="flex items-center gap-1.5 shrink-0">
                            {/* Duration Badge */}
                            {duration && (
                              <span
                                title="Execution Duration"
                                className="rounded bg-gray-100 px-1.5 py-0.5 text-[11px] font-mono text-gray-600 border border-gray-200"
                              >
                                ⏱️ {duration}
                              </span>
                            )}

                            {/* Result Count Badge */}
                            <span className="rounded-full bg-indigo-50 px-2 py-0.5 text-[11px] font-semibold text-indigo-700 border border-indigo-200">
                              {run.result_count ?? 0} results
                            </span>
                          </div>
                        </div>

                        {/* Extra Run Details */}
                        <div className="mt-2 flex items-center justify-between text-[11px] text-gray-400">
                          <span className="capitalize">
                            Status: <strong className="text-gray-600 font-medium">{run.status}</strong>
                          </span>
                          <span>Order #{run.execution_order ?? index + 1}</span>
                        </div>
                      </div>
                    );
                  })
                )}
              </div>

              {/* Live Control Buttons at the Bottom */}
              <div className="border-t border-gray-200 p-4 bg-gray-50/50">
                <div className="text-xs font-semibold text-gray-500 mb-2 uppercase tracking-wider">
                  Live Controls
                </div>

                <div className="grid grid-cols-3 gap-2">
                  {/* Pause / Resume Button */}
                  <button
                    onClick={handleTogglePause}
                    disabled={isScanTerminal || actionLoading !== null}
                    className="inline-flex items-center justify-center gap-1 rounded-lg border border-gray-300 bg-white px-2.5 py-2 text-xs font-medium text-gray-700 shadow-sm hover:bg-gray-100 hover:border-gray-400 active:bg-gray-200 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                  >
                    {actionLoading === "pause" || actionLoading === "resume" ? (
                      <span className="inline-block animate-spin text-xs">🔄</span>
                    ) : scanJob?.is_paused || scanJob?.status === "paused" ? (
                      "▶️ Resume"
                    ) : (
                      "⏸️ Pause"
                    )}
                  </button>

                  {/* Skip Tool Button */}
                  <button
                    onClick={handleSkipTool}
                    disabled={isScanTerminal || actionLoading !== null}
                    className="inline-flex items-center justify-center gap-1 rounded-lg border border-gray-300 bg-white px-2.5 py-2 text-xs font-medium text-gray-700 shadow-sm hover:bg-gray-100 hover:border-gray-400 active:bg-gray-200 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                  >
                    {actionLoading === "skip" ? (
                      <span className="inline-block animate-spin text-xs">🔄</span>
                    ) : (
                      "⏭️ Skip Tool"
                    )}
                  </button>

                  {/* Cancel Scan Button */}
                  <button
                    onClick={handleCancelScan}
                    disabled={isScanTerminal || actionLoading !== null}
                    className="inline-flex items-center justify-center gap-1 rounded-lg border border-red-200 bg-white px-2.5 py-2 text-xs font-medium text-red-600 shadow-sm hover:bg-red-50 hover:border-red-300 active:bg-red-100 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                  >
                    {actionLoading === "cancel" ? (
                      <span className="inline-block animate-spin text-xs">🔄</span>
                    ) : (
                      "🛑 Cancel Scan"
                    )}
                  </button>
                </div>
              </div>
            </div>

            {/* ══════════════════════════════════════════════════════════════ */}
            {/* RIGHT PANEL — Agent Decision Trail (2/3 width on lg)           */}
            {/* ══════════════════════════════════════════════════════════════ */}
            <div className="lg:col-span-2 flex flex-col rounded-xl border border-gray-200 bg-white shadow-sm overflow-hidden">
              {/* Agent Decision Trail Header */}
              <div className="border-b border-gray-200 p-5 bg-gradient-to-b from-gray-50/70 to-white flex items-center justify-between">
                <div>
                  <h2 className="text-lg font-bold text-gray-900 flex items-center gap-2">
                    <span>🧠</span> Agent Decision Trail
                  </h2>
                  <p className="mt-0.5 text-xs text-gray-500">
                    Real-time AI reasoning, scope policy checks, and autonomous execution trail.
                  </p>
                </div>

                <div className="flex items-center gap-2">
                  <span className="rounded-full bg-indigo-100 px-2.5 py-0.5 text-xs font-semibold text-indigo-700">
                    {decisions.length} events
                  </span>
                </div>
              </div>

              {/* Scrollable Decision Cards List (auto-scroll) */}
              <div className="p-5 space-y-4 max-h-[640px] overflow-y-auto">
                {decisions.length === 0 ? (
                  <div className="rounded-xl border border-dashed border-gray-200 p-12 text-center text-gray-400">
                    <p className="text-4xl animate-bounce">🧠</p>
                    <p className="mt-3 text-base font-medium text-gray-700">
                      Awaiting Agent Decisions
                    </p>
                    <p className="mt-1 text-xs text-gray-500 max-w-sm mx-auto">
                      As the AI agent analyzes targets, evaluates ROI scores, and chooses tools,
                      each step of its reasoning will stream live here.
                    </p>
                  </div>
                ) : (
                  decisions.map((item, index) => {
                    // Card border styling: indigo for normal, amber for scope events, red for errors
                    const borderClass =
                      item.severity === "scope"
                        ? "border-l-4 border-l-amber-500 border-gray-200"
                        : item.severity === "error"
                        ? "border-l-4 border-l-red-500 border-gray-200"
                        : "border-l-4 border-l-indigo-600 border-gray-200";

                    return (
                      <div
                        key={item.id || index}
                        className={`rounded-r-xl rounded-l-sm border bg-white p-4 shadow-sm transition-all hover:shadow-md ${borderClass}`}
                      >
                        {/* Header: Timestamp and Event Type */}
                        <div className="flex items-center justify-between gap-2 border-b border-gray-100 pb-2">
                          <div className="flex items-center gap-2">
                            <span
                              className={`rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${
                                item.severity === "scope"
                                  ? "bg-amber-100 text-amber-800"
                                  : item.severity === "error"
                                  ? "bg-red-100 text-red-800"
                                  : "bg-indigo-100 text-indigo-800"
                              }`}
                            >
                              {item.type === "scope_filter"
                                ? "Scope Guard"
                                : item.type === "agent_decision"
                                ? "Agent Decision"
                                : item.type}
                            </span>
                          </div>
                          <span className="font-mono text-xs text-gray-400">
                            {formatTime(item.timestamp)}
                          </span>
                        </div>

                        {/* Observation Line */}
                        {item.observation && (
                          <div className="mt-2.5 text-sm text-gray-800 leading-relaxed">
                            <span className="font-semibold text-gray-900">🔍 Observation: </span>
                            {item.observation}
                          </div>
                        )}

                        {/* Reasoning Line */}
                        {item.reasoning && (
                          <div className="mt-1.5 text-sm text-gray-700 leading-relaxed">
                            <span className="font-semibold text-gray-900">🧠 Reasoning: </span>
                            {item.reasoning}
                          </div>
                        )}

                        {/* Action Line */}
                        {item.action_chosen && (
                          <div className="mt-1.5 text-sm font-medium text-indigo-700 leading-relaxed">
                            <span className="font-semibold text-gray-900">⚡ Action: </span>
                            {item.action_chosen}
                          </div>
                        )}

                        {/* Education Note with LearnMore Link */}
                        {item.education_note && (
                          <div className="mt-3.5 rounded-lg border border-indigo-100 bg-indigo-50/60 p-3">
                            <div className="flex items-start gap-2">
                              <span className="text-base shrink-0">🎓</span>
                              <div className="text-xs text-indigo-950 leading-relaxed">
                                <span className="font-semibold">Educational Note: </span>
                                {item.education_note}
                              </div>
                            </div>

                            {item.learnMoreId && (
                              <div className="mt-2.5 pt-2 border-t border-indigo-200/50">
                                <LearnMore contentId={item.learnMoreId} />
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    );
                  })
                )}

                {/* Auto-scroll target element */}
                <div ref={decisionEndRef} />
              </div>
            </div>
          </div>
        )}

        {/* Scan Results Section */}
        {!loading && scanResults && (
          <div className="mt-6 rounded-xl border border-gray-200 bg-white p-6 shadow-sm">
            <h2 className="text-lg font-bold text-gray-900 mb-4">📊 Scan Results</h2>
            
            {/* Subdomains */}
            {scanResults.discovered_subdomains && scanResults.discovered_subdomains.length > 0 && (
              <div className="mb-6">
                <div className="flex items-center justify-between mb-3">
                  <h3 className="text-sm font-semibold text-gray-700">
                    🌐 Discovered Hosts / Domains
                    <span className="ml-2 px-2 py-0.5 bg-indigo-100 text-indigo-800 rounded-full text-xs">
                      {scanResults.discovered_subdomains.length}
                    </span>
                  </h3>
                  {scanResults.scan?.target_id && (
                    <div className="flex gap-2">
                      <a href={exports.subdomainsTxt(scanResults.scan.target_id)} target="_blank" className="text-xs px-2 py-1 border border-gray-300 hover:bg-gray-50 rounded text-gray-700">
                        📥 Export TXT
                      </a>
                      <a href={exports.subdomainsCsv(scanResults.scan.target_id)} target="_blank" className="text-xs px-2 py-1 border border-gray-300 hover:bg-gray-50 rounded text-gray-700">
                        📥 Export CSV
                      </a>
                    </div>
                  )}
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-gray-200">
                        <th className="text-left py-2 px-3 text-xs font-semibold text-gray-600 uppercase">FQDN</th>
                        <th className="text-left py-2 px-3 text-xs font-semibold text-gray-600 uppercase">IP Address</th>
                        <th className="text-left py-2 px-3 text-xs font-semibold text-gray-600 uppercase">HTTP Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {scanResults.discovered_subdomains.map((sub: any) => (
                        <tr key={sub.id} className="border-b border-gray-100 hover:bg-gray-50">
                          <td className="py-2 px-3 font-mono text-sm text-gray-900">{sub.fqdn}</td>
                          <td className="py-2 px-3 text-sm text-gray-600">{sub.ip_address || '—'}</td>
                          <td className="py-2 px-3">
                            {sub.http_status ? (
                              <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                                sub.http_status >= 200 && sub.http_status < 300 ? 'bg-green-100 text-green-800' :
                                sub.http_status >= 300 && sub.http_status < 400 ? 'bg-yellow-100 text-yellow-800' :
                                sub.http_status === 403 ? 'bg-orange-100 text-orange-800' :
                                'bg-red-100 text-red-800'
                              }`}>{sub.http_status}</span>
                            ) : <span className="text-gray-400">—</span>}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* Findings */}
            {scanResults.findings && scanResults.findings.length > 0 && (
              <div className="mb-6">
                <h3 className="text-sm font-semibold text-gray-700 mb-3">
                  🐛 Vulnerability Findings
                  <span className="ml-2 px-2 py-0.5 bg-red-100 text-red-800 rounded-full text-xs">
                    {scanResults.findings.length}
                  </span>
                </h3>
                <div className="space-y-2">
                  {scanResults.findings.map((f: any) => (
                    <div key={f.id} className="p-3 rounded-lg border border-gray-200 bg-gray-50">
                      <div className="flex items-center gap-2">
                        <span className={`px-2 py-0.5 rounded text-xs font-bold uppercase ${
                          f.severity === 'critical' ? 'bg-red-600 text-white' :
                          f.severity === 'high' ? 'bg-orange-500 text-white' :
                          f.severity === 'medium' ? 'bg-yellow-400 text-gray-900' :
                          f.severity === 'low' ? 'bg-blue-100 text-blue-800' :
                          'bg-gray-200 text-gray-700'
                        }`}>{f.severity}</span>
                        <span className="font-semibold text-sm text-gray-900">{f.title}</span>
                      </div>
                      {f.description && <p className="mt-1 text-xs text-gray-600">{f.description}</p>}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Raw Tool Outputs (for tools that don't produce structured DB models) */}
            {scanResults.tool_runs && scanResults.tool_runs.some((tr: any) => tr.stdout && !['subfinder', 'httpx', 'nuclei'].includes(tr.tool_name)) && (
              <div>
                <h3 className="text-sm font-semibold text-gray-700 mb-3">
                  📋 Raw Discovery Logs
                </h3>
                <div className="space-y-3">
                  {scanResults.tool_runs
                    .filter((tr: any) => tr.stdout && !['subfinder', 'httpx', 'nuclei'].includes(tr.tool_name))
                    .map((tr: any) => (
                      <details key={tr.id} className="group rounded-lg border border-gray-200 bg-white overflow-hidden shadow-sm">
                        <summary className="cursor-pointer bg-gray-50 p-3 text-sm font-semibold text-gray-900 hover:bg-gray-100 flex items-center justify-between">
                          <span>{tr.tool_name.toUpperCase()}</span>
                          <div className="flex items-center gap-3">
                            <span className="text-xs bg-gray-200 text-gray-700 px-2 py-0.5 rounded-full font-medium">
                              {tr.stdout.includes('------------------------------------------------------------') 
                                ? tr.stdout.split('------------------------------------------------------------')[1].split('\n').filter((l: string) => l.trim()).length 
                                : tr.stdout.split('\n').filter((l: string) => l.trim()).length} results
                            </span>
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                const blob = new Blob([tr.stdout || ''], { type: 'text/plain' });
                                const url = URL.createObjectURL(blob);
                                const a = document.createElement('a');
                                a.href = url;
                                a.download = `scan_${scanId}_${tr.tool_name}_logs.txt`;
                                document.body.appendChild(a);
                                a.click();
                                document.body.removeChild(a);
                                URL.revokeObjectURL(url);
                              }}
                              className="text-xs bg-indigo-50 text-indigo-700 border border-indigo-200 hover:bg-indigo-100 px-2.5 py-1 rounded-md font-medium transition-colors"
                              title={`Download ${tr.tool_name.toUpperCase()} logs`}
                            >
                              📥 Download
                            </button>
                          </div>
                        </summary>
                        <div className="p-4 border-t border-gray-200 bg-white">
                          {(() => {
                            const raw = tr.stdout || '';
                            let aiText = '';
                            let logs = raw;
                            
                            if (raw.includes('------------------------------------------------------------')) {
                              const parts = raw.split('------------------------------------------------------------');
                              aiText = parts[0].trim();
                              logs = parts[1].trim();
                            }

                            return (
                              <div className="space-y-4">
                                {aiText && (
                                  <div className="bg-blue-50 border border-blue-100 rounded-lg p-3 text-sm text-blue-900 whitespace-pre-wrap leading-relaxed shadow-sm">
                                    {aiText}
                                  </div>
                                )}
                                
                                {logs && (
                                  <div className="bg-[#1e1e1e] rounded-lg p-3 max-h-80 overflow-y-auto">
                                    <ul className="space-y-1">
                                      {logs.split('\n').map((line: string, i: number) => {
                                        if (!line.trim()) return null;
                                        return (
                                          <li key={i} className="text-[13px] font-mono text-green-400 break-all border-b border-gray-800 pb-1 last:border-0 last:pb-0">
                                            {line}
                                          </li>
                                        );
                                      })}
                                    </ul>
                                  </div>
                                )}
                              </div>
                            );
                          })()}
                        </div>
                      </details>
                    ))}
                </div>
              </div>
            )}

            {/* Empty state */}
            {(!scanResults.discovered_subdomains || scanResults.discovered_subdomains.length === 0) && 
             (!scanResults.findings || scanResults.findings.length === 0) && 
             (!scanResults.tool_runs || !scanResults.tool_runs.some((tr: any) => tr.stdout && !['subfinder', 'httpx', 'nuclei'].includes(tr.tool_name))) && (
              <p className="text-sm text-gray-500 text-center py-4">No results available yet.</p>
            )}
          </div>
        )}
      </main>

      {/* Tool Result Modal */}
      {selectedToolRun && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-gray-900/50 backdrop-blur-sm" onClick={() => setSelectedToolRun(null)}>
          <div className="bg-white rounded-xl shadow-xl w-full max-w-4xl max-h-[90vh] flex flex-col overflow-hidden" onClick={e => e.stopPropagation()}>
            <div className="flex justify-between items-center p-4 border-b border-gray-200">
              <h2 className="text-xl font-bold text-gray-900 flex items-center gap-2">
                <span>{getStatusIcon(selectedToolRun.status)}</span>
                {selectedToolRun.tool_name || selectedToolRun.plugin_name} Results
              </h2>
              <button onClick={() => setSelectedToolRun(null)} className="text-gray-500 hover:text-gray-900 bg-gray-100 hover:bg-gray-200 rounded-full w-8 h-8 flex items-center justify-center font-bold transition-colors">✕</button>
            </div>
            
            <div className="flex-1 overflow-y-auto p-0 bg-gray-50 flex flex-col">
              {/* AI Hacker Analysis */}
              <div className="m-4 p-5 bg-indigo-50 border border-indigo-200 rounded-xl shadow-sm relative overflow-hidden">
                <div className="absolute top-0 right-0 p-4 opacity-10 text-4xl">🤖</div>
                <h3 className="text-indigo-900 font-bold text-sm mb-2 flex items-center gap-2">
                  <span>🤖</span> AI Analysis
                </h3>
                <p className="text-sm text-indigo-900 leading-relaxed font-medium">
                  {generateHackerAnalysis(
                    selectedToolRun.tool_name || selectedToolRun.plugin_name, 
                    selectedToolRun.stdout || "", 
                    selectedToolRun.result_count || 0
                  )}
                </p>
              </div>

              {/* Styled Results Data */}
              <div className="mx-4 mb-4">
                <h3 className="text-gray-700 font-bold text-sm mb-2">Parsed Target Data</h3>
                
                {selectedToolRun.stderr && (
                  <div className="mb-4 bg-red-50 border border-red-200 rounded-lg p-3">
                    <h4 className="text-red-800 font-bold text-xs mb-1 uppercase tracking-wider">Error Output (stderr)</h4>
                    <div className="font-mono text-xs text-red-600 whitespace-pre-wrap max-h-40 overflow-y-auto">
                      {selectedToolRun.stderr}
                    </div>
                  </div>
                )}

                <div className="bg-white border border-gray-200 rounded-lg shadow-sm overflow-hidden">
                  <div className="max-h-96 overflow-y-auto p-2 font-mono text-xs text-gray-800 whitespace-pre-wrap">
                    {selectedToolRun.stdout ? (
                      selectedToolRun.stdout.split('\n').filter(Boolean).map((line: string, i: number) => {
                        let isHighlight = line.includes('high') || line.includes('critical') || line.includes('200') || line.includes('403');
                        return (
                            <div key={i} className={`py-1.5 px-2 border-b border-gray-50 last:border-0 hover:bg-gray-50 ${isHighlight ? 'text-indigo-700 font-semibold' : ''}`}>
                                {line}
                            </div>
                        );
                      })
                    ) : (
                      <div className="p-4 text-gray-400 italic">No output recorded. Tool might have failed, found zero results, or is still running.</div>
                    )}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
