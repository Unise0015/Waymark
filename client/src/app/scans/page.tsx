"use client";

import { useState, useEffect } from "react";
import Link from "next/link";
import { LearnMore } from "@/components/LearnMore";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api/v1";

interface ScanJob {
  id: string;
  target_type: string;
  target_id: string;
  profile: string;
  status: string;
  current_tier: string;
  is_paused: boolean;
  rate_limit: number;
  started_at: string | null;
  completed_at: string | null;
}

const STATUS_CONFIG: Record<string, { icon: string; color: string; label: string }> = {
  queued: { icon: "⏳", color: "bg-gray-100 text-gray-600", label: "Queued" },
  running: { icon: "🔄", color: "bg-blue-100 text-blue-700", label: "Running" },
  completed: { icon: "✅", color: "bg-green-100 text-green-700", label: "Completed" },
  failed: { icon: "❌", color: "bg-red-100 text-red-700", label: "Failed" },
  cancelled: { icon: "🛑", color: "bg-gray-100 text-gray-500", label: "Cancelled" },
};

const PROFILE_LABELS: Record<string, { label: string; desc: string }> = {
  stealth: { label: "🥷 Stealth", desc: "Passive only" },
  standard: { label: "⚡ Standard", desc: "Passive + Validation" },
  autonomous: { label: "🤖 Autonomous", desc: "All tiers auto" },
  custom: { label: "🎛️ Custom", desc: "Manual tool selection" },
};

const TIER_LABELS: Record<string, string> = {
  passive: "Tier 1: Passive",
  validation: "Tier 2: Validation",
  active: "Tier 3: Active",
};

export default function ScansPage() {
  const [scans, setScans] = useState<ScanJob[]>([]);
  const [loading, setLoading] = useState(true);
  const [showNew, setShowNew] = useState(false);

  useEffect(() => {
    // Fetch scans — this endpoint may not exist yet, gracefully handle
    fetch(`${API_BASE}/scans/`)
      .then((r) => r.json())
      .then((data) => setScans(Array.isArray(data) ? data : []))
      .catch(() => setScans([]))
      .finally(() => setLoading(false));
  }, []);

  const runningCount = scans.filter((s) => s.status === "running").length;

  return (
    <div className="min-h-screen bg-gray-50 pl-56">
      <div className="mx-auto max-w-7xl px-6 py-8">
        {/* Header */}
        <div className="mb-8 flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-gray-900">🔍 Scans</h1>
            <p className="mt-1 text-gray-500">
              {runningCount > 0
                ? `${runningCount} scan${runningCount > 1 ? "s" : ""} running`
                : "Manage and monitor your reconnaissance scans"}
            </p>
          </div>
        </div>

        {/* Loading */}
        {loading && (
          <div className="space-y-3">
            {[1, 2, 3].map((i) => (
              <div key={i} className="h-24 animate-pulse rounded-xl bg-gray-200" />
            ))}
          </div>
        )}

        {/* Scan list */}
        {!loading && scans.length > 0 && (
          <div className="space-y-3">
            {scans.map((scan) => {
              const statusCfg = STATUS_CONFIG[scan.status] || STATUS_CONFIG.queued;
              const profileCfg = PROFILE_LABELS[scan.profile] || PROFILE_LABELS.standard;

              return (
                <Link
                  key={scan.id}
                  href={`/scans/${scan.id}`}
                  className="block rounded-xl border border-gray-200 bg-white p-5 shadow-sm transition-all hover:shadow-md hover:border-indigo-200"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <span className={`rounded-full px-3 py-1 text-xs font-semibold ${statusCfg.color}`}>
                        {statusCfg.icon} {statusCfg.label}
                      </span>
                      <span className="text-sm font-medium text-gray-900">
                        {scan.target_type}: {scan.target_id.slice(0, 8)}...
                      </span>
                    </div>
                    <div className="flex items-center gap-3 text-sm text-gray-500">
                      <span>{profileCfg.label}</span>
                      <span className="rounded bg-gray-100 px-2 py-0.5 text-xs">
                        {TIER_LABELS[scan.current_tier] || scan.current_tier}
                      </span>
                      {scan.is_paused && (
                        <span className="rounded bg-amber-100 px-2 py-0.5 text-xs text-amber-700">
                          ⏸️ Paused
                        </span>
                      )}
                    </div>
                  </div>
                  <div className="mt-2 flex items-center gap-4 text-xs text-gray-400">
                    <span>Rate: {scan.rate_limit} req/s</span>
                    {scan.started_at && (
                      <span>Started: {new Date(scan.started_at).toLocaleString()}</span>
                    )}
                    {scan.completed_at && (
                      <span>Completed: {new Date(scan.completed_at).toLocaleString()}</span>
                    )}
                  </div>
                </Link>
              );
            })}
          </div>
        )}

        {/* Empty state */}
        {!loading && scans.length === 0 && (
          <div className="rounded-xl border border-gray-200 bg-white p-12 text-center">
            <p className="text-4xl">🔍</p>
            <p className="mt-4 text-lg font-medium text-gray-600">No scans yet. Go to a Company, add a wildcard target, and click 'Start Scan' to begin reconnaissance.</p>
            <Link
              href="/companies"
              className="mt-4 inline-block rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-700"
            >
              Go to Companies
            </Link>
          </div>
        )}

        {/* Education */}
        <div className="mt-8">
          <LearnMore contentId="methodology:recon_pipeline" />
        </div>
      </div>
    </div>
  );
}
