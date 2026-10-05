"use client";

import { useState, useEffect } from "react";
import Link from "next/link";
import { exports } from "@/lib/api";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api/v1";

interface Finding {
  id: string;
  subdomain_id: string;
  title: string;
  description: string | null;
  severity: string;
  status: string;
  discovery_tool: string;
  matched_at: string | null;
  is_false_positive: boolean;
  created_at: string;
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-100 text-red-800 border-red-200",
  high: "bg-orange-100 text-orange-800 border-orange-200",
  medium: "bg-yellow-100 text-yellow-800 border-yellow-200",
  low: "bg-blue-100 text-blue-800 border-blue-200",
  info: "bg-gray-100 text-gray-600 border-gray-200",
};

const STATUS_LABELS: Record<string, { label: string; color: string }> = {
  open: { label: "Open", color: "bg-red-50 text-red-700" },
  confirmed: { label: "Confirmed", color: "bg-orange-50 text-orange-700" },
  false_positive: { label: "False Positive", color: "bg-gray-50 text-gray-500" },
  resolved: { label: "Resolved", color: "bg-green-50 text-green-700" },
  accepted_risk: { label: "Accepted Risk", color: "bg-yellow-50 text-yellow-700" },
};

export default function FindingsPage() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [severityFilter, setSeverityFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState("");

  useEffect(() => {
    setLoading(true);
    fetch(`${API_BASE}/findings/`)
      .then((r) => r.json())
      .then((data) => setFindings(Array.isArray(data) ? data : []))
      .catch(() => setFindings([]))
      .finally(() => setLoading(false));
  }, []);

  const filtered = findings.filter((f) => {
    if (severityFilter && f.severity !== severityFilter) return false;
    if (statusFilter && f.status !== statusFilter) return false;
    return true;
  });

  const severityCounts = findings.reduce(
    (acc, f) => {
      acc[f.severity] = (acc[f.severity] || 0) + 1;
      return acc;
    },
    {} as Record<string, number>
  );

  return (
    <div className="min-h-screen bg-gray-50 pl-56">
      <div className="mx-auto max-w-7xl px-6 py-8">
        {/* Header */}
        <div className="mb-8 flex items-start justify-between">
          <div>
            <h1 className="text-2xl font-bold text-gray-900">🐛 Findings</h1>
            <p className="mt-1 text-gray-500">
              Vulnerabilities and issues discovered across all targets
            </p>
          </div>
          <div className="flex items-center gap-2">
            <a href={exports.findingsCsv()} target="_blank" className="inline-flex items-center gap-1.5 px-3 py-1.5 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-lg hover:bg-gray-50">
              📥 Export CSV
            </a>
            <a href={exports.findingsJson()} target="_blank" className="inline-flex items-center gap-1.5 px-3 py-1.5 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-lg hover:bg-gray-50">
              📥 Export JSON
            </a>
          </div>
        </div>

        {/* Severity summary cards */}
        <div className="mb-6 grid grid-cols-5 gap-3">
          {["critical", "high", "medium", "low", "info"].map((sev) => (
            <button
              key={sev}
              onClick={() => setSeverityFilter(severityFilter === sev ? "" : sev)}
              className={`rounded-lg border p-3 text-center transition-all ${
                severityFilter === sev
                  ? SEVERITY_COLORS[sev]
                  : "border-gray-200 bg-white hover:border-gray-300"
              }`}
            >
              <div className="text-2xl font-bold text-gray-900">{severityCounts[sev] || 0}</div>
              <div className="text-xs font-medium capitalize text-gray-700">{sev}</div>
            </button>
          ))}
        </div>

        {/* Status filter */}
        <div className="mb-6 flex gap-2">
          <span className="self-center text-sm text-gray-900">Status:</span>
          {["", "open", "confirmed", "false_positive", "resolved"].map((s) => (
            <button
              key={s}
              onClick={() => setStatusFilter(s)}
              className={`rounded-lg px-3 py-1.5 text-xs font-medium transition-colors ${
                statusFilter === s
                  ? "bg-indigo-100 text-indigo-900"
                  : "bg-white text-gray-700 border border-gray-200 hover:bg-gray-50"
              }`}
            >
              {s === "" ? "All" : STATUS_LABELS[s]?.label || s}
            </button>
          ))}
        </div>

        {/* Loading */}
        {loading && (
          <div className="space-y-3">
            {[1, 2, 3, 4].map((i) => (
              <div key={i} className="h-20 animate-pulse rounded-xl bg-gray-200" />
            ))}
          </div>
        )}

        {/* Findings list */}
        {!loading && filtered.length > 0 && (
          <div className="space-y-3">
            {filtered.map((finding) => (
              <div
                key={finding.id}
                className={`rounded-xl border bg-white p-5 shadow-sm transition-shadow hover:shadow-md ${
                  finding.is_false_positive ? "opacity-50" : ""
                }`}
              >
                <div className="flex items-start justify-between gap-4">
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <span
                        className={`rounded-full px-2.5 py-0.5 text-xs font-semibold uppercase ${
                          SEVERITY_COLORS[finding.severity] || SEVERITY_COLORS.info
                        }`}
                      >
                        {finding.severity}
                      </span>
                      <h3 className="font-semibold text-gray-900">{finding.title}</h3>
                    </div>
                    {finding.description && (
                      <p className="mt-1 text-sm text-gray-600 line-clamp-2">
                        {finding.description}
                      </p>
                    )}
                    <div className="mt-2 flex items-center gap-3 text-xs text-gray-400">
                      <span>🔧 {finding.discovery_tool}</span>
                      {finding.matched_at && <span>📍 {finding.matched_at}</span>}
                      <span>
                        {new Date(finding.created_at).toLocaleDateString()}
                      </span>
                    </div>
                  </div>
                  <span
                    className={`shrink-0 rounded-full px-2.5 py-0.5 text-xs font-medium ${
                      STATUS_LABELS[finding.status]?.color || "bg-gray-100 text-gray-600"
                    }`}
                  >
                    {STATUS_LABELS[finding.status]?.label || finding.status}
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Empty state */}
        {!loading && filtered.length === 0 && (
          <div className="rounded-xl border border-gray-200 bg-white p-12 text-center">
            <p className="text-4xl">🔍</p>
            <p className="mt-4 text-lg font-medium text-gray-600">No findings yet</p>
            <p className="mt-1 text-sm text-gray-400">
              Run a scan to start discovering vulnerabilities
            </p>
            <Link
              href="/scans"
              className="mt-4 inline-block rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-700"
            >
              Start a Scan
            </Link>
          </div>
        )}
      </div>
    </div>
  );
}
