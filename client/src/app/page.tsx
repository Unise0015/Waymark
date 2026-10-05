"use client";

import { useState, useEffect } from "react";
import Link from "next/link";
import { companies, scans, findings, education } from "@/lib/api";
import { LearnMore } from "@/components/LearnMore";

interface DashboardStats {
  companyCount: number;
  activeScanCount: number;
  findingCount: number;
  avgRoiScore: number;
}

export default function DashboardPage() {
  const [stats, setStats] = useState<DashboardStats>({
    companyCount: 0,
    activeScanCount: 0,
    findingCount: 0,
    avgRoiScore: 0,
  });
  const [loading, setLoading] = useState(true);
  const [recentScans, setRecentScans] = useState<any[]>([]);

  useEffect(() => {
    let isMounted = true;
    setLoading(true);

    Promise.allSettled([
      companies.list(),
      scans.list(),
      findings.list(),
    ]).then(([companiesRes, scansRes, findingsRes]) => {
      if (!isMounted) return;

      const companyCount =
        companiesRes.status === "fulfilled" && Array.isArray(companiesRes.value)
          ? companiesRes.value.length
          : 0;

      const fetchedScans = scansRes.status === "fulfilled" && Array.isArray(scansRes.value) ? scansRes.value : [];
      setRecentScans(fetchedScans);

      const activeScanCount = fetchedScans.filter((s: any) => s.status === 'running' || s.status === 'queued').length;

      const findingCount =
        findingsRes.status === "fulfilled" && Array.isArray(findingsRes.value)
          ? findingsRes.value.length
          : 0;

      setStats({
        companyCount,
        activeScanCount,
        findingCount,
        avgRoiScore: 0,
      });
      setLoading(false);
    });

    return () => {
      isMounted = false;
    };
  }, []);

  const statCards = [
    {
      label: "Total Companies",
      value: stats.companyCount,
      icon: "🏢",
    },
    {
      label: "Active Scans",
      value: stats.activeScanCount,
      icon: "⚡",
    },
    {
      label: "Total Findings",
      value: stats.findingCount,
      icon: "🐛",
    },
    {
      label: "ROI Score Avg",
      value: stats.avgRoiScore,
      icon: "🎯",
    },
  ];

  return (
    <div className="min-h-screen bg-gray-50 pl-56">
      <div className="max-w-7xl mx-auto px-6 py-8 space-y-8">
        {/* Header */}
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Dashboard</h1>
          <p className="mt-1 text-sm text-gray-500">Your reconnaissance overview</p>
        </div>

        {/* 4 Stat Cards in a Grid (2x2 on mobile, 4 columns on desktop) */}
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-4 sm:gap-6">
          {statCards.map((card) => (
            <div
              key={card.label}
              className="rounded-xl border border-gray-200 bg-white p-6 shadow-sm"
            >
              <div className="flex items-center justify-between">
                <span className="text-2xl">{card.icon}</span>
              </div>
              <p className="mt-4 text-sm text-gray-500">{card.label}</p>
              {loading ? (
                <div className="mt-2 h-9 w-16 animate-pulse rounded bg-gray-200" />
              ) : (
                <p className="mt-2 text-3xl font-bold text-black">{card.value}</p>
              )}
            </div>
          ))}
        </div>

        {/* Quick Actions */}
        <div>
          <h2 className="text-base font-semibold text-gray-900 mb-4">Quick Actions</h2>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 sm:gap-6">
            <Link
              href="/companies"
              className="group block rounded-xl border border-gray-200 bg-white p-5 shadow-sm transition hover:border-indigo-300 hover:shadow-md"
            >
              <div className="flex items-center gap-4">
                <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-indigo-50 text-xl font-bold text-indigo-600 transition-colors group-hover:bg-indigo-100">
                  +
                </div>
                <div>
                  <h3 className="font-semibold text-gray-900 transition-colors group-hover:text-indigo-600">
                    Add Company
                  </h3>
                  <p className="mt-1 text-sm text-gray-500">
                    Register a new company and authorize recon scope
                  </p>
                </div>
              </div>
            </Link>

            <Link
              href="/scans"
              className="group block rounded-xl border border-gray-200 bg-white p-5 shadow-sm transition hover:border-indigo-300 hover:shadow-md"
            >
              <div className="flex items-center gap-4">
                <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-indigo-50 text-xl text-indigo-600 transition-colors group-hover:bg-indigo-100">
                  🔍
                </div>
                <div>
                  <h3 className="font-semibold text-gray-900 transition-colors group-hover:text-indigo-600">
                    Start Scan
                  </h3>
                  <p className="mt-1 text-sm text-gray-500">
                    Launch multi-tier scanning across discovered subdomains
                  </p>
                </div>
              </div>
            </Link>
          </div>
        </div>

        {/* Recent Activity */}
        <div>
          <h2 className="text-base font-semibold text-gray-900 mb-4">Recent Activity</h2>
          {recentScans.length > 0 ? (
            <div className="space-y-3">
              {recentScans.slice(0, 5).map((scan: any) => (
                <a key={scan.id} href={`/scans/${scan.id}`} className="flex items-center justify-between p-3 rounded-lg border border-gray-200 hover:bg-gray-50 transition-colors">
                  <div className="flex items-center gap-3">
                    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${
                      scan.status === 'completed' ? 'bg-green-100 text-green-800' :
                      scan.status === 'running' ? 'bg-blue-100 text-blue-800' :
                      scan.status === 'failed' ? 'bg-red-100 text-red-800' :
                      'bg-gray-100 text-gray-800'
                    }`}>{scan.status}</span>
                    <span className="text-sm text-gray-900">{scan.profile} scan</span>
                  </div>
                  <span className="text-xs text-gray-500">{new Date(scan.started_at || scan.created_at).toLocaleDateString()}</span>
                </a>
              ))}
            </div>
          ) : (
            <div className="rounded-xl border border-gray-200 bg-white p-8 sm:p-12 text-center shadow-sm">
              <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-gray-100 text-xl text-gray-400">
                📋
              </div>
              <p className="mt-3 text-sm text-gray-500">
                No recent activity yet. Add a company to get started.
              </p>
            </div>
          )}
        </div>

        {/* LearnMore Component */}
        <div className="pt-2">
          <LearnMore contentId="methodology:recon_pipeline" />
        </div>
      </div>
    </div>
  );
}
