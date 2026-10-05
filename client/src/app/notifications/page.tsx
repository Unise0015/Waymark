"use client";

import { useState, useEffect } from "react";
import Link from "next/link";
import { notifications, Notification } from "@/lib/api";
import { LearnMore } from "@/components/LearnMore";

export default function NotificationsPage() {
  const [items, setItems] = useState<Notification[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<"all" | "unread" | "read">("all");
  const [typeFilter, setTypeFilter] = useState<string>("all");
  const [isProcessing, setIsProcessing] = useState(false);

  const fetchNotifications = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await notifications.list();
      setItems(data || []);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load notifications");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchNotifications();
  }, []);

  const handleMarkAsRead = async (id: string) => {
    try {
      const updated = await notifications.markRead(id);
      setItems((prev) =>
        prev.map((item) => (item.id === id ? { ...item, is_read: true } : item))
      );
    } catch (err) {
      console.error("Failed to mark as read:", err);
    }
  };

  const handleMarkAllRead = async () => {
    setIsProcessing(true);
    try {
      await notifications.markAllRead();
      setItems((prev) => prev.map((item) => ({ ...item, is_read: true })));
    } catch (err) {
      alert(err instanceof Error ? err.message : "Failed to mark all as read");
    } finally {
      setIsProcessing(false);
    }
  };

  const handleDelete = async (id: string) => {
    try {
      await notifications.delete(id);
      setItems((prev) => prev.filter((item) => item.id !== id));
    } catch (err) {
      alert(err instanceof Error ? err.message : "Failed to delete notification");
    }
  };

  const getSeverityInfo = (type: string) => {
    switch (type) {
      case "new_finding":
        return {
          severity: "High",
          badgeClass: "bg-red-50 text-red-700 ring-red-600/20",
          icon: "🚨",
          label: "Vulnerability Found",
        };
      case "certificate_expiry":
        return {
          severity: "Medium",
          badgeClass: "bg-amber-50 text-amber-700 ring-amber-600/20",
          icon: "⚠️",
          label: "SSL Expiring",
        };
      case "content_change":
        return {
          severity: "Medium",
          badgeClass: "bg-blue-50 text-blue-700 ring-blue-600/20",
          icon: "🔄",
          label: "Content Change",
        };
      case "new_subdomain":
        return {
          severity: "Low",
          badgeClass: "bg-emerald-50 text-emerald-700 ring-emerald-600/20",
          icon: "🌐",
          label: "New Asset",
        };
      case "scan_complete":
      default:
        return {
          severity: "Info",
          badgeClass: "bg-gray-100 text-gray-700 ring-gray-600/20",
          icon: "🏁",
          label: "Scan Complete",
        };
    }
  };

  const filteredItems = items.filter((item) => {
    if (filter === "unread" && item.is_read) return false;
    if (filter === "read" && !item.is_read) return false;
    if (typeFilter !== "all" && item.type !== typeFilter) return false;
    return true;
  });

  const unreadCount = items.filter((i) => !i.is_read).length;

  return (
    <div className="min-h-screen bg-gray-50 pl-56">
      <div className="mx-auto max-w-5xl px-6 py-8">
        {/* Header */}
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <div className="flex items-center gap-3">
              <h1 className="text-2xl font-bold text-gray-900">🔔 Notifications</h1>
              {unreadCount > 0 && (
                <span className="rounded-full bg-indigo-600 px-2.5 py-0.5 text-xs font-semibold text-white">
                  {unreadCount} new
                </span>
              )}
            </div>
            <p className="mt-1 text-sm text-gray-500">
              Activity stream, security alerts, and change detection updates.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={fetchNotifications}
              disabled={loading}
              className="rounded-lg border border-gray-200 bg-white px-3 py-1.5 text-xs font-medium text-gray-600 hover:bg-gray-50 transition-colors"
            >
              🔄 Refresh
            </button>
            {unreadCount > 0 && (
              <button
                onClick={handleMarkAllRead}
                disabled={isProcessing}
                className="rounded-lg bg-indigo-50 border border-indigo-200 px-3 py-1.5 text-xs font-semibold text-indigo-700 hover:bg-indigo-100 transition-colors disabled:opacity-50"
              >
                ✓ Mark all as read
              </button>
            )}
          </div>
        </div>

        {/* Continuous Monitoring Educational Guide */}
        <div className="mt-6">
          <LearnMore contentId="concept:continuous_monitoring" />
        </div>

        {/* Filter Bar */}
        <div className="mt-6 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between border-b border-gray-200 pb-3">
          <div className="flex items-center gap-2">
            {(["all", "unread", "read"] as const).map((tab) => (
              <button
                key={tab}
                onClick={() => setFilter(tab)}
                className={`rounded-lg px-3 py-1.5 text-xs font-medium capitalize transition-colors ${
                  filter === tab
                    ? "bg-indigo-600 text-white shadow-sm"
                    : "bg-white text-gray-600 border border-gray-200 hover:bg-gray-50"
                }`}
              >
                {tab === "all" ? `All (${items.length})` : tab === "unread" ? `Unread (${unreadCount})` : `Read (${items.length - unreadCount})`}
              </button>
            ))}
          </div>

          <div className="flex items-center gap-2">
            <span className="text-xs text-gray-500">Type:</span>
            <select
              value={typeFilter}
              onChange={(e) => setTypeFilter(e.target.value)}
              className="rounded-lg border border-gray-300 bg-white px-2.5 py-1 text-xs text-gray-700 focus:border-indigo-500 focus:outline-none"
            >
              <option value="all">All Types</option>
              <option value="new_finding">Findings / Vulnerabilities</option>
              <option value="new_subdomain">New Subdomains</option>
              <option value="content_change">Content Changes</option>
              <option value="certificate_expiry">SSL Expiry</option>
              <option value="scan_complete">Scan Completed</option>
            </select>
          </div>
        </div>

        {/* Notification List */}
        <div className="mt-6">
          {loading && (
            <div className="rounded-xl border border-gray-200 bg-white p-12 text-center shadow-sm">
              <div className="inline-block h-8 w-8 animate-spin rounded-full border-4 border-indigo-600 border-r-transparent"></div>
              <p className="mt-3 text-sm text-gray-500">Loading notifications...</p>
            </div>
          )}

          {!loading && error && (
            <div className="rounded-xl border border-red-200 bg-red-50 p-6 text-center">
              <p className="text-sm font-semibold text-red-800">Failed to fetch notifications</p>
              <p className="mt-1 text-xs text-red-600">{error}</p>
              <button
                onClick={fetchNotifications}
                className="mt-3 rounded-lg bg-red-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-red-500 transition-colors"
              >
                Retry
              </button>
            </div>
          )}

          {!loading && !error && filteredItems.length === 0 && (
            <div className="rounded-xl border border-dashed border-gray-300 bg-white p-12 text-center">
              <span className="text-4xl">🎉</span>
              <h3 className="mt-3 text-base font-semibold text-gray-900">
                {filter === "unread" ? "All caught up!" : "No notifications found"}
              </h3>
              <p className="mx-auto mt-1 max-w-sm text-sm text-gray-500">
                {filter === "unread"
                  ? "There are no unread notifications right now."
                  : "When scans detect changes, new subdomains, or findings, they will appear here."}
              </p>
            </div>
          )}

          {!loading && !error && filteredItems.length > 0 && (
            <div className="space-y-3">
              {filteredItems.map((item) => {
                const info = getSeverityInfo(item.type);
                return (
                  <div
                    key={item.id}
                    className={`rounded-xl border p-4 transition-all ${
                      item.is_read
                        ? "border-gray-200 bg-white"
                        : "border-indigo-200 bg-indigo-50/20 shadow-sm"
                    }`}
                  >
                    <div className="flex items-start justify-between gap-4">
                      <div className="flex items-start gap-3">
                        <span className="text-2xl mt-0.5">{info.icon}</span>
                        <div className="space-y-1">
                          <div className="flex flex-wrap items-center gap-2">
                            <span
                              className={`font-semibold text-sm ${
                                item.is_read ? "text-gray-800" : "text-gray-900 font-bold"
                              }`}
                            >
                              {item.title}
                            </span>
                            <span
                              className={`inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-semibold ring-1 ring-inset ${info.badgeClass}`}
                            >
                              {info.severity}
                            </span>
                            <span className="rounded bg-gray-100 px-1.5 py-0.5 text-[10px] font-medium text-gray-600">
                              {info.label}
                            </span>
                            {!item.is_read && (
                              <span className="inline-block h-2 w-2 rounded-full bg-indigo-600" title="Unread"></span>
                            )}
                          </div>

                          {item.message && (
                            <p className="text-sm text-gray-600 leading-relaxed max-w-3xl whitespace-pre-wrap">
                              {item.message}
                            </p>
                          )}

                          <div className="flex flex-wrap items-center gap-3 pt-1 text-xs text-gray-400">
                            <span>
                              🕒{" "}
                              {new Date(item.created_at).toLocaleString("en-US", {
                                month: "short",
                                day: "numeric",
                                hour: "2-digit",
                                minute: "2-digit",
                              })}
                            </span>

                            {item.related_entity_type && item.related_entity_id && (
                              <span className="text-indigo-600 font-mono text-[11px]">
                                Ref: {item.related_entity_type} #{item.related_entity_id.slice(0, 8)}
                              </span>
                            )}
                          </div>
                        </div>
                      </div>

                      {/* Actions */}
                      <div className="flex items-center gap-2 shrink-0">
                        {!item.is_read && (
                          <button
                            onClick={() => handleMarkAsRead(item.id)}
                            className="rounded-lg border border-indigo-200 bg-indigo-50 px-2.5 py-1 text-xs font-semibold text-indigo-700 hover:bg-indigo-100 transition-colors"
                            title="Mark as read"
                          >
                            Mark Read
                          </button>
                        )}
                        <button
                          onClick={() => handleDelete(item.id)}
                          className="rounded-lg p-1.5 text-gray-400 hover:text-red-600 hover:bg-red-50 transition-colors text-xs"
                          title="Delete notification"
                        >
                          ✕
                        </button>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
