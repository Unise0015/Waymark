"use client";

import { useState, useEffect } from "react";
import { webhooks, Webhook } from "@/lib/api";
import { LearnMore } from "@/components/LearnMore";

const AVAILABLE_EVENTS = [
  { id: "new_subdomain", label: "New Subdomain", desc: "Triggered when a new subdomain is found" },
  { id: "new_finding", label: "New Finding", desc: "Triggered on discovered vulnerabilities" },
  { id: "scan_complete", label: "Scan Complete", desc: "Triggered when a scan run finishes" },
  { id: "content_change", label: "Content Change", desc: "Triggered when website response changes" },
  { id: "certificate_expiry", label: "Certificate Expiry", desc: "Triggered on SSL cert expiry alerts" },
];

export default function SettingsPage() {
  const [activeTab, setActiveTab] = useState("wordlists");

  // Webhooks state
  const [webhookList, setWebhookList] = useState<Webhook[]>([]);
  const [loadingWebhooks, setLoadingWebhooks] = useState(false);
  const [webhookError, setWebhookError] = useState<string | null>(null);
  const [showAddWebhook, setShowAddWebhook] = useState(false);

  // New webhook form
  const [webhookName, setWebhookName] = useState("");
  const [webhookUrl, setWebhookUrl] = useState("");
  const [webhookSecret, setWebhookSecret] = useState("");
  const [webhookEvents, setWebhookEvents] = useState<string[]>([
    "new_subdomain",
    "new_finding",
    "scan_complete",
  ]);
  const [minSeverity, setMinSeverity] = useState("low");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  useEffect(() => {
    if (activeTab === "webhooks") {
      fetchWebhooks();
    }
  }, [activeTab]);

  async function fetchWebhooks() {
    setLoadingWebhooks(true);
    setWebhookError(null);
    try {
      const data = await webhooks.list();
      setWebhookList(data || []);
    } catch (err) {
      setWebhookError(err instanceof Error ? err.message : "Failed to load webhooks");
    } finally {
      setLoadingWebhooks(false);
    }
  }

  const handleToggleEvent = (eventId: string) => {
    setWebhookEvents((prev) =>
      prev.includes(eventId) ? prev.filter((e) => e !== eventId) : [...prev, eventId]
    );
  };

  const handleCreateWebhook = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!webhookName.trim() || !webhookUrl.trim()) {
      setFormError("Name and URL are required");
      return;
    }

    try {
      new URL(webhookUrl);
    } catch {
      setFormError("Please enter a valid URL (e.g. https://discord.com/api/webhooks/...)");
      return;
    }

    setIsSubmitting(true);
    setFormError(null);

    try {
      const created = await webhooks.create({
        name: webhookName.trim(),
        url: webhookUrl.trim(),
        secret_key: webhookSecret.trim() || undefined,
        event_types: webhookEvents,
        min_severity: minSeverity,
        is_active: true,
      });

      setWebhookList((prev) => [...prev, created]);
      setWebhookName("");
      setWebhookUrl("");
      setWebhookSecret("");
      setWebhookEvents(["new_subdomain", "new_finding", "scan_complete"]);
      setMinSeverity("low");
      setShowAddWebhook(false);
    } catch (err) {
      setFormError(err instanceof Error ? err.message : "Failed to create webhook");
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleToggleActive = async (id: string) => {
    try {
      const updated = await webhooks.toggle(id);
      setWebhookList((prev) =>
        prev.map((item) => (item.id === id ? updated : item))
      );
    } catch (err) {
      alert(err instanceof Error ? err.message : "Failed to toggle webhook");
    }
  };

  const handleDeleteWebhook = async (id: string, name: string) => {
    if (!confirm(`Are you sure you want to delete the webhook "${name}"?`)) {
      return;
    }

    try {
      await webhooks.delete(id);
      setWebhookList((prev) => prev.filter((item) => item.id !== id));
    } catch (err) {
      alert(err instanceof Error ? err.message : "Failed to delete webhook");
    }
  };

  const TABS = [
    { key: "wordlists", label: "📝 Wordlist Paths" },
    { key: "webhooks", label: "🔔 Webhooks" },
    { key: "about", label: "ℹ️ About" },
  ];

  return (
    <div className="min-h-screen bg-gray-50 pl-56">
      <div className="mx-auto max-w-4xl px-6 py-8">
        <h1 className="text-2xl font-bold text-gray-900">⚙️ Settings</h1>
        <p className="mt-1 text-gray-700">Configure Waymark defaults and integrations</p>

        {/* Tabs */}
        <div className="mt-6 flex gap-1 border-b border-gray-200">
          {TABS.map((tab) => (
            <button
              key={tab.key}
              onClick={() => setActiveTab(tab.key)}
              className={`px-4 py-2.5 text-sm font-medium transition-colors ${
                activeTab === tab.key
                  ? "border-b-2 border-indigo-600 text-indigo-700"
                  : "text-gray-700 hover:text-gray-700"
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* Tab content */}
        <div className="mt-6">


          {activeTab === "wordlists" && (
            <div className="rounded-xl border border-gray-200 bg-white p-6">
              <h3 className="font-semibold text-gray-900">Wordlist Storage Path</h3>
              <p className="mt-1 text-sm text-gray-700">
                Location where bundled and uploaded wordlists are stored
              </p>
              <div className="mt-3 rounded-lg bg-gray-50 p-3 font-mono text-sm text-gray-700">
                data/wordlists/
              </div>
              <div className="mt-4 space-y-2 text-sm text-gray-700">
                <p>📁 <code className="bg-gray-100 px-1 rounded">builtin/</code> — Bundled wordlists (read-only)</p>
                <p>📁 <code className="bg-gray-100 px-1 rounded">custom/</code> — Your uploaded wordlists</p>
              </div>
            </div>
          )}

          {activeTab === "webhooks" && (
            <div className="space-y-6">
              {/* Webhooks Card */}
              <div className="rounded-xl border border-gray-200 bg-white p-6 shadow-sm">
                <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
                  <div>
                    <div className="flex items-center gap-2">
                      <h3 className="font-semibold text-gray-900">Webhook Integrations</h3>
                      <span className="rounded-full bg-gray-100 px-2 py-0.5 text-xs font-medium text-gray-700">
                        {webhookList.length}
                      </span>
                    </div>
                    <p className="mt-1 text-sm text-gray-700">
                      Send continuous reconnaissance alerts and newly discovered findings to Slack, Discord, or SIEMs.
                    </p>
                  </div>
                  {!showAddWebhook && (
                    <button
                      onClick={() => setShowAddWebhook(true)}
                      className="inline-flex items-center gap-1.5 rounded-lg bg-indigo-600 px-3.5 py-2 text-sm font-semibold text-white shadow-sm hover:bg-indigo-500 transition-colors"
                    >
                      <span>+</span> Add Webhook
                    </button>
                  )}
                </div>

                {/* Educational LearnMore Component */}
                <div className="mt-5">
                  <LearnMore contentId="concept:continuous_monitoring" />
                </div>

                {/* Add Webhook Form */}
                {showAddWebhook && (
                  <form
                    onSubmit={handleCreateWebhook}
                    className="mt-6 rounded-xl border border-indigo-100 bg-indigo-50/40 p-5 shadow-inner"
                  >
                    <div className="flex items-center justify-between pb-3 border-b border-indigo-100">
                      <h4 className="font-semibold text-gray-900">New Webhook Endpoint</h4>
                      <button
                        type="button"
                        onClick={() => setShowAddWebhook(false)}
                        className="text-xs text-gray-700 hover:text-gray-700"
                      >
                        ✕ Close
                      </button>
                    </div>

                    {formError && (
                      <div className="mt-4 rounded-lg border border-red-200 bg-red-50 p-3 text-xs text-red-700">
                        {formError}
                      </div>
                    )}

                    <div className="mt-4 grid grid-cols-1 gap-4 sm:grid-cols-2">
                      <div>
                        <label className="block text-xs font-medium text-gray-700">
                          Webhook Name <span className="text-red-500">*</span>
                        </label>
                        <input
                          type="text"
                          value={webhookName}
                          onChange={(e) => setWebhookName(e.target.value)}
                          placeholder="e.g. Discord #recon-alerts"
                          required
                          className="mt-1 w-full rounded-lg border border-gray-300 bg-white px-3 py-2 text-sm text-gray-900 placeholder-gray-400 focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
                        />
                      </div>

                      <div>
                        <label className="block text-xs font-medium text-gray-700">
                          Payload URL <span className="text-red-500">*</span>
                        </label>
                        <input
                          type="url"
                          value={webhookUrl}
                          onChange={(e) => setWebhookUrl(e.target.value)}
                          placeholder="https://discord.com/api/webhooks/..."
                          required
                          className="mt-1 w-full rounded-lg border border-gray-300 bg-white px-3 py-2 text-sm text-gray-900 placeholder-gray-400 focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
                        />
                      </div>

                      <div>
                        <label className="block text-xs font-medium text-gray-700">
                          Secret Key (Optional HMAC SHA-256)
                        </label>
                        <input
                          type="password"
                          value={webhookSecret}
                          onChange={(e) => setWebhookSecret(e.target.value)}
                          placeholder="Secret used to sign payloads in X-Hub-Signature-256"
                          className="mt-1 w-full rounded-lg border border-gray-300 bg-white px-3 py-2 text-sm text-gray-900 placeholder-gray-400 focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
                        />
                        <p className="mt-1 text-[11px] text-gray-700">
                          If set, requests will include an HMAC SHA-256 signature header.
                        </p>
                      </div>

                      <div>
                        <label className="block text-xs font-medium text-gray-700">
                          Minimum Finding Severity
                        </label>
                        <select
                          value={minSeverity}
                          onChange={(e) => setMinSeverity(e.target.value)}
                          className="mt-1 w-full rounded-lg border border-gray-300 bg-white px-3 py-2 text-sm text-gray-900 focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
                        >
                          <option value="info">Info & Higher (All findings)</option>
                          <option value="low">Low & Higher</option>
                          <option value="medium">Medium & Higher</option>
                          <option value="high">High & Higher</option>
                          <option value="critical">Critical Only</option>
                        </select>
                      </div>
                    </div>

                    {/* Event Types */}
                    <div className="mt-4">
                      <label className="block text-xs font-medium text-gray-700 mb-2">
                        Subscribed Event Types
                      </label>
                      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
                        {AVAILABLE_EVENTS.map((event) => {
                          const isSelected = webhookEvents.includes(event.id);
                          return (
                            <label
                              key={event.id}
                              onClick={() => handleToggleEvent(event.id)}
                              className={`flex items-start gap-2.5 rounded-lg border p-3 cursor-pointer transition-all ${
                                isSelected
                                  ? "border-indigo-500 bg-white shadow-sm ring-1 ring-indigo-500"
                                  : "border-gray-200 bg-white/70 hover:bg-white"
                              }`}
                            >
                              <input
                                type="checkbox"
                                checked={isSelected}
                                onChange={() => {}}
                                className="mt-0.5 h-4 w-4 rounded border-gray-300 text-indigo-600 focus:ring-indigo-500"
                              />
                              <div>
                                <span className="text-xs font-semibold text-gray-900 block">
                                  {event.label}
                                </span>
                                <span className="text-[11px] text-gray-700 leading-tight block">
                                  {event.desc}
                                </span>
                              </div>
                            </label>
                          );
                        })}
                      </div>
                    </div>

                    <div className="mt-5 flex items-center justify-end gap-3 pt-3 border-t border-indigo-100">
                      <button
                        type="button"
                        onClick={() => setShowAddWebhook(false)}
                        className="rounded-lg border border-gray-300 bg-white px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50 transition-colors"
                      >
                        Cancel
                      </button>
                      <button
                        type="submit"
                        disabled={isSubmitting}
                        className="inline-flex items-center gap-1.5 rounded-lg bg-indigo-600 px-4 py-2 text-sm font-semibold text-white shadow-sm hover:bg-indigo-500 disabled:opacity-50 transition-colors"
                      >
                        {isSubmitting ? "Creating..." : "Create Webhook"}
                      </button>
                    </div>
                  </form>
                )}

                {/* Webhooks List */}
                <div className="mt-6">
                  {loadingWebhooks && (
                    <div className="py-8 text-center">
                      <div className="inline-block h-6 w-6 animate-spin rounded-full border-2 border-indigo-600 border-r-transparent"></div>
                      <p className="mt-2 text-xs text-gray-700">Loading configured webhooks...</p>
                    </div>
                  )}

                  {!loadingWebhooks && webhookError && (
                    <div className="rounded-lg border border-red-200 bg-red-50 p-4 text-sm text-red-700">
                      <div className="flex items-center justify-between">
                        <span>{webhookError}</span>
                        <button
                          onClick={fetchWebhooks}
                          className="font-medium underline hover:text-red-900"
                        >
                          Retry
                        </button>
                      </div>
                    </div>
                  )}

                  {!loadingWebhooks && !webhookError && webhookList.length === 0 && !showAddWebhook && (
                    <div className="rounded-xl border border-dashed border-gray-300 bg-gray-50/50 p-8 text-center">
                      <span className="text-3xl">🔔</span>
                      <h4 className="mt-2 text-sm font-semibold text-gray-900">No webhooks configured</h4>
                      <p className="mx-auto mt-1 max-w-sm text-xs text-gray-700">
                        Add a webhook to receive real-time push alerts to your Discord, Slack, or monitoring server.
                      </p>
                      <button
                        onClick={() => setShowAddWebhook(true)}
                        className="mt-4 inline-flex items-center gap-1.5 rounded-lg bg-indigo-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-indigo-500 transition-colors"
                      >
                        <span>+</span> Add Webhook
                      </button>
                    </div>
                  )}

                  {!loadingWebhooks && !webhookError && webhookList.length > 0 && (
                    <div className="divide-y divide-gray-100 rounded-lg border border-gray-200">
                      {webhookList.map((hook) => (
                        <div key={hook.id} className="p-4 sm:flex sm:items-center sm:justify-between hover:bg-gray-50/60 transition-colors">
                          <div className="space-y-1.5">
                            <div className="flex flex-wrap items-center gap-2">
                              <span className="font-semibold text-sm text-gray-900">{hook.name}</span>
                              {hook.is_active ? (
                                <span className="inline-flex items-center gap-1 rounded-full bg-emerald-50 px-2 py-0.5 text-[11px] font-medium text-emerald-700 ring-1 ring-inset ring-emerald-600/20">
                                  ● Active
                                </span>
                              ) : (
                                <span className="inline-flex items-center gap-1 rounded-full bg-gray-100 px-2 py-0.5 text-[11px] font-medium text-gray-700">
                                  ○ Paused
                                </span>
                              )}
                              {hook.secret_key && (
                                <span className="inline-flex items-center gap-1 rounded bg-purple-50 px-1.5 py-0.5 text-[10px] font-medium text-purple-700 ring-1 ring-inset ring-purple-600/20">
                                  🔒 HMAC SHA-256
                                </span>
                              )}
                              {hook.min_severity && (
                                <span className="inline-flex items-center rounded bg-amber-50 px-1.5 py-0.5 text-[10px] font-medium text-amber-700">
                                  Min: {hook.min_severity}
                                </span>
                              )}
                            </div>
                            <div className="font-mono text-xs text-gray-700 truncate max-w-md">
                              {hook.url}
                            </div>
                            <div className="flex flex-wrap gap-1.5 pt-1">
                              {hook.event_types && hook.event_types.length > 0 ? (
                                hook.event_types.map((evt) => (
                                  <span
                                    key={evt}
                                    className="rounded bg-gray-100 px-2 py-0.5 text-[10px] font-mono text-gray-700"
                                  >
                                    {evt}
                                  </span>
                                ))
                              ) : (
                                <span className="text-[11px] text-gray-700 italic">All events</span>
                              )}
                            </div>
                          </div>

                          <div className="mt-3 flex items-center gap-2 sm:mt-0">
                            <button
                              onClick={() => handleToggleActive(hook.id)}
                              className={`rounded-lg px-2.5 py-1 text-xs font-medium border transition-colors ${
                                hook.is_active
                                  ? "border-gray-200 text-gray-700 hover:bg-gray-100"
                                  : "border-indigo-200 bg-indigo-50 text-indigo-700 hover:bg-indigo-100"
                              }`}
                            >
                              {hook.is_active ? "Pause" : "Enable"}
                            </button>
                            <button
                              onClick={() => handleDeleteWebhook(hook.id, hook.name)}
                              className="rounded-lg border border-red-200 bg-white px-2.5 py-1 text-xs font-medium text-red-600 hover:bg-red-50 transition-colors"
                            >
                              Delete
                            </button>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

          {activeTab === "about" && (
            <div className="rounded-xl border border-gray-200 bg-white p-6">
              <div className="flex items-center gap-3">
                <span className="text-4xl">🧭</span>
                <div>
                  <h3 className="text-xl font-bold text-gray-900">Waymark v0.1.0</h3>
                  <p className="text-sm text-gray-700">Bug Bounty Reconnaissance Platform</p>
                </div>
              </div>
              <div className="mt-6 space-y-3 text-sm">
                <div className="flex justify-between border-b border-gray-100 py-2">
                  <span className="text-gray-900">Deployment</span>
                  <span className="font-medium text-gray-700">Self-hosted on Kali Linux</span>
                </div>
                <div className="flex justify-between py-2">
                  <span className="text-gray-900">Tech Stack</span>
                  <span className="font-medium text-gray-700">Built with FastAPI + Next.js</span>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
