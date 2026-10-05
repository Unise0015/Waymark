"use client";

import { useState, useEffect } from "react";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api/v1";

interface WordlistInfo {
  id: string;
  name: string;
  category: string;
  description: string | null;
  line_count: number;
  size_bytes: number;
  is_builtin: boolean;
}

const CATEGORY_ICONS: Record<string, string> = {
  subdomains: "🌐",
  directories: "📁",
  apis: "🔌",
  parameters: "🔑",
  tech_specific: "🎯",
};

export default function WordlistsPage() {
  const [wordlists, setWordlists] = useState<WordlistInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [category, setCategory] = useState("");
  const [uploading, setUploading] = useState(false);
  const [showUpload, setShowUpload] = useState(false);

  const fetchWordlists = () => {
    setLoading(true);
    const q = category ? `?category=${category}` : "";
    fetch(`${API_BASE}/wordlists/${q}`)
      .then((r) => r.json())
      .then((data) => setWordlists(Array.isArray(data) ? data : []))
      .catch(() => setWordlists([]))
      .finally(() => setLoading(false));
  };

  useEffect(() => { fetchWordlists(); }, [category]);

  const handleUpload = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const form = e.currentTarget;
    const formData = new FormData(form);
    setUploading(true);
    try {
      const res = await fetch(`${API_BASE}/wordlists/upload`, {
        method: "POST",
        body: formData,
      });
      if (res.ok) {
        setShowUpload(false);
        form.reset();
        fetchWordlists();
      }
    } finally {
      setUploading(false);
    }
  };

  const formatSize = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  return (
    <div className="min-h-screen bg-gray-50 pl-56">
      <div className="mx-auto max-w-7xl px-6 py-8">
        {/* Header */}
        <div className="mb-8 flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-gray-900">📝 Wordlists</h1>
            <p className="mt-1 text-gray-500">
              Manage discovery dictionaries for subdomain, directory, and API fuzzing
            </p>
          </div>
          <button
            onClick={() => setShowUpload(!showUpload)}
            className="rounded-lg bg-indigo-600 px-4 py-2.5 text-sm font-medium text-white hover:bg-indigo-700 transition-colors"
          >
            + Upload Wordlist
          </button>
        </div>

        {/* Upload form */}
        {showUpload && (
          <div className="mb-6 rounded-xl border border-indigo-200 bg-white p-6 shadow-sm">
            <h3 className="font-semibold text-gray-900">Upload Custom Wordlist</h3>
            <form onSubmit={handleUpload} className="mt-4 grid gap-4 md:grid-cols-2">
              <div>
                <label className="block text-sm font-medium text-gray-700">Name</label>
                <input
                  name="name"
                  required
                  className="mt-1 w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-indigo-500 focus:outline-none"
                  placeholder="e.g. Target-specific API paths"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700">Category</label>
                <select
                  name="category"
                  required
                  className="mt-1 w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-indigo-500 focus:outline-none"
                >
                  <option value="subdomains">Subdomains</option>
                  <option value="directories">Directories</option>
                  <option value="apis">APIs</option>
                  <option value="parameters">Parameters</option>
                  <option value="tech_specific">Tech-Specific</option>
                </select>
              </div>
              <div className="md:col-span-2">
                <label className="block text-sm font-medium text-gray-700">Description (optional)</label>
                <input
                  name="description"
                  className="mt-1 w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-indigo-500 focus:outline-none"
                  placeholder="e.g. Extracted from JavaScript bundles of target.com"
                />
              </div>
              <div className="md:col-span-2">
                <label className="block text-sm font-medium text-gray-700">File (.txt)</label>
                <input
                  type="file"
                  name="file"
                  accept=".txt,.lst"
                  required
                  className="mt-1 w-full text-sm text-gray-500 file:mr-4 file:rounded-lg file:border-0 file:bg-indigo-50 file:px-4 file:py-2 file:text-sm file:font-medium file:text-indigo-700 hover:file:bg-indigo-100"
                />
              </div>
              <div className="flex gap-3 md:col-span-2">
                <button
                  type="submit"
                  disabled={uploading}
                  className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-700 disabled:opacity-50"
                >
                  {uploading ? "Uploading..." : "Upload"}
                </button>
                <button
                  type="button"
                  onClick={() => setShowUpload(false)}
                  className="rounded-lg border border-gray-300 px-4 py-2 text-sm font-medium text-gray-600 hover:bg-gray-50"
                >
                  Cancel
                </button>
              </div>
            </form>
          </div>
        )}

        {/* Category filter */}
        <div className="mb-6 flex gap-2">
          {[
            { key: "", label: "All" },
            { key: "subdomains", label: "🌐 Subdomains" },
            { key: "directories", label: "📁 Directories" },
            { key: "apis", label: "🔌 APIs" },
            { key: "parameters", label: "🔑 Parameters" },
          ].map((cat) => (
            <button
              key={cat.key}
              onClick={() => setCategory(cat.key)}
              className={`rounded-lg px-3 py-1.5 text-sm font-medium transition-colors ${
                category === cat.key
                  ? "bg-indigo-100 text-indigo-700"
                  : "bg-white border border-gray-200 text-gray-600 hover:bg-gray-50"
              }`}
            >
              {cat.label}
            </button>
          ))}
        </div>

        {/* Loading */}
        {loading && (
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            {[1, 2, 3].map((i) => (
              <div key={i} className="h-36 animate-pulse rounded-xl bg-gray-200" />
            ))}
          </div>
        )}

        {/* Wordlist cards */}
        {!loading && (
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            {wordlists.map((wl) => (
              <div
                key={wl.id}
                className="rounded-xl border border-gray-200 bg-white p-5 shadow-sm"
              >
                <div className="flex items-start justify-between">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-lg">{CATEGORY_ICONS[wl.category] || "📄"}</span>
                      <h3 className="font-semibold text-gray-900">{wl.name}</h3>
                    </div>
                    {wl.description && (
                      <p className="mt-1 text-sm text-gray-500 line-clamp-2">{wl.description}</p>
                    )}
                  </div>
                  {wl.is_builtin && (
                    <span className="shrink-0 rounded bg-green-100 px-2 py-0.5 text-xs font-medium text-green-700">
                      Builtin
                    </span>
                  )}
                </div>
                <div className="mt-4 flex items-center gap-4 text-xs text-gray-400">
                  <span>{wl.line_count.toLocaleString()} lines</span>
                  <span>{formatSize(wl.size_bytes)}</span>
                  <span className="rounded bg-gray-100 px-1.5 py-0.5 text-gray-500">
                    {wl.category}
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Empty state */}
        {!loading && wordlists.length === 0 && (
          <div className="rounded-xl border border-gray-200 bg-white p-12 text-center">
            <p className="text-4xl">📝</p>
            <p className="mt-4 text-lg font-medium text-gray-600">No wordlists found</p>
            <p className="mt-1 text-sm text-gray-400">
              Upload a custom wordlist to get started
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
