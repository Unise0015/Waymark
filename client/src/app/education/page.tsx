"use client";

import Link from "next/link";
import { useState, useEffect } from "react";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api/v1";

interface EducationGuide {
  id: string;
  title: string;
  category: string;
  difficulty: string;
  summary: string;
  what_it_does: string;
  why_it_matters: string;
  tips: string[];
}

const CATEGORIES = [
  { key: "", label: "All", icon: "📚" },
  { key: "concept", label: "Concepts", icon: "💡" },
  { key: "tool", label: "Tools", icon: "🔧" },
  { key: "methodology", label: "Methodology", icon: "📋" },
  { key: "finding", label: "Findings", icon: "🐛" },
];

const DIFFICULTY_COLORS: Record<string, string> = {
  beginner: "bg-green-100 text-green-700",
  intermediate: "bg-yellow-100 text-yellow-700",
  advanced: "bg-red-100 text-red-700",
};

export default function EducationPage() {
  const [guides, setGuides] = useState<EducationGuide[]>([]);
  const [loading, setLoading] = useState(true);
  const [category, setCategory] = useState("");
  const [search, setSearch] = useState("");
  const [expanded, setExpanded] = useState<string | null>(null);

  useEffect(() => {
    setLoading(true);
    const query = category ? `?category=${category}` : "";
    fetch(`${API_BASE}/education/${query}`)
      .then((r) => r.json())
      .then(setGuides)
      .catch(() => setGuides([]))
      .finally(() => setLoading(false));
  }, [category]);

  const filtered = guides.filter(
    (g) =>
      !search ||
      g.title.toLowerCase().includes(search.toLowerCase()) ||
      g.summary.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="min-h-screen bg-gray-50 pl-56">
      <div className="mx-auto max-w-7xl px-6 py-8">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-2xl font-bold text-gray-900">🎓 Knowledge Base</h1>
          <p className="mt-1 text-gray-500">
            Learn security concepts, tool usage, and vulnerability hunting methodologies
          </p>
        </div>

        {/* Category tabs */}
        <div className="mb-6 flex flex-wrap gap-2">
          {CATEGORIES.map((cat) => (
            <button
              key={cat.key}
              onClick={() => setCategory(cat.key)}
              className={`rounded-lg px-4 py-2 text-sm font-medium transition-colors ${
                category === cat.key
                  ? "bg-indigo-100 text-indigo-700"
                  : "bg-white text-gray-600 hover:bg-gray-50 border border-gray-200"
              }`}
            >
              {cat.icon} {cat.label}
            </button>
          ))}
        </div>

        {/* Search */}
        <div className="mb-6">
          <input
            type="text"
            placeholder="Search guides..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full max-w-md rounded-lg border border-gray-300 px-4 py-2.5 text-sm focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
          />
        </div>

        {/* Loading */}
        {loading && (
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            {[1, 2, 3, 4, 5, 6].map((i) => (
              <div key={i} className="h-48 animate-pulse rounded-xl bg-gray-200" />
            ))}
          </div>
        )}

        {/* Guides grid */}
        {!loading && (
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            {filtered.map((guide) => (
              <div
                key={guide.id}
                className="rounded-xl border border-gray-200 bg-white shadow-sm transition-shadow hover:shadow-md"
              >
                <button
                  onClick={() => setExpanded(expanded === guide.id ? null : guide.id)}
                  className="w-full p-5 text-left"
                >
                  <div className="flex items-start justify-between gap-2">
                    <h3 className="font-semibold text-gray-900">{guide.title}</h3>
                    <span
                      className={`shrink-0 rounded-full px-2 py-0.5 text-xs font-medium ${
                        DIFFICULTY_COLORS[guide.difficulty] || "bg-gray-100 text-gray-600"
                      }`}
                    >
                      {guide.difficulty}
                    </span>
                  </div>
                  <p className="mt-2 text-sm text-gray-600 line-clamp-3">{guide.summary}</p>
                  <div className="mt-3 flex items-center gap-2">
                    <span className="rounded bg-gray-100 px-2 py-0.5 text-xs text-gray-500">
                      {guide.category}
                    </span>
                  </div>
                </button>

                {expanded === guide.id && (
                  <div className="border-t border-gray-100 px-5 pb-5 pt-4 text-sm">
                    <div className="mb-3">
                      <h4 className="font-medium text-gray-800">What it does:</h4>
                      <p className="mt-1 text-gray-600">{guide.what_it_does}</p>
                    </div>
                    <div className="mb-3">
                      <h4 className="font-medium text-gray-800">Why it matters:</h4>
                      <p className="mt-1 text-gray-600">{guide.why_it_matters}</p>
                    </div>
                    {guide.tips.length > 0 && (
                      <div>
                        <h4 className="font-medium text-gray-800">💡 Tips:</h4>
                        <ul className="mt-1 list-disc pl-5 space-y-1">
                          {guide.tips.map((tip, i) => (
                            <li key={i} className="text-gray-600">{tip}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}

        {/* Empty state */}
        {!loading && filtered.length === 0 && (
          <div className="rounded-xl border border-gray-200 bg-white p-12 text-center">
            <p className="text-lg text-gray-400">No guides found</p>
            <p className="mt-1 text-sm text-gray-400">Try a different category or search term</p>
          </div>
        )}
      </div>
    </div>
  );
}
