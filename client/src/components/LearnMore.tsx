"use client";

import { useState, useEffect } from "react";

/**
 * 🎓 LearnMore Component — Waymark's Educational System
 *
 * Displays expandable educational panels throughout the UI.
 * Fetches content from the Education API and renders inline
 * summaries, explanations, and tips.
 *
 * Usage:
 *   <LearnMore contentId="concept:scope" />
 *   <LearnMore contentId="tool:subfinder" />
 */

interface EducationData {
  title: string;
  summary: string;
  what_it_does: string;
  why_it_matters: string;
  tips: string[];
  questions: { question: string; answers: string[] }[];
}

interface LearnMoreProps {
  contentId: string;
  className?: string;
}

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api/v1";

export function LearnMore({ contentId, className = "" }: LearnMoreProps) {
  const [data, setData] = useState<EducationData | null>(null);
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!open || data) return;
    setLoading(true);
    fetch(`${API_BASE}/education/guides/${contentId}`)
      .then(async (r) => {
        if (!r.ok) {
          setData(null);
          return null;
        }
        return r.json();
      })
      .then((d) => d && setData(d))
      .catch(() => setData(null))
      .finally(() => setLoading(false));
  }, [open, contentId, data]);

  return (
    <div className={`rounded-lg border border-indigo-200 bg-indigo-50/50 ${className}`}>
      <button
        onClick={() => setOpen(!open)}
        className="flex w-full items-center gap-2 px-4 py-2.5 text-left text-sm font-medium text-indigo-700 hover:bg-indigo-100/50 transition-colors"
      >
        <span className="text-base">🎓</span>
        <span>{open ? "Hide" : "Learn More"}</span>
        <svg
          className={`ml-auto h-4 w-4 transition-transform ${open ? "rotate-180" : ""}`}
          fill="none" viewBox="0 0 24 24" stroke="currentColor"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      {open && (
        <div className="border-t border-indigo-200 px-4 py-3 text-sm text-gray-700">
          {loading && <p className="text-gray-400 animate-pulse">Loading...</p>}
          {data && (
            <>
              <h4 className="font-semibold text-indigo-900">{data.title}</h4>
              <p className="mt-1 text-gray-600">{data.summary}</p>

              <div className="mt-3">
                <h5 className="font-medium text-gray-800">What it does:</h5>
                <p className="mt-0.5 text-gray-600">{data.what_it_does}</p>
              </div>

              <div className="mt-3">
                <h5 className="font-medium text-gray-800">Why it matters:</h5>
                <p className="mt-0.5 text-gray-600">{data.why_it_matters}</p>
              </div>

              {data?.tips?.length > 0 && (
                <div className="mt-3">
                  <h5 className="font-medium text-gray-800">💡 Tips:</h5>
                  <ul className="mt-1 list-disc pl-5 space-y-1">
                    {data.tips.map((tip, i) => (
                      <li key={i} className="text-gray-600">{tip}</li>
                    ))}
                  </ul>
                </div>
              )}

              {data?.questions?.length > 0 && (
                <div className="mt-3 space-y-2">
                  {data.questions.map((q, i) => (
                    <details key={i} className="rounded bg-white/60 p-2">
                      <summary className="cursor-pointer font-medium text-indigo-700">
                        ❓ {q.question}
                      </summary>
                      <div className="mt-1 space-y-1 pl-4">
                        {q.answers.map((a, j) => (
                          <p key={j} className="text-gray-600">• {a}</p>
                        ))}
                      </div>
                    </details>
                  ))}
                </div>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}

export default LearnMore;
