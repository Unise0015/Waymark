"use client";

import { useState, useEffect } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { chains } from "@/lib/api";

export default function ChainsPage() {
  const router = useRouter();
  const [items, setItems] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [showModal, setShowModal] = useState(false);
  const [newChainName, setNewChainName] = useState("");
  const [newChainHypothesis, setNewChainHypothesis] = useState("");
  const [creating, setCreating] = useState(false);

  useEffect(() => {
    fetchChains();
  }, []);

  const fetchChains = async () => {
    try {
      setLoading(true);
      const data = await chains.list();
      setItems(data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleCreate = async () => {
    if (!newChainName) return;
    try {
      setCreating(true);
      const newChain = await chains.create({
        name: newChainName,
        hypothesis: newChainHypothesis,
      });
      setShowModal(false);
      router.push(`/chains/${newChain.id}`);
    } catch (err) {
      console.error(err);
    } finally {
      setCreating(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 pl-56">
      <div className="mx-auto max-w-7xl px-6 py-8">
        <div className="mb-8 flex items-start justify-between">
          <div>
            <h1 className="text-2xl font-bold text-gray-900">🔗 Vulnerability Chains</h1>
            <p className="mt-1 text-gray-500">
              Build and analyze multi-step attack chains from captured proxy traffic.
            </p>
          </div>
          <button
            onClick={() => setShowModal(true)}
            className="inline-flex items-center gap-1.5 rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-700"
          >
            + New Chain
          </button>
        </div>

        {loading ? (
          <div className="text-gray-500">Loading...</div>
        ) : items.length === 0 ? (
          <div className="rounded-xl border border-gray-200 bg-white p-12 text-center">
            <p className="text-4xl">🔗</p>
            <p className="mt-4 text-lg font-medium text-gray-600">No chains yet</p>
            <p className="mt-1 text-sm text-gray-400">
              Create a chain to start analyzing multi-step vulnerabilities.
            </p>
            <button
              onClick={() => setShowModal(true)}
              className="mt-4 inline-block rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-700"
            >
              + New Chain
            </button>
          </div>
        ) : (
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {items.map((chain) => (
              <Link
                href={`/chains/${chain.id}`}
                key={chain.id}
                className="flex flex-col rounded-xl border border-gray-200 bg-white p-5 shadow-sm transition-shadow hover:shadow-md"
              >
                <div className="flex items-start justify-between mb-2">
                  <h3 className="font-bold text-gray-900 line-clamp-1" title={chain.name}>
                    {chain.name}
                  </h3>
                  <span
                    className={`shrink-0 rounded-full px-2.5 py-0.5 text-xs font-semibold ${
                      chain.status === "analyzed"
                        ? "bg-green-100 text-green-800"
                        : "bg-gray-100 text-gray-800"
                    }`}
                  >
                    {chain.status}
                  </span>
                </div>
                {chain.hypothesis && (
                  <p className="text-sm text-gray-600 line-clamp-2 mb-4 flex-1">
                    {chain.hypothesis}
                  </p>
                )}
                <div className="mt-auto pt-4 border-t border-gray-100 flex flex-wrap items-center gap-2 text-xs">
                  {chain.verdict && (
                    <span
                      className={`rounded px-1.5 py-0.5 font-medium ${
                        chain.verdict === "CONFIRMED"
                          ? "bg-red-100 text-red-700"
                          : chain.verdict === "PARTIAL"
                          ? "bg-orange-100 text-orange-700"
                          : chain.verdict === "FAILED"
                          ? "bg-gray-100 text-gray-700"
                          : "bg-yellow-100 text-yellow-700"
                      }`}
                    >
                      {chain.verdict}
                    </span>
                  )}
                  {chain.severity && (
                    <span className="rounded bg-gray-100 px-1.5 py-0.5 text-gray-700 font-medium">
                      {chain.severity}
                    </span>
                  )}
                  <span className="text-gray-500 ml-auto">
                    {chain.steps?.length || 0} steps
                  </span>
                </div>
              </Link>
            ))}
          </div>
        )}

        {showModal && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
            <div className="w-full max-w-md rounded-xl bg-white p-6 shadow-lg">
              <h2 className="mb-4 text-xl font-bold text-gray-900">New Chain</h2>
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Name
                  </label>
                  <input
                    type="text"
                    value={newChainName}
                    onChange={(e) => setNewChainName(e.target.value)}
                    placeholder="e.g. CSRF to Account Takeover"
                    className="w-full rounded-lg border border-gray-300 p-2.5 text-sm outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 text-gray-900"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Hypothesis (Optional)
                  </label>
                  <textarea
                    value={newChainHypothesis}
                    onChange={(e) => setNewChainHypothesis(e.target.value)}
                    placeholder="What are you trying to prove?"
                    rows={3}
                    className="w-full rounded-lg border border-gray-300 p-2.5 text-sm outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 text-gray-900"
                  />
                </div>
              </div>
              <div className="mt-6 flex justify-end gap-3">
                <button
                  onClick={() => setShowModal(false)}
                  className="rounded-lg px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-100"
                >
                  Cancel
                </button>
                <button
                  onClick={handleCreate}
                  disabled={!newChainName || creating}
                  className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-700 disabled:opacity-50"
                >
                  {creating ? "Creating..." : "Create Chain"}
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
