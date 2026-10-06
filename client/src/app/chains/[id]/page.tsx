"use client";

import { useState, useEffect } from "react";
import { useRouter, useParams } from "next/navigation";
import { chains, traffic, TrafficLog } from "@/lib/api";

const METHOD_COLORS: Record<string, string> = {
  GET: "bg-green-100 text-green-800",
  POST: "bg-blue-100 text-blue-800",
  PUT: "bg-orange-100 text-orange-800",
  DELETE: "bg-red-100 text-red-800",
  PATCH: "bg-yellow-100 text-yellow-800",
};

export default function ChainDetailPage() {
  const router = useRouter();
  const params = useParams();
  const id = params?.id as string;
  const [chain, setChain] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [analyzing, setAnalyzing] = useState(false);
  
  // Modal state
  const [showModal, setShowModal] = useState(false);
  const [trafficLogs, setTrafficLogs] = useState<TrafficLog[]>([]);
  const [logsLoading, setLogsLoading] = useState(false);
  const [searchTerm, setSearchTerm] = useState("");

  useEffect(() => {
    if (id) fetchChain();
  }, [id]);

  const fetchChain = async () => {
    try {
      const data = await chains.get(id);
      // Sort steps
      if (data.steps) {
        data.steps.sort((a: any, b: any) => a.step_order - b.step_order);
      }
      setChain(data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleAnalyze = async () => {
    if (!chain || (chain.steps?.length || 0) < 2) return;
    try {
      setAnalyzing(true);
      await chains.analyze(chain.id);
      await fetchChain();
    } catch (err) {
      console.error(err);
      alert("Analysis failed.");
    } finally {
      setAnalyzing(false);
    }
  };

  const openAddModal = async () => {
    setShowModal(true);
    setLogsLoading(true);
    try {
      const logs = await traffic.list(100, 0);
      setTrafficLogs(logs);
    } catch (err) {
      console.error(err);
    } finally {
      setLogsLoading(false);
    }
  };

  const handleAddRequest = async (logId: string) => {
    try {
      const nextOrder = (chain?.steps?.length || 0) + 1;
      await chains.addStep(chain.id, {
        traffic_log_id: logId,
        step_order: nextOrder,
      });
      setShowModal(false);
      await fetchChain();
    } catch (err) {
      console.error(err);
      alert("Failed to add step");
    }
  };

  const handleRemoveStep = async (stepId: string) => {
    if (!confirm("Remove this step?")) return;
    try {
      await chains.removeStep(chain.id, stepId);
      await fetchChain();
    } catch (err) {
      console.error(err);
    }
  };

  const handleUpdateNote = async (stepId: string, note: string) => {
    try {
      await chains.updateStep(chain.id, stepId, { note });
    } catch (err) {
      console.error(err);
    }
  };

  if (loading) {
    return <div className="min-h-screen bg-[#f3f3f3] pl-56 pt-16 p-8 text-gray-500">Loading...</div>;
  }

  if (!chain) {
    return <div className="min-h-screen bg-[#f3f3f3] pl-56 pt-16 p-8 text-gray-500">Chain not found.</div>;
  }

  const filteredLogs = trafficLogs.filter((log) => 
    log.url.toLowerCase().includes(searchTerm.toLowerCase()) || 
    log.path.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="min-h-screen bg-[#f3f3f3] pl-56 pt-16 flex flex-col">
      <div className="bg-white border-b border-gray-300 p-4 shadow-sm z-10 flex items-center justify-between">
        <div className="flex items-center gap-4">
          <button onClick={() => router.push('/chains')} className="text-gray-500 hover:text-gray-900">
            ← Back
          </button>
          <h1 className="text-xl font-bold text-gray-900">{chain.name}</h1>
          <span className={`px-2 py-0.5 rounded text-xs font-semibold ${chain.status === 'analyzed' ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-800'}`}>
            {chain.status}
          </span>
        </div>
        <button
          onClick={handleAnalyze}
          disabled={analyzing || (chain.steps?.length || 0) < 2}
          className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-700 disabled:opacity-50"
        >
          {analyzing ? "Analyzing..." : "🧠 Analyze Chain"}
        </button>
      </div>

      <div className="flex-1 flex overflow-hidden">
        {/* Left Column: Timeline */}
        <div className="w-[60%] overflow-auto border-r border-gray-300 p-6">
          <div className="mb-6">
            <h2 className="text-sm font-medium text-gray-700 mb-1">Hypothesis</h2>
            <div className="bg-white rounded-lg border border-gray-200 p-3 shadow-sm text-sm text-gray-800 min-h-[60px]">
              {chain.hypothesis || <span className="text-gray-400">No hypothesis set.</span>}
            </div>
          </div>

          <div className="relative pl-6">
            {/* Vertical line */}
            <div className="absolute top-0 bottom-0 left-[2.25rem] w-px border-l-2 border-dashed border-gray-300"></div>

            <div className="space-y-6">
              {chain.steps?.map((step: any, idx: number) => {
                const isLast = idx === (chain.steps?.length || 0) - 1;
                return (
                  <div key={step.id} className="relative flex gap-4">
                    {/* Step Number Badge */}
                    <div className="relative z-10 flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-indigo-100 text-xs font-bold text-indigo-700 ring-4 ring-[#f3f3f3]">
                      {idx + 1}
                    </div>

                    <div className="flex-1 rounded-xl border border-gray-200 bg-white p-4 shadow-sm">
                      <div className="flex items-start justify-between gap-4 mb-3">
                        <div className="flex items-center gap-2 overflow-hidden">
                          <span className={`shrink-0 rounded px-1.5 py-0.5 text-[10px] font-bold ${METHOD_COLORS[step.traffic_log?.method] || 'bg-gray-100 text-gray-800'}`}>
                            {step.traffic_log?.method}
                          </span>
                          <span className="truncate text-sm font-mono text-gray-700" title={step.traffic_log?.url}>
                            {step.traffic_log?.path}
                          </span>
                        </div>
                        <div className="flex items-center gap-3 shrink-0">
                          {step.traffic_log?.response_status && (
                            <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold text-white ${step.traffic_log.response_status < 400 ? 'bg-green-500' : 'bg-red-500'}`}>
                              {step.traffic_log.response_status}
                            </span>
                          )}
                          <button
                            onClick={() => handleRemoveStep(step.id)}
                            className="text-gray-400 hover:text-red-600 text-sm"
                            title="Remove Step"
                          >
                            ✕
                          </button>
                        </div>
                      </div>
                      
                      <textarea
                        defaultValue={step.note || ""}
                        onBlur={(e) => {
                          if (e.target.value !== step.note) {
                            handleUpdateNote(step.id, e.target.value);
                          }
                        }}
                        placeholder="Add a note explaining this step's role in the chain..."
                        className="w-full rounded-md border border-gray-200 p-2 text-xs text-gray-700 outline-none focus:border-indigo-500"
                        rows={2}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
            
            <div className="relative mt-6 flex">
              <div className="relative z-10 flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-gray-200 text-xs font-bold text-gray-500 ring-4 ring-[#f3f3f3]">
                +
              </div>
              <div className="ml-4">
                <button
                  onClick={openAddModal}
                  className="rounded-lg border border-dashed border-gray-300 px-4 py-2 text-sm font-medium text-gray-600 hover:border-gray-400 hover:bg-gray-50"
                >
                  Add Request
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Right Column: AI Analysis */}
        <div className="w-[40%] bg-white p-6 overflow-auto">
          <h2 className="text-lg font-bold text-gray-900 mb-4 flex items-center gap-2">
            ✨ AI Analysis
          </h2>

          {chain.ai_analysis ? (
            <div>
              <div className="flex gap-2 mb-4">
                {chain.verdict && (
                  <span className={`px-2 py-1 rounded text-xs font-bold ${
                    chain.verdict === 'CONFIRMED' ? 'bg-red-100 text-red-700' :
                    chain.verdict === 'PARTIAL' ? 'bg-orange-100 text-orange-700' :
                    chain.verdict === 'FAILED' ? 'bg-gray-100 text-gray-700' :
                    'bg-yellow-100 text-yellow-700'
                  }`}>
                    {chain.verdict}
                  </span>
                )}
                {chain.severity && (
                  <span className="px-2 py-1 rounded text-xs font-bold bg-gray-100 text-gray-700">
                    {chain.severity}
                  </span>
                )}
              </div>
              
              <div className="prose prose-sm max-w-none">
                {chain.ai_analysis.split('\n').map((line: string, i: number) => {
                  const formatted = line.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
                  return <p key={i} className="text-sm text-gray-800 mb-1" dangerouslySetInnerHTML={{ __html: formatted }} />;
                })}
              </div>
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center h-48 rounded-xl border border-dashed border-gray-300 text-center p-6">
              <span className="text-2xl mb-2 text-gray-400">🧠</span>
              <p className="text-sm text-gray-600">Add at least 2 requests and click Analyze Chain</p>
            </div>
          )}
        </div>
      </div>

      {/* Add Request Modal */}
      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
          <div className="w-full max-w-3xl max-h-[80vh] flex flex-col rounded-xl bg-white shadow-lg overflow-hidden">
            <div className="p-4 border-b border-gray-200 flex justify-between items-center bg-gray-50">
              <h2 className="text-lg font-bold text-gray-900">Select Request from Traffic</h2>
              <button onClick={() => setShowModal(false)} className="text-gray-500 hover:text-gray-900">✕</button>
            </div>
            
            <div className="p-4 border-b border-gray-200 bg-white">
              <input
                type="text"
                placeholder="Search URL or path..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full rounded-md border border-gray-300 p-2 text-sm text-gray-900 outline-none focus:border-indigo-500"
              />
            </div>

            <div className="flex-1 overflow-auto p-4 bg-white">
              {logsLoading ? (
                <div className="text-center text-gray-500 py-8">Loading traffic logs...</div>
              ) : filteredLogs.length === 0 ? (
                <div className="text-center text-gray-500 py-8">No matching requests found.</div>
              ) : (
                <div className="space-y-2">
                  {filteredLogs.map(log => (
                    <div key={log.id} className="flex items-center justify-between p-3 border border-gray-200 rounded-lg hover:bg-gray-50">
                      <div className="flex items-center gap-3 overflow-hidden">
                        <span className={`shrink-0 rounded px-1.5 py-0.5 text-[10px] font-bold ${METHOD_COLORS[log.method] || 'bg-gray-100 text-gray-800'}`}>
                          {log.method}
                        </span>
                        <span className="truncate text-sm font-mono text-gray-700" title={log.url}>
                          {log.path}
                        </span>
                        {log.response_status && (
                          <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold text-white shrink-0 ${log.response_status < 400 ? 'bg-green-500' : 'bg-red-500'}`}>
                            {log.response_status}
                          </span>
                        )}
                      </div>
                      <button
                        onClick={() => handleAddRequest(log.id)}
                        className="ml-4 shrink-0 rounded bg-indigo-50 px-3 py-1 text-xs font-medium text-indigo-700 hover:bg-indigo-100"
                      >
                        Add
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
