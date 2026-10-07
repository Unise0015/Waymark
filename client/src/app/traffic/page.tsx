"use client";

import { useState, useEffect, useRef } from "react";
import { traffic, TrafficLog } from "@/lib/api";
import ReactMarkdown from 'react-markdown';

export default function TrafficPage() {
  const [logs, setLogs] = useState<TrafficLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedLog, setSelectedLog] = useState<TrafficLog | null>(null);
  
  // Tabs for bottom panes
  const [reqTab, setReqTab] = useState<"raw" | "headers">("raw");
  const [resTab, setResTab] = useState<"raw" | "headers" | "ai">("raw");

  const [aiAnalysisMap, setAiAnalysisMap] = useState<Record<string, string>>({});
  const [analyzingMap, setAnalyzingMap] = useState<Record<string, boolean>>({});

  useEffect(() => {
    fetchLogs();
  }, []);

  const fetchLogs = async () => {
    try {
      const data = await traffic.list(500, 0); // Fetch more for table
      setLogs(data);
      if (data.length > 0 && !selectedLog) {
        setSelectedLog(data[0]);
      }
    } catch (err) {
      console.error("Failed to fetch traffic logs:", err);
    } finally {
      setLoading(false);
    }
  };

  const handleAiAnalysis = async (logId: string) => {
    setResTab("ai");
    if (aiAnalysisMap[logId] || analyzingMap[logId]) return;
    
    setAnalyzingMap(prev => ({ ...prev, [logId]: true }));
    try {
      const res = await traffic.analyze(logId);
      setAiAnalysisMap(prev => ({ ...prev, [logId]: res.analysis }));
    } catch (e) {
      setAiAnalysisMap(prev => ({ ...prev, [logId]: "Failed to generate AI analysis. Ensure backend is running and LLM is configured." }));
    } finally {
      setAnalyzingMap(prev => ({ ...prev, [logId]: false }));
    }
  };

  const formatHeaders = (headers: Record<string, any>) => {
    if (!headers || Object.keys(headers).length === 0) return "";
    return Object.entries(headers)
      .map(([k, v]) => `${k}: ${v}`)
      .join("\n");
  };

  const getHost = (urlStr: string) => {
    try { return new URL(urlStr).hostname; } catch { return "-"; }
  };

  
    const [searchTerm, setSearchTerm] = useState("");
  const [methodFilter, setMethodFilter] = useState("ALL");
  const [statusFilter, setStatusFilter] = useState("ALL");
  const [captureEnabled, setCaptureEnabled] = useState(true);
  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    traffic.getStatus().then(res => setCaptureEnabled(res.capture_enabled)).catch(() => {});
  }, []);

  const handleToggleCapture = async () => {
    try {
      const res = await traffic.toggleCapture();
      setCaptureEnabled(res.capture_enabled);
    } catch (e) {
      console.error("Failed to toggle capture", e);
    }
  };

  const handleImport = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      setLoading(true);
      await traffic.importTraffic(file);
      await fetchLogs();
      alert("Traffic imported successfully!");
    } catch (err) {
      console.error("Failed to import", err);
      alert("Failed to import traffic");
    } finally {
      if (fileInputRef.current) fileInputRef.current.value = "";
      setLoading(false);
    }
  };

  const handleClearTraffic = async () => {
    if (confirm("Are you sure you want to delete all captured proxy traffic logs? This cannot be undone.")) {
      try {
        await traffic.clearAll();
        setLogs([]);
        setSelectedLog(null);
      } catch (err) {
        console.error("Failed to clear traffic:", err);
      }
    }
  };


  const filteredLogs = logs.filter(log => {
    if (methodFilter !== "ALL" && log.method !== methodFilter) return false;
    
    if (statusFilter !== "ALL") {
      const s = log.response_status || 0;
      if (statusFilter === "2xx" && (s < 200 || s >= 300)) return false;
      if (statusFilter === "3xx" && (s < 300 || s >= 400)) return false;
      if (statusFilter === "4xx" && (s < 400 || s >= 500)) return false;
      if (statusFilter === "5xx" && (s < 500 || s >= 600)) return false;
    }
    
    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      if (!log.url.toLowerCase().includes(term) && !log.path.toLowerCase().includes(term)) {
        return false;
      }
    }
    
    return true;
  });

  return (
    <div className="flex h-screen bg-[#f3f3f3] pl-56 pt-16 flex-col">
      {/* Top Bar */}
      <div className="bg-white border-b border-gray-300 p-2 flex justify-between items-center shadow-sm z-10">
        <div className="flex items-center gap-4">
          <h1 className="text-sm font-semibold text-gray-800">HTTP History</h1>
          
          <button 
            onClick={handleToggleCapture}
            className={`flex items-center gap-1.5 px-2 py-1 rounded-full text-[10px] font-bold transition-colors ${
              captureEnabled 
                ? 'bg-green-100 text-green-800 border border-green-200' 
                : 'bg-gray-100 text-gray-600 border border-gray-200'
            }`}
          >
            <div className={`w-2 h-2 rounded-full ${captureEnabled ? 'bg-green-500 animate-pulse' : 'bg-gray-400'}`}></div>
            {captureEnabled ? 'LIVE CAPTURE: ON' : 'CAPTURE: PAUSED'}
          </button>
        </div>

        <div className="flex items-center gap-2">
          <input type="file" ref={fileInputRef} hidden accept=".json" onChange={handleImport} />
          <button
            onClick={() => fileInputRef.current?.click()}
            className="text-xs px-2 py-1 bg-white border border-gray-300 rounded hover:bg-gray-50 text-gray-700 shadow-sm flex items-center gap-1"
            title="Import JSON traffic file"
          >
            📤 Import
          </button>
          <a
            href={traffic.exportUrl()}
            target="_blank"
            className="text-xs px-2 py-1 bg-white border border-gray-300 rounded hover:bg-gray-50 text-gray-700 shadow-sm flex items-center gap-1"
            title="Export traffic to JSON"
          >
            📥 Export
          </a>
          <div className="w-px h-4 bg-gray-300 mx-1"></div>
          <button
            onClick={handleClearTraffic}
            className="text-xs px-3 py-1 bg-white border border-red-200 text-red-600 rounded hover:bg-red-50 shadow-sm"
          >
            🗑️ Clear All
          </button>
          <button
            onClick={fetchLogs}
            className="text-xs px-3 py-1 bg-white border border-gray-300 rounded hover:bg-gray-50 text-gray-700 shadow-sm"
          >
            Refresh
          </button>
        </div>
      </div>


      {/* Filter Bar */}
      <div className="bg-[#f0f0f0] border-b border-gray-300 p-1.5 flex gap-2 items-center text-xs">
        <span className="text-gray-600 font-semibold ml-1">Filters:</span>
        <input 
          type="text" 
          placeholder="Search URL or Path..." 
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          className="border border-gray-300 rounded px-2 py-1 w-64 text-gray-800"
        />
        <select 
          value={methodFilter} 
          onChange={(e) => setMethodFilter(e.target.value)}
          className="border border-gray-300 rounded px-2 py-1 text-gray-800 bg-white"
        >
          <option value="ALL">Any Method</option>
          <option value="GET">GET</option>
          <option value="POST">POST</option>
          <option value="PUT">PUT</option>
          <option value="DELETE">DELETE</option>
          <option value="OPTIONS">OPTIONS</option>
        </select>
        <select 
          value={statusFilter} 
          onChange={(e) => setStatusFilter(e.target.value)}
          className="border border-gray-300 rounded px-2 py-1 text-gray-800 bg-white"
        >
          <option value="ALL">Any Status</option>
          <option value="2xx">2xx Success</option>
          <option value="3xx">3xx Redirection</option>
          <option value="4xx">4xx Client Error</option>
          <option value="5xx">5xx Server Error</option>
        </select>
        <span className="text-gray-500 ml-auto mr-2">Showing {filteredLogs.length} / {logs.length}</span>
      </div>

      {/* Top Pane - Data Table */}
      <div className="h-1/2 overflow-auto bg-white border-b border-gray-300 relative">
        <table className="w-full text-xs text-left whitespace-nowrap">
          <thead className="bg-[#f0f0f0] text-gray-700 sticky top-0 border-b border-gray-300 shadow-sm z-10">
            <tr>
              <th className="px-2 py-1 font-normal border-r border-gray-300 w-12 text-center">#</th>
              <th className="px-2 py-1 font-normal border-r border-gray-300">Host</th>
              <th className="px-2 py-1 font-normal border-r border-gray-300 w-16">Method</th>
              <th className="px-2 py-1 font-normal border-r border-gray-300">URL / Path</th>
              <th className="px-2 py-1 font-normal border-r border-gray-300 w-24">Status</th>
              <th className="px-2 py-1 font-normal border-r border-gray-300">Time</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={6} className="text-center py-4 text-gray-500">Loading...</td></tr>
            ) : filteredLogs.length === 0 ? (
              <tr><td colSpan={6} className="text-center py-4 text-gray-500">No traffic captured yet.</td></tr>
            ) : (
              filteredLogs.map((log, index) => (
                <tr 
                  key={log.id} 
                  onClick={() => setSelectedLog(log)}
                  className={`cursor-pointer border-b border-gray-100 ${
                    selectedLog?.id === log.id ? "bg-[#0058b0] text-white" : "hover:bg-[#f5f9ff] text-gray-800"
                  }`}
                >
                  <td className={`px-2 py-0.5 text-center border-r ${selectedLog?.id === log.id ? 'border-transparent' : 'border-gray-200'}`}>{index + 1}</td>
                  <td className={`px-2 py-0.5 border-r ${selectedLog?.id === log.id ? 'border-transparent' : 'border-gray-200'}`}>{getHost(log.url)}</td>
                  <td className={`px-2 py-0.5 border-r ${selectedLog?.id === log.id ? 'border-transparent' : 'border-gray-200'}`}>{log.method}</td>
                  <td className={`px-2 py-0.5 border-r ${selectedLog?.id === log.id ? 'border-transparent' : 'border-gray-200'} truncate max-w-md`} title={log.url}>{log.path}</td>
                  <td className={`px-2 py-0.5 border-r ${selectedLog?.id === log.id ? 'border-transparent' : 'border-gray-200'}`}>
                    {log.response_status || '-'}
                  </td>
                  <td className="px-2 py-0.5">{new Date(log.created_at).toLocaleTimeString()}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Bottom Pane - Request / Response Split */}
      <div className="h-1/2 flex bg-[#dfdfdf]">
        {/* Request Pane */}
        <div className="w-1/2 flex flex-col border-r border-gray-300">
          <div className="flex bg-[#f0f0f0] border-b border-gray-300 text-xs font-semibold text-gray-700">
            <div className="px-3 py-1.5 border-r border-gray-300 bg-[#dfdfdf]">Request</div>
          </div>
          <div className="flex bg-[#f0f0f0] border-b border-gray-300 text-xs">
            <button onClick={() => setReqTab("raw")} className={`px-4 py-1 border-r border-gray-300 ${reqTab === "raw" ? "bg-white font-semibold text-gray-800 border-t-2 border-t-orange-400" : "hover:bg-gray-200 text-gray-600 border-t-2 border-transparent"}`}>Raw</button>
            <button onClick={() => setReqTab("headers")} className={`px-4 py-1 border-r border-gray-300 ${reqTab === "headers" ? "bg-white font-semibold text-gray-800 border-t-2 border-t-orange-400" : "hover:bg-gray-200 text-gray-600 border-t-2 border-transparent"}`}>Headers</button>
          </div>
          <div className="flex-1 bg-white overflow-auto p-2 font-mono text-[11px] text-gray-800 whitespace-pre-wrap">
            {selectedLog ? (
              reqTab === "raw" ? (
                <>{selectedLog.method} {selectedLog.path} HTTP/1.1{"\n"}{formatHeaders(selectedLog.request_headers)}{"\n\n"}{selectedLog.request_body}</>
              ) : (
                <>{formatHeaders(selectedLog.request_headers)}</>
              )
            ) : "Select a request..."}
          </div>
        </div>

        {/* Response Pane */}
        <div className="w-1/2 flex flex-col">
          <div className="flex bg-[#f0f0f0] border-b border-gray-300 text-xs font-semibold text-gray-700 justify-between items-center pr-2">
            <div className="flex">
              <div className="px-3 py-1.5 border-r border-gray-300 bg-[#dfdfdf]">Response</div>
            </div>
            {selectedLog?.response_status && (
              <span className={`px-2 py-0.5 rounded text-[10px] text-white ${selectedLog.response_status < 400 ? 'bg-green-600' : 'bg-red-600'}`}>
                {selectedLog.response_status}
              </span>
            )}
          </div>
          <div className="flex bg-[#f0f0f0] border-b border-gray-300 text-xs justify-between">
            <div className="flex">
              <button onClick={() => setResTab("raw")} className={`px-4 py-1 border-r border-gray-300 ${resTab === "raw" ? "bg-white font-semibold text-gray-800 border-t-2 border-t-orange-400" : "hover:bg-gray-200 text-gray-600 border-t-2 border-transparent"}`}>Raw</button>
              <button onClick={() => setResTab("headers")} className={`px-4 py-1 border-r border-gray-300 ${resTab === "headers" ? "bg-white font-semibold text-gray-800 border-t-2 border-t-orange-400" : "hover:bg-gray-200 text-gray-600 border-t-2 border-transparent"}`}>Headers</button>
              <button onClick={() => selectedLog && handleAiAnalysis(selectedLog.id)} className={`px-4 py-1 border-r border-gray-300 flex items-center gap-1 ${resTab === "ai" ? "bg-white font-semibold text-indigo-700 border-t-2 border-t-indigo-500" : "hover:bg-gray-200 text-indigo-600 border-t-2 border-transparent"}`}>
                ✨ AI Analysis
              </button>
            </div>
          </div>
          <div className="flex-1 bg-white overflow-auto p-2 font-mono text-[11px] text-gray-800 whitespace-pre-wrap">
            {selectedLog ? (
              resTab === "raw" ? (
                <>HTTP/1.1 {selectedLog.response_status || 'Unknown'}{"\n"}{formatHeaders(selectedLog.response_headers)}{"\n\n"}{selectedLog.response_body}</>
              ) : resTab === "headers" ? (
                <>{formatHeaders(selectedLog.response_headers)}</>
              ) : (
                <div className="font-sans text-sm p-2 prose prose-sm max-w-none text-gray-800">
                  {analyzingMap[selectedLog.id] ? (
                    <div className="flex flex-col items-center justify-center mt-10 text-gray-500">
                      <span className="text-2xl mb-2 animate-bounce">✨</span>
                      Analyzing request & response for attack vectors...
                    </div>
                  ) : (
                    <ReactMarkdown>{aiAnalysisMap[selectedLog.id] || "No analysis generated."}</ReactMarkdown>
                  )}
                </div>
              )
            ) : "Select a request..."}
          </div>
        </div>
      </div>
    </div>
  );
}
