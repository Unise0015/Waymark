"use client";

import { useState, useEffect } from "react";
import { findings, traffic, companies, wildcards, scopeRules, Finding, TrafficLog, Company } from "@/lib/api";

const DEFAULT_REPORT_TEMPLATE = `## Summary
Provide a brief description of the vulnerability and its impact.

## Description
Detailed explanation of the issue, how it was discovered, and the underlying flaw.

## Steps to Reproduce
1. Go to \`[URL]\`
2. ...
3. ...

## Impact
Explain what an attacker can achieve (e.g., data breach, account takeover).

## Mitigation
Recommendations for fixing the vulnerability.
`;

export default function ReportsPage() {
  const [reportContent, setReportContent] = useState(DEFAULT_REPORT_TEMPLATE);
  
  // Undo/Redo state
  const [history, setHistory] = useState<string[]>([DEFAULT_REPORT_TEMPLATE]);
  const [historyIndex, setHistoryIndex] = useState<number>(0);

  const [availableFindings, setAvailableFindings] = useState<Finding[]>([]);
  const [availableTraffic, setAvailableTraffic] = useState<TrafficLog[]>([]);
  const [availableCompanies, setAvailableCompanies] = useState<Company[]>([]);
  
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<"findings" | "traffic">("findings");

  // Create Modal State
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [selectedCompanyId, setSelectedCompanyId] = useState<string>("");
  const [isGenerating, setIsGenerating] = useState(false);

  useEffect(() => {
    // Load draft from localStorage on mount
    const savedDraft = localStorage.getItem("waymark_report_draft_default");
    if (savedDraft) {
      setReportContent(savedDraft);
      setHistory([savedDraft]);
    }

    Promise.all([
      findings.list().catch(() => []),
      traffic.list(20, 0).catch(() => []),
      companies.list().catch(() => [])
    ]).then(([fData, tData, cData]) => {
      setAvailableFindings(fData);
      setAvailableTraffic(tData);
      setAvailableCompanies(cData);
      setLoading(false);
    }).catch(err => {
      console.error("Failed to load evidence data", err);
      setLoading(false);
    });
  }, []);

  const updateContent = (newContent: string) => {
    const newHistory = history.slice(0, historyIndex + 1);
    newHistory.push(newContent);
    if (newHistory.length > 50) newHistory.shift();
    
    setHistory(newHistory);
    setHistoryIndex(newHistory.length - 1);
    setReportContent(newContent);
    // Save to localStorage
    localStorage.setItem("waymark_report_draft_default", newContent);
  };

  const handleUndo = () => {
    if (historyIndex > 0) {
      setHistoryIndex(historyIndex - 1);
      setReportContent(history[historyIndex - 1]);
    }
  };

  const handleRedo = () => {
    if (historyIndex < history.length - 1) {
      setHistoryIndex(historyIndex + 1);
      setReportContent(history[historyIndex + 1]);
    }
  };

  const handleContentChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    setReportContent(e.target.value);
  };
  
  // Save to history on blur instead of on every keystroke to prevent massive histories
  const handleContentBlur = () => {
    if (reportContent !== history[historyIndex]) {
      updateContent(reportContent);
    }
  };

  const injectFinding = (finding: Finding) => {
    const md = `\n### Finding: ${finding.title}\n**Severity:** ${finding.severity.toUpperCase()}\n**Tool:** ${finding.discovery_tool}\n\n${finding.description || "No description provided."}\n`;
    updateContent(reportContent + md);
  };

  const injectTraffic = (log: TrafficLog) => {
    const headersStr = Object.entries(log.request_headers)
      .map(([k, v]) => `${k}: ${v}`)
      .join("\n");
      
    let md = `\n### Captured Request: ${log.method} ${log.path}\n\`\`\`http\n${log.method} ${log.url} HTTP/1.1\n${headersStr}\n\n`;
    if (log.request_body) md += `${log.request_body}\n`;
    md += `\`\`\`\n`;
    updateContent(reportContent + md);
  };

  const copyToClipboard = () => {
    navigator.clipboard.writeText(reportContent);
    alert("Report copied to clipboard! Ready to paste into HackerOne or Bugcrowd.");
  };

  const handleCreateReport = async () => {
    if (!selectedCompanyId) return;
    setIsGenerating(true);
    
    try {
      const company = availableCompanies.find(c => c.id === selectedCompanyId);
      const companyWildcards = await wildcards.listForCompany(selectedCompanyId);
      
      let inScopeText = "";
      let outOfScopeText = "";
      
      for (const wc of companyWildcards) {
        if (wc.scope_status === "in_scope") {
          inScopeText += `- **${wc.root_domain}**\n`;
        } else if (wc.scope_status === "out_of_scope") {
          outOfScopeText += `- **${wc.root_domain}**\n`;
        }
        
        try {
          const rules = await scopeRules.list(wc.id);
          for (const r of rules) {
            if (r.rule_type === "include") {
              inScopeText += `  - ${r.pattern}\n`;
            } else if (r.rule_type === "exclude") {
              outOfScopeText += `  - ${r.pattern}\n`;
            }
          }
        } catch(e) {
          // ignore rules fetch failure
        }
      }
      
      const newTemplate = `# Target: ${company?.name || 'Unknown'}
**Bug Bounty URL:** ${company?.bug_bounty_url || 'N/A'}

## Scope Definition
### In-Scope
${inScopeText || "None specified"}

### Out-of-Scope
${outOfScopeText || "None specified"}

---

## Summary
Provide a brief description of the vulnerability and its impact.

## Description
Detailed explanation of the issue, how it was discovered, and the underlying flaw.

## Steps to Reproduce
1. Go to \`[URL]\`
2. ...

## Impact
Explain what an attacker can achieve (e.g., data breach, account takeover).

## Mitigation
Recommendations for fixing the vulnerability.
`;
      updateContent(newTemplate);
      setShowCreateModal(false);
    } catch (e) {
      console.error(e);
      alert("Failed to fetch scope data");
    } finally {
      setIsGenerating(false);
    }
  };

  return (
    <div className="flex h-screen bg-gray-50 pl-56 pt-16">
      
      {/* Create Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm">
          <div className="w-full max-w-md rounded-2xl bg-white p-6 shadow-xl">
            <h2 className="text-xl font-bold text-gray-900 mb-4">Create New Report</h2>
            <p className="text-sm text-gray-600 mb-4">Select a company to automatically fetch its scope rules.</p>
            
            <div className="mb-6">
              <label className="block text-sm font-medium text-gray-700 mb-1">Company / Target</label>
              <select 
                value={selectedCompanyId} 
                onChange={(e) => setSelectedCompanyId(e.target.value)}
                className="w-full rounded-lg border border-gray-300 p-2 text-sm text-gray-900 focus:ring-indigo-500 focus:border-indigo-500"
              >
                <option value="">Select a company...</option>
                {availableCompanies.map(c => (
                  <option key={c.id} value={c.id}>{c.name}</option>
                ))}
              </select>
            </div>
            
            <div className="flex justify-end gap-3">
              <button 
                onClick={() => setShowCreateModal(false)}
                className="px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-100 rounded-lg"
              >
                Cancel
              </button>
              <button 
                onClick={handleCreateReport}
                disabled={!selectedCompanyId || isGenerating}
                className="px-4 py-2 text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 rounded-lg disabled:opacity-50"
              >
                {isGenerating ? "Fetching..." : "Create Report"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Left side - Markdown Editor */}
      <div className="flex-1 flex flex-col h-full border-r border-gray-200">
        <div className="p-4 border-b border-gray-200 bg-white flex justify-between items-center">
          <div>
            <h1 className="text-xl font-bold text-gray-900">Report Writer</h1>
            <p className="text-xs text-gray-500">Draft Bug Bounty reports in Markdown</p>
          </div>
          <div className="flex items-center gap-2">
            <button 
              onClick={() => setShowCreateModal(true)}
              className="bg-white border border-gray-300 hover:bg-gray-50 text-gray-700 px-3 py-1.5 rounded-lg text-sm font-semibold transition-colors"
            >
              + New Report
            </button>
            <div className="h-6 w-px bg-gray-300 mx-1"></div>
            <button 
              onClick={handleUndo}
              disabled={historyIndex <= 0}
              className="px-2 py-1.5 text-gray-600 hover:bg-gray-100 rounded disabled:opacity-30 disabled:cursor-not-allowed"
              title="Undo"
            >
              ↩ Undo
            </button>
            <button 
              onClick={handleRedo}
              disabled={historyIndex >= history.length - 1}
              className="px-2 py-1.5 text-gray-600 hover:bg-gray-100 rounded disabled:opacity-30 disabled:cursor-not-allowed"
              title="Redo"
            >
              ↪ Redo
            </button>
            <div className="h-6 w-px bg-gray-300 mx-1"></div>
            <button 
              onClick={() => {
                if(confirm('Are you sure you want to clear the entire report?')) {
                  updateContent(DEFAULT_REPORT_TEMPLATE);
                }
              }}
              className="bg-red-50 hover:bg-red-100 border border-red-200 text-red-700 px-3 py-1.5 rounded-lg text-sm font-semibold transition-colors"
            >
              🗑️ Clear
            </button>
            <div className="h-6 w-px bg-gray-300 mx-1"></div>
            <button 
              onClick={copyToClipboard}
              className="bg-indigo-600 hover:bg-indigo-700 text-white px-4 py-1.5 rounded-lg text-sm font-semibold transition-colors flex items-center gap-2"
            >
              Copy Markdown
            </button>
          </div>
        </div>
        <div className="flex-1 p-4 bg-gray-50">
          <textarea
            value={reportContent}
            onChange={handleContentChange}
            onBlur={handleContentBlur}
            className="w-full h-full p-6 border border-gray-200 rounded-xl shadow-sm focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 font-mono text-sm resize-none bg-white text-gray-900"
            placeholder="Write your markdown report here..."
          />
        </div>
      </div>

      {/* Right side - Evidence Injector */}
      <div className="w-96 bg-white h-full flex flex-col">
        <div className="p-4 border-b border-gray-200">
          <h2 className="text-lg font-bold text-gray-900 mb-1">Evidence Library</h2>
          <p className="text-xs text-gray-500 mb-4">Click items to inject them into your report</p>
          
          <div className="flex bg-gray-100 rounded-lg p-1">
            <button
              onClick={() => setActiveTab("findings")}
              className={`flex-1 py-1.5 text-xs font-semibold rounded-md transition-colors ${activeTab === "findings" ? "bg-white shadow text-gray-900" : "text-gray-500 hover:text-gray-700"}`}
            >
              Findings
            </button>
            <button
              onClick={() => setActiveTab("traffic")}
              className={`flex-1 py-1.5 text-xs font-semibold rounded-md transition-colors ${activeTab === "traffic" ? "bg-white shadow text-gray-900" : "text-gray-500 hover:text-gray-700"}`}
            >
              Traffic Log
            </button>
          </div>
        </div>

        <div className="flex-1 overflow-y-auto p-2">
          {loading ? (
            <p className="text-center text-sm text-gray-500 mt-8">Loading evidence...</p>
          ) : activeTab === "findings" ? (
            <div className="space-y-2">
              {availableFindings.length === 0 ? (
                <p className="text-center text-xs text-gray-400 mt-8">No findings available.</p>
              ) : availableFindings.map(f => (
                <div key={f.id} onClick={() => injectFinding(f)} className="p-3 border border-gray-200 rounded-lg cursor-pointer hover:border-indigo-400 hover:bg-indigo-50 transition-colors group">
                  <div className="flex justify-between items-start mb-1">
                    <span className="font-semibold text-xs text-gray-900 truncate pr-2">{f.title}</span>
                    <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold uppercase shrink-0 ${
                      f.severity === 'critical' ? 'bg-red-600 text-white' :
                      f.severity === 'high' ? 'bg-orange-500 text-white' :
                      f.severity === 'medium' ? 'bg-yellow-400 text-gray-900' :
                      f.severity === 'low' ? 'bg-blue-100 text-blue-800' : 'bg-gray-100 text-gray-800'
                    }`}>{f.severity}</span>
                  </div>
                  <p className="text-[10px] text-gray-500 truncate">{f.discovery_tool}</p>
                  <p className="text-[10px] text-indigo-600 font-semibold mt-2 opacity-0 group-hover:opacity-100 transition-opacity">
                    + Inject to report
                  </p>
                </div>
              ))}
            </div>
          ) : (
            <div className="space-y-2">
              {availableTraffic.length === 0 ? (
                <p className="text-center text-xs text-gray-400 mt-8">No traffic captured yet.</p>
              ) : availableTraffic.map(t => (
                <div key={t.id} onClick={() => injectTraffic(t)} className="p-3 border border-gray-200 rounded-lg cursor-pointer hover:border-indigo-400 hover:bg-indigo-50 transition-colors group">
                  <div className="flex items-center gap-2 mb-1">
                    <span className={`px-1 py-0.5 text-[9px] font-bold rounded ${
                      t.method === 'GET' ? 'bg-blue-100 text-blue-700' :
                      t.method === 'POST' ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-700'
                    }`}>{t.method}</span>
                    <span className="font-mono text-xs text-gray-900 truncate" title={t.path}>{t.path}</span>
                  </div>
                  <div className="flex justify-between items-center text-[10px] text-gray-500">
                    <span>Status: {t.response_status || ''}</span>
                    <span className="text-indigo-600 font-semibold opacity-0 group-hover:opacity-100 transition-opacity">
                      + Inject Request
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
