"use client";

import { useState, useEffect } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { companies, wildcards, scopeRules, schedules, scans, Company, Wildcard, Schedule, exports } from "@/lib/api";
import { LearnMore } from "@/components/LearnMore";

export default function CompanyDetailPage() {
  const params = useParams();
  const id = params.id as string;

  const [company, setCompany] = useState<Company | null>(null);
  const [wildcardList, setWildcardList] = useState<Wildcard[]>([]);
  const [scheduleList, setScheduleList] = useState<Schedule[]>([]);
  const [activeTab, setActiveTab] = useState<"wildcards" | "scope">("wildcards");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Add Wildcard form state
  const [showAddForm, setShowAddForm] = useState(false);
  const [newDomain, setNewDomain] = useState("");
  const [newScopeStatus, setNewScopeStatus] = useState("in_scope");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  // Add Schedule form state
  const [showAddSchedule, setShowAddSchedule] = useState(false);
  const [scheduleWildcardId, setScheduleWildcardId] = useState("");
  const [scheduleFrequency, setScheduleFrequency] = useState("daily");
  const [scheduleCron, setScheduleCron] = useState("");
  const [scheduleScanMode, setScheduleScanMode] = useState("full");
  const [isScheduleSubmitting, setIsScheduleSubmitting] = useState(false);
  const [scheduleFormError, setScheduleFormError] = useState<string | null>(null);

  // Scan modal state
  const [showScanModal, setShowScanModal] = useState(false);
  const [scanWildcardId, setScanWildcardId] = useState<string | null>(null);
  const [scanWildcardDomain, setScanWildcardDomain] = useState<string>("");
  const [enabledTools, setEnabledTools] = useState<string[]>(['subfinder', 'httpx']);
  const [scanRateLimit, setScanRateLimit] = useState(25);
  const [useProxy, setUseProxy] = useState(false);
  const [isScanSubmitting, setIsScanSubmitting] = useState(false);
  // Exclude Rules state
  const [excludeRules, setExcludeRules] = useState<any[]>([]);
  const [showAddExclude, setShowAddExclude] = useState(false);
  const [newExcludePattern, setNewExcludePattern] = useState("");
  const [isExcludeSubmitting, setIsExcludeSubmitting] = useState(false);

  const toggleTool = (toolName: string) => {
    setEnabledTools(prev => 
      prev.includes(toolName) 
        ? prev.filter(t => t !== toolName)
        : [...prev, toolName]
    );
  };

  const AVAILABLE_TOOLS = [
    { name: 'subfinder', icon: '🔍', label: 'Subfinder', desc: 'Discovers subdomains from public certificate logs, DNS databases, and search engines. Never touches the target directly.', tag: 'Passive', tagColor: 'bg-green-100 text-green-800' },
    { name: 'httpx', icon: '🌐', label: 'HTTPX', desc: 'Probes discovered subdomains to check which have live web servers. Detects technology stacks and security headers.', tag: 'Light Active', tagColor: 'bg-blue-100 text-blue-800' },
    { name: 'dnsx', icon: '📡', label: 'DNSX', desc: 'Resolves DNS records (A, AAAA, CNAME, MX) for discovered subdomains. Reveals hosting infrastructure.', tag: 'Passive', tagColor: 'bg-green-100 text-green-800' },
    { name: 'naabu', icon: '🔌', label: 'Naabu', desc: 'Fast port scanner. Finds open ports on live hosts to identify running services like SSH, FTP, databases.', tag: 'Active', tagColor: 'bg-orange-100 text-orange-800' },
    { name: 'nuclei', icon: '☢️', label: 'Nuclei', desc: 'Vulnerability scanner using community templates. Detects CVEs, misconfigurations, exposed panels, and default credentials.', tag: 'Active', tagColor: 'bg-orange-100 text-orange-800' },
    { name: 'ffuf', icon: '📁', label: 'FFUF', desc: 'Directory and file fuzzer. Discovers hidden pages, admin panels, backup files, and API endpoints.', tag: 'Active', tagColor: 'bg-orange-100 text-orange-800' },
    { name: 'katana', icon: '🕷️', label: 'Katana', desc: 'Web crawler that follows links and discovers JavaScript endpoints, forms, and hidden URLs.', tag: 'Active', tagColor: 'bg-orange-100 text-orange-800' },
    { name: 'gau', icon: '🕰️', label: 'GAU', desc: 'Fetches historical URLs from Wayback Machine, Common Crawl, and AlienVault OTX. Finds deleted pages and old endpoints.', tag: 'Passive', tagColor: 'bg-green-100 text-green-800' },
    { name: 'paramspider', icon: '🎯', label: 'ParamSpider', desc: 'Mines web archives to find URLs with query parameters (?id=, ?url=, ?search=). Each parameter is a potential injection point for bugs.', tag: 'Passive', tagColor: 'bg-green-100 text-green-800' },
  ];

  useEffect(() => {
    if (!id) return;

    let isMounted = true;
    setLoading(true);
    setError(null);

    Promise.all([
      companies.get(id),
      wildcards.listForCompany(id),
      schedules.list(),
    ])
      .then(async ([companyData, wildcardsData, allSchedules]) => {
        if (!isMounted) return;
        setCompany(companyData);
        const wList = wildcardsData || [];
        setWildcardList(wList);
        if (wList.length > 0) {
          setScheduleWildcardId(wList[0].id);
          try {
            const rules = await scopeRules.list(wList[0].id);
            setExcludeRules(rules.filter(r => r.rule_type === 'exclude'));
          } catch(e) { console.error(e); }
        }
        const wildcardIds = new Set(wList.map((w) => w.id));
        setScheduleList((allSchedules || []).filter((s) => wildcardIds.has(s.wildcard_id)));
      })
      .catch((err) => {
        if (!isMounted) return;
        setError(err instanceof Error ? err.message : "Failed to load company details");
      })
      .finally(() => {
        if (isMounted) setLoading(false);
      });

    return () => {
      isMounted = false;
    };
  }, [id]);

  const handleStartScan = async () => {
    if (!scanWildcardId) return;
    setIsScanSubmitting(true);
    try {
      const isWildcard = scanWildcardDomain.startsWith('*.');
      const finalTools = isWildcard 
        ? enabledTools 
        : enabledTools.filter(t => !['subfinder', 'dnsx'].includes(t));

      const scan = await scans.create({
        target_type: 'wildcard',
        target_id: scanWildcardId,
        profile: 'custom',
        enabled_tools: finalTools,
        rate_limit: scanRateLimit,
        use_proxy: useProxy
      });
      if (scan && scan.id) {
        setShowScanModal(false);
        alert(`Scan started! Scan ID: ${scan.id}`);
      } else {
        alert('Failed to start scan');
      }
    } catch (err) {
      console.error(err);
      alert('Failed to start scan');
    } finally {
      setIsScanSubmitting(false);
    }
  };

  const handleDeleteWildcard = async (wildcardId: string) => {
    if (!confirm('Delete this wildcard?')) return;
    try {
      await wildcards.delete(wildcardId);
      // Refresh wildcards
      const data = await wildcards.listForCompany(id);
      setWildcardList(data || []);
    } catch (err) {
      console.error('Failed to delete wildcard:', err);
    }
  };

  
  const handleAddExclude = async (e: React.FormEvent) => {
    e.preventDefault();
    if (wildcardList.length === 0) {
      alert("Please add at least one Include target first.");
      return;
    }
    setIsExcludeSubmitting(true);
    try {
      const created = await scopeRules.create(wildcardList[0].id, {
        pattern: newExcludePattern,
        rule_type: "exclude",
        is_regex: true,
        description: "Added via UI"
      });
      setExcludeRules(prev => [...prev, created]);
      setNewExcludePattern("");
      setShowAddExclude(false);
    } catch (err) {
      alert(err instanceof Error ? err.message : "Failed to add exclude rule");
    } finally {
      setIsExcludeSubmitting(false);
    }
  };

  const handleDeleteExclude = async (ruleId: string) => {
    if (!confirm("Remove this exclude rule?")) return;
    try {
      await scopeRules.delete(ruleId);
      setExcludeRules(prev => prev.filter(r => r.id !== ruleId));
    } catch (err) {
      alert("Failed to delete rule");
    }
  };

  const handleAddWildcard = async (e: React.FormEvent) => {
    e.preventDefault();
    const trimmedDomain = newDomain.trim();
    if (!trimmedDomain) return;

    setIsSubmitting(true);
    setFormError(null);

    try {
      const created = await wildcards.create(id, {
        root_domain: trimmedDomain,
        scope_status: newScopeStatus,
      });
      setWildcardList((prev) => [...prev, created]);
      if (!scheduleWildcardId) {
        setScheduleWildcardId(created.id);
      }
      setNewDomain("");
      setNewScopeStatus("in_scope");
      setShowAddForm(false);
    } catch (err) {
      setFormError(err instanceof Error ? err.message : "Failed to add wildcard");
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleAddSchedule = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!scheduleWildcardId) {
      setScheduleFormError("Please select a target wildcard");
      return;
    }
    if (scheduleFrequency === "custom" && !scheduleCron.trim()) {
      setScheduleFormError("Please enter a cron expression (e.g. 0 0 * * *)");
      return;
    }

    setIsScheduleSubmitting(true);
    setScheduleFormError(null);

    try {
      const created = await schedules.create({
        wildcard_id: scheduleWildcardId,
        frequency: scheduleFrequency,
        cron_expression: scheduleFrequency === "custom" ? scheduleCron.trim() : undefined,
        scan_mode: scheduleScanMode,
        is_active: true,
      });
      setScheduleList((prev) => [...prev, created]);
      setShowAddSchedule(false);
      setScheduleCron("");
      setScheduleFrequency("daily");
    } catch (err) {
      setScheduleFormError(err instanceof Error ? err.message : "Failed to create schedule");
    } finally {
      setIsScheduleSubmitting(false);
    }
  };

  const handleToggleSchedule = async (scheduleId: string) => {
    try {
      const updated = await schedules.toggle(scheduleId);
      setScheduleList((prev) =>
        prev.map((s) => (s.id === scheduleId ? updated : s))
      );
    } catch (err) {
      alert(err instanceof Error ? err.message : "Failed to toggle schedule");
    }
  };

  const handleDeleteSchedule = async (scheduleId: string) => {
    if (!confirm("Are you sure you want to delete this scan schedule?")) return;
    try {
      await schedules.delete(scheduleId);
      setScheduleList((prev) => prev.filter((s) => s.id !== scheduleId));
    } catch (err) {
      alert(err instanceof Error ? err.message : "Failed to delete schedule");
    }
  };

  const getScopeBadge = (status: string) => {
    switch (status) {
      case "in_scope":
        return (
          <span className="inline-flex items-center gap-1 rounded-full bg-emerald-50 px-2.5 py-0.5 text-xs font-medium text-emerald-700 ring-1 ring-inset ring-emerald-600/20">
            ✅ In Scope
          </span>
        );
      case "out_of_scope":
        return (
          <span className="inline-flex items-center gap-1 rounded-full bg-red-50 px-2.5 py-0.5 text-xs font-medium text-red-700 ring-1 ring-inset ring-red-600/20">
            ❌ Out of Scope
          </span>
        );
      case "pending_review":
      default:
        return (
          <span className="inline-flex items-center gap-1 rounded-full bg-amber-50 px-2.5 py-0.5 text-xs font-medium text-amber-700 ring-1 ring-inset ring-amber-600/20">
            ⏸️ Pending Review
          </span>
        );
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 pl-56">
      <div className="max-w-7xl mx-auto px-6 py-8">
        {/* Back link */}
        <div className="mb-6">
          <Link
            href="/companies"
            className="inline-flex items-center gap-1 text-sm font-medium text-gray-500 hover:text-indigo-600 transition-colors"
          >
            ← Companies
          </Link>
        </div>

        {/* Loading State */}
        {loading && (
          <div className="rounded-xl border border-gray-200 bg-white p-12 text-center shadow-sm">
            <div className="inline-block h-8 w-8 animate-spin rounded-full border-4 border-indigo-600 border-r-transparent"></div>
            <p className="mt-4 text-sm font-medium text-gray-600">Loading company details...</p>
          </div>
        )}

        {/* Error State */}
        {!loading && error && (
          <div className="rounded-xl border border-red-200 bg-red-50 p-6 shadow-sm">
            <div className="flex items-start gap-3">
              <span className="text-xl">⚠️</span>
              <div>
                <h3 className="text-sm font-semibold text-red-800">Error loading company</h3>
                <p className="mt-1 text-sm text-red-600">{error}</p>
                <button
                  onClick={() => {
                    setError(null);
                    setLoading(true);
                    Promise.all([
                      companies.get(id),
                      wildcards.listForCompany(id),
                    ])
                      .then(([companyData, wildcardsData]) => {
                        setCompany(companyData);
                        setWildcardList(wildcardsData || []);
                      })
                      .catch((err) => {
                        setError(err instanceof Error ? err.message : "Failed to load company details");
                      })
                      .finally(() => setLoading(false));
                  }}
                  className="mt-3 inline-flex items-center rounded-lg bg-red-600 px-3 py-1.5 text-xs font-semibold text-white shadow-sm hover:bg-red-500 transition-colors"
                >
                  Try Again
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Company Details & Wildcards */}
        {!loading && !error && company && (
          <>
            {/* Company Header */}
            <div className="mb-8 rounded-xl border border-gray-200 bg-white p-6 shadow-sm">
              <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
                <div>
                  <div className="flex flex-wrap items-center gap-3">
                    <h1 className="text-2xl font-bold text-gray-900">{company.name}</h1>
                    {company.scope_authorized ? (
                      <span className="inline-flex items-center gap-1 rounded-full bg-emerald-50 px-2.5 py-0.5 text-xs font-medium text-emerald-700 ring-1 ring-inset ring-emerald-600/20">
                        ✅ Scope Authorized
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 rounded-full bg-red-50 px-2.5 py-0.5 text-xs font-medium text-red-700 ring-1 ring-inset ring-red-600/20">
                        ❌ Scope Unauthorized
                      </span>
                    )}
                  </div>
                  {company.description && (
                    <p className="mt-2 text-sm text-gray-600 max-w-2xl">{company.description}</p>
                  )}
                  <div className="mt-4 flex flex-wrap items-center gap-4 text-xs text-gray-500">
                    <span>
                      📅 Created:{" "}
                      {new Date(company.created_at).toLocaleDateString("en-US", {
                        year: "numeric",
                        month: "short",
                        day: "numeric",
                      })}
                    </span>
                    {company.bug_bounty_url && (
                      <a
                        href={
                          company.bug_bounty_url.startsWith("http")
                            ? company.bug_bounty_url
                            : `https://${company.bug_bounty_url}`
                        }
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 font-medium text-indigo-600 hover:text-indigo-800 hover:underline"
                      >
                        🎯 Bug Bounty Policy ↗
                      </a>
                    )}
                  </div>
                </div>
              </div>
            </div>

            

                        
            {/* Target Scope Section */}
            <div className="mb-8">
              <div className="mb-4 flex items-center justify-between">
                <div>
                  <h2 className="text-xl font-bold text-gray-900">Target Scope</h2>
                  <p className="text-xs text-gray-500 mt-1">
                    Use these settings to define exactly what hosts and URLs constitute the target for your current work. 
                  </p>
                </div>
                <button
                  onClick={() => {
                    if (wildcardList.length === 0) {
                      alert("Please add an Include target first.");
                      return;
                    }
                    if (wildcardList.length === 1) {
                      setScanWildcardId(wildcardList[0].id);
                      setScanWildcardDomain(wildcardList[0].root_domain);
                      setShowScanModal(true);
                    } else {
                      // Just open modal and let them pick in the modal
                      setScanWildcardId(wildcardList[0].id);
                      setScanWildcardDomain(wildcardList[0].root_domain);
                      setShowScanModal(true);
                    }
                  }}
                  className="inline-flex items-center gap-1.5 rounded-lg bg-indigo-600 px-4 py-2 text-sm font-semibold text-white shadow-sm hover:bg-indigo-500 transition-colors"
                >
                  ▶ Start Scan
                </button>
              </div>

              {/* Include Table */}
              <div className="mb-6">
                <h3 className="text-sm font-semibold text-gray-700 mb-2">Include in scope</h3>
                <div className="flex gap-2 mb-2">
                   <button onClick={() => setShowAddForm(true)} className="px-3 py-1 bg-gray-100 hover:bg-gray-200 text-xs font-semibold text-gray-700 rounded border border-gray-300">Add Target</button>
                </div>
                
                {showAddForm && (
                  <form onSubmit={handleAddWildcard} className="mb-4 p-3 border border-gray-200 bg-white rounded flex gap-2 items-center">
                    <input 
                      type="text" 
                      value={newDomain} 
                      onChange={(e) => setNewDomain(e.target.value)} 
                      placeholder="example.com or *.example.com" 
                      className="border border-gray-300 rounded px-2 py-1 text-sm flex-1 text-gray-900"
                      required 
                    />
                    <button type="submit" disabled={isSubmitting} className="bg-indigo-600 text-white px-3 py-1 rounded text-sm hover:bg-indigo-500">Save</button>
                    <button type="button" onClick={() => setShowAddForm(false)} className="bg-gray-100 text-gray-700 border border-gray-300 px-3 py-1 rounded text-sm hover:bg-gray-200">Cancel</button>
                  </form>
                )}

                <div className="border border-gray-300 bg-white max-h-64 overflow-y-auto">
                  <table className="w-full text-xs text-left">
                    <thead className="bg-[#f0f0f0] sticky top-0 border-b border-gray-300">
                      <tr>
                        <th className="px-2 py-1 font-semibold text-gray-900 border-r border-gray-300 w-16 text-center">Enabled</th>
                        <th className="px-2 py-1 font-semibold text-gray-900 border-r border-gray-300">Prefix / Domain</th>
                        <th className="px-2 py-1 font-semibold text-gray-900 w-32">Include subdomains</th>
                        <th className="px-2 py-1 font-semibold text-gray-900 w-16">Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {wildcardList.length === 0 ? (
                        <tr><td colSpan={4} className="text-center py-4 text-gray-500">No targets in scope. Add one to begin.</td></tr>
                      ) : (
                        wildcardList.map(wc => (
                          <tr key={wc.id} className="hover:bg-[#f5f9ff] border-b border-gray-100">
                            <td className="px-2 py-1 border-r border-gray-200 text-center"><input type="checkbox" defaultChecked /></td>
                            <td className="px-2 py-1 border-r border-gray-200 font-mono text-gray-900 font-medium">
                              ^https?://.*\.{wc.root_domain.replace('*.', '').replace('.', '\\.')}/
                            </td>
                            <td className="px-2 py-1 border-r border-gray-200 text-gray-600">{wc.root_domain.startsWith('*.') ? 'Yes' : 'No'}</td>
                            <td className="px-2 py-1 text-center">
                              <button onClick={() => handleDeleteWildcard(wc.id)} className="text-red-500 hover:text-red-700">Remove</button>
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Exclude Table */}
              <div>
                <h3 className="text-sm font-semibold text-gray-700 mb-2">Exclude from scope</h3>
                <div className="flex gap-2 mb-2">
                   <button onClick={() => setShowAddExclude(true)} className="px-3 py-1 bg-gray-100 hover:bg-gray-200 text-xs font-semibold text-gray-700 rounded border border-gray-300">Add</button>
                </div>

                {showAddExclude && (
                  <form onSubmit={handleAddExclude} className="mb-4 p-3 border border-gray-200 bg-white rounded flex gap-2 items-center">
                    <input 
                      type="text" 
                      value={newExcludePattern} 
                      onChange={(e) => setNewExcludePattern(e.target.value)} 
                      placeholder="^https?://out-of-scope\.example\.com/.*" 
                      className="border border-gray-300 rounded px-2 py-1 text-sm flex-1 text-gray-900"
                      required 
                    />
                    <button type="submit" disabled={isExcludeSubmitting} className="bg-indigo-600 text-white px-3 py-1 rounded text-sm hover:bg-indigo-500">Save</button>
                    <button type="button" onClick={() => setShowAddExclude(false)} className="bg-gray-100 text-gray-700 border border-gray-300 px-3 py-1 rounded text-sm hover:bg-gray-200">Cancel</button>
                  </form>
                )}

                <div className="border border-gray-300 bg-white h-32 overflow-y-auto">
                  <table className="w-full text-xs text-left">
                    <thead className="bg-[#f0f0f0] sticky top-0 border-b border-gray-300">
                      <tr>
                        <th className="px-2 py-1 font-semibold text-gray-900 border-r border-gray-300 w-16 text-center">Enabled</th>
                        <th className="px-2 py-1 font-semibold text-gray-900 border-r border-gray-300">Prefix / Regex Pattern</th>
                        <th className="px-2 py-1 font-semibold text-gray-900 w-16">Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {excludeRules.length === 0 ? (
                        <tr><td colSpan={3} className="text-center py-4 text-gray-500">No exclusions defined.</td></tr>
                      ) : (
                        excludeRules.map(rule => (
                          <tr key={rule.id} className="hover:bg-[#f5f9ff] border-b border-gray-100">
                            <td className="px-2 py-1 border-r border-gray-200 text-center"><input type="checkbox" defaultChecked /></td>
                            <td className="px-2 py-1 border-r border-gray-200 font-mono text-gray-900 font-medium">{rule.pattern}</td>
                            <td className="px-2 py-1 text-center">
                              <button onClick={() => handleDeleteExclude(rule.id)} className="text-red-500 hover:text-red-700">Remove</button>
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          </>
        )}

        {/* Scan Configuration Modal */}
        {showScanModal && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-gray-900/50 backdrop-blur-sm">
            <div className="w-full max-w-lg rounded-xl bg-white p-6 shadow-xl">
              <div className="mb-4 flex items-center justify-between">
                <h3 className="text-lg font-bold text-gray-900">Configure Scan</h3>
                <button
                  onClick={() => setShowScanModal(false)}
                  className="text-gray-500 hover:text-gray-700"
                >
                  ✕
                </button>
              </div>
              
              <div className="space-y-6">
                <div>
                  <label className="mb-1 block text-sm font-medium text-gray-700">Target to Scan</label>
                  {wildcardList.length > 1 ? (
                    <select 
                      value={scanWildcardId || ""} 
                      onChange={(e) => {
                        setScanWildcardId(e.target.value);
                        setScanWildcardDomain(wildcardList.find(w => w.id === e.target.value)?.root_domain || "");
                      }}
                      className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm text-gray-900 font-mono focus:border-indigo-500 focus:outline-none"
                    >
                      {wildcardList.map(wc => (
                        <option key={wc.id} value={wc.id}>{wc.root_domain}</option>
                      ))}
                    </select>
                  ) : (
                    <div className="rounded-lg bg-gray-100 px-3 py-2 text-sm text-gray-900 font-mono">
                      {scanWildcardDomain}
                    </div>
                  )}
                </div>

                <div>
                  <label className="mb-2 block text-sm font-medium text-gray-700">Tools</label>
                  <div className="space-y-2 max-h-80 overflow-y-auto">
                    {AVAILABLE_TOOLS.filter(tool => 
                      scanWildcardDomain.startsWith('*.') ? true : !['subfinder', 'dnsx'].includes(tool.name)
                    ).map(tool => (
                      <label key={tool.name} className={`flex items-start gap-3 p-3 rounded-lg border cursor-pointer transition-all ${enabledTools.includes(tool.name) ? 'border-indigo-300 bg-indigo-50/50' : 'border-gray-200 bg-white hover:bg-gray-50'}`}>
                        <input
                          type="checkbox"
                          checked={enabledTools.includes(tool.name)}
                          onChange={() => toggleTool(tool.name)}
                          className="mt-1 h-4 w-4 rounded border-gray-300 text-indigo-600 focus:ring-indigo-500"
                        />
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2">
                            <span>{tool.icon}</span>
                            <span className="font-semibold text-sm text-gray-900">{tool.label}</span>
                            <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${tool.tagColor}`}>{tool.tag}</span>
                          </div>
                          <p className="mt-0.5 text-xs text-gray-600">{tool.desc}</p>
                        </div>
                      </label>
                    ))}
                  </div>
                  
              {/* Burp Suite Proxy Toggle */}
              <div className="mt-4">
                <label className="flex items-center gap-3 p-3 rounded-lg border border-gray-200 bg-white hover:bg-gray-50 cursor-pointer transition-all">
                  <input
                    type="checkbox"
                    checked={useProxy}
                    onChange={(e) => setUseProxy(e.target.checked)}
                    className="h-4 w-4 rounded border-gray-300 text-indigo-600 focus:ring-indigo-500"
                  />
                  <div>
                    <span className="font-semibold text-sm text-gray-900 flex items-center gap-2">🦊 Send to Burp Suite Proxy</span>
                    <p className="mt-0.5 text-xs text-gray-500">Route active tools (FFUF, Katana, Nuclei) through 127.0.0.1:8080.</p>
                  </div>
                </label>
              </div>

              <p className="mt-2 text-xs text-gray-500">
                    {scanWildcardDomain.startsWith('*.') 
                      ? "💡 Tip: This is a wildcard target. Start with Subfinder and DNSX to discover subdomains first, then pass them to active tools."
                      : "💡 Tip: This is a specific domain. Subdomain enumeration is skipped. Focus on Katana, FFUF, and Nuclei to find endpoints and bugs."}
                  </p>
                </div>

                <div>
                  <label className="mb-1 block text-sm font-medium text-gray-700">Rate Limit (req/sec)</label>
                  <input
                    type="number"
                    min="1"
                    max="150"
                    value={scanRateLimit}
                    onChange={(e) => setScanRateLimit(Number(e.target.value))}
                    className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm text-gray-900 focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
                  />
                  <p className="mt-1 text-xs text-gray-500">
                    Lower = stealthier. 25 is safe for most targets.
                  </p>
                </div>
              </div>

              <div className="mt-6 flex items-center justify-end gap-3 border-t border-gray-100 pt-4">
                <button
                  type="button"
                  onClick={() => setShowScanModal(false)}
                  className="rounded-lg border border-gray-300 bg-white px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50 transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={handleStartScan}
                  disabled={isScanSubmitting}
                  className="inline-flex items-center gap-2 rounded-lg bg-indigo-600 px-4 py-2 text-sm font-semibold text-white shadow-sm hover:bg-indigo-500 disabled:opacity-50 transition-colors"
                >
                  {isScanSubmitting ? "Starting..." : "Start Scan"}
                </button>
              </div>
            </div>
          </div>
        )}

      </div>
    </div>
  );
}
