"use client";

import { useState, useEffect } from "react";
import Link from "next/link";
import { companies, type Company } from "@/lib/api";
import LearnMore from "@/components/LearnMore";

export default function CompaniesPage() {
  const [companyList, setCompanyList] = useState<Company[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Modal / Form state
  const [isModalOpen, setIsModalOpen] = useState<boolean>(false);
  const [name, setName] = useState<string>("");
  const [bugBountyUrl, setBugBountyUrl] = useState<string>("");
  const [scopeAuthorized, setScopeAuthorized] = useState<boolean>(false);
  const [submitting, setSubmitting] = useState<boolean>(false);
  const [formError, setFormError] = useState<string | null>(null);

  const fetchCompanies = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await companies.list();
      setCompanyList(Array.isArray(data) ? data : []);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to load companies";
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (id: string) => {
    if (!confirm('Are you sure you want to delete this company? This will remove all associated data.')) return;
    try {
      await companies.delete(id);
      fetchCompanies(); // refresh list
    } catch (err) {
      console.error('Failed to delete company:', err);
    }
  };

  useEffect(() => {
    fetchCompanies();
  }, []);

  const handleOpenModal = () => {
    setName("");
    setBugBountyUrl("");
    setScopeAuthorized(false);
    setFormError(null);
    setIsModalOpen(true);
  };

  const handleCloseModal = () => {
    if (submitting) return;
    setIsModalOpen(false);
    setFormError(null);
  };

  const handleCreateCompany = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) {
      setFormError("Company name is required.");
      return;
    }
    if (!scopeAuthorized) {
      setFormError("Scope authorization confirmation is required before proceeding.");
      return;
    }

    try {
      setSubmitting(true);
      setFormError(null);
      await companies.create({
        name: name.trim(),
        bug_bounty_url: bugBountyUrl.trim() || undefined,
        scope_authorized: scopeAuthorized,
      });
      setIsModalOpen(false);
      await fetchCompanies();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to create company";
      setFormError(msg);
    } finally {
      setSubmitting(false);
    }
  };

  const formatDate = (dateStr: string) => {
    try {
      const d = new Date(dateStr);
      return d.toLocaleDateString("en-US", {
        year: "numeric",
        month: "short",
        day: "numeric",
      });
    } catch {
      return dateStr;
    }
  };

  return (
    <main className="min-h-screen bg-gray-50 pl-56">
      <div className="max-w-7xl mx-auto px-6 py-8">
        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 pb-6 border-b border-gray-200">
          <div>
            <h1 className="text-3xl font-bold tracking-tight text-gray-900 flex items-center gap-2">
              <span>🏢</span> Companies
            </h1>
            <p className="mt-1 text-sm text-gray-500">
              Manage reconnaissance targets, bug bounty program scopes, and target authorizations.
            </p>
          </div>
          <div>
            <button
              onClick={handleOpenModal}
              className="inline-flex items-center gap-2 rounded-lg bg-indigo-600 px-4 py-2.5 text-sm font-medium text-white shadow-sm hover:bg-indigo-700 transition-colors focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2"
            >
              <span className="text-base font-bold">+</span>
              Add Company
            </button>
          </div>
        </div>

        {/* Error Alert */}
        {error && (
          <div className="mt-6 rounded-lg bg-red-50 border border-red-200 p-4 flex items-center justify-between text-sm text-red-700">
            <div className="flex items-center gap-2">
              <span>⚠️</span>
              <span>{error}</span>
            </div>
            <button
              onClick={fetchCompanies}
              className="font-medium underline hover:text-red-900 text-xs"
            >
              Retry
            </button>
          </div>
        )}

        {/* Content Section */}
        <div className="mt-8">
          {loading ? (
            /* Loading Shimmer Grid */
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {[...Array(6)].map((_, i) => (
                <div
                  key={i}
                  className="bg-white rounded-xl shadow-sm border border-gray-200 p-5 animate-pulse flex flex-col justify-between h-44"
                >
                  <div>
                    <div className="flex items-start justify-between gap-2">
                      <div className="h-5 bg-gray-200 rounded w-2/3"></div>
                      <div className="h-5 bg-gray-200 rounded-full w-20"></div>
                    </div>
                    <div className="mt-4 h-3 bg-gray-200 rounded w-4/5"></div>
                    <div className="mt-2 h-3 bg-gray-200 rounded w-1/2"></div>
                  </div>
                  <div className="pt-4 border-t border-gray-100 flex items-center justify-between">
                    <div className="h-3 bg-gray-200 rounded w-24"></div>
                    <div className="h-3 bg-gray-200 rounded w-16"></div>
                  </div>
                </div>
              ))}
            </div>
          ) : companyList.length === 0 ? (
            /* Empty State */
            <div className="rounded-2xl border-2 border-dashed border-gray-200 bg-white p-12 text-center max-w-xl mx-auto my-12 shadow-sm">
              <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-full bg-indigo-50 text-3xl">
                🏢
              </div>
              <h3 className="mt-4 text-lg font-semibold text-gray-900">No companies yet</h3>
              <p className="mt-2 text-sm text-gray-500 leading-relaxed">
                No companies yet. Add a company with a bug bounty program to get started.
              </p>
              <div className="mt-6">
                <button
                  type="button"
                  onClick={handleOpenModal}
                  className="inline-flex items-center gap-2 rounded-lg bg-indigo-600 px-4 py-2.5 text-sm font-medium text-white shadow-sm hover:bg-indigo-700 transition-colors focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2"
                >
                  <span className="text-base font-bold">+</span>
                  Add Company
                </button>
              </div>
            </div>
          ) : (
            /* Companies Grid */
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {companyList.map((company) => (
                <Link
                  key={company.id}
                  href={`/companies/${company.id}`}
                  className="group relative flex flex-col justify-between bg-white rounded-xl shadow-sm border border-gray-200 p-5 hover:shadow-md hover:border-indigo-300 transition-all cursor-pointer"
                >
                  <div>
                    {/* Header: Company Name & Scope Badge */}
                    <div className="flex items-start justify-between gap-3">
                      <h2 className="text-lg font-semibold text-gray-900 group-hover:text-indigo-600 transition-colors truncate">
                        {company.name}
                      </h2>
                      {company.scope_authorized ? (
                        <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-50 text-green-700 border border-green-200 shrink-0">
                          <span>✅</span> Authorized
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-50 text-red-700 border border-red-200 shrink-0">
                          <span>❌</span> Unauthorized
                        </span>
                      )}
                    </div>

                    {/* Bug Bounty URL */}
                    <div className="mt-3">
                      {company.bug_bounty_url ? (
                        <span
                          role="link"
                          tabIndex={0}
                          onClick={(e) => {
                            e.preventDefault();
                            e.stopPropagation();
                            window.open(company.bug_bounty_url!, "_blank", "noopener,noreferrer");
                          }}
                          onKeyDown={(e) => {
                            if (e.key === "Enter") {
                              e.preventDefault();
                              e.stopPropagation();
                              window.open(company.bug_bounty_url!, "_blank", "noopener,noreferrer");
                            }
                          }}
                          className="text-xs text-indigo-600 hover:text-indigo-800 underline truncate inline-flex items-center gap-1 max-w-full hover:font-medium transition-all"
                          title={company.bug_bounty_url}
                        >
                          <span>🔗</span>
                          <span className="truncate">{company.bug_bounty_url}</span>
                        </span>
                      ) : (
                        <span className="text-xs text-gray-400 italic">No bounty URL provided</span>
                      )}
                    </div>

                    {company.description && (
                      <p className="mt-2 text-xs text-gray-500 line-clamp-2">
                        {company.description}
                      </p>
                    )}
                  </div>

                  {/* Footer: Created Date & Details Arrow */}
                  <div className="mt-6 pt-3 border-t border-gray-100 flex items-center justify-between text-xs text-gray-500">
                    <span className="flex items-center gap-1">
                      <span>📅</span>
                      <span>Added {formatDate(company.created_at)}</span>
                    </span>
                    <div className="flex items-center gap-3">
                      <button 
                        onClick={(e) => { e.preventDefault(); e.stopPropagation(); handleDelete(company.id); }}
                        className="text-red-500 hover:text-red-700 transition-colors"
                        title="Delete Company"
                      >
                        🗑️ Delete
                      </button>
                      <span className="text-indigo-600 font-medium group-hover:translate-x-0.5 transition-transform flex items-center gap-0.5">
                        View details →
                      </span>
                    </div>
                  </div>
                </Link>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Add Company Modal */}
      {isModalOpen && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-sm animate-in fade-in duration-150"
          onClick={(e) => {
            if (e.target === e.currentTarget) handleCloseModal();
          }}
        >
          <div className="bg-white rounded-2xl shadow-xl border border-gray-200 w-full max-w-lg max-h-[90vh] overflow-y-auto p-6 space-y-5">
            {/* Modal Header */}
            <div className="flex items-center justify-between border-b border-gray-100 pb-3">
              <h2 className="text-xl font-bold text-gray-900 flex items-center gap-2">
                <span>🏢</span> Add New Company
              </h2>
              <button
                type="button"
                onClick={handleCloseModal}
                disabled={submitting}
                className="text-gray-400 hover:text-gray-600 p-1 rounded-md transition-colors"
                aria-label="Close"
              >
                ✕
              </button>
            </div>

            {/* Modal Form */}
            <form onSubmit={handleCreateCompany} className="space-y-4">
              {formError && (
                <div className="rounded-lg bg-red-50 border border-red-200 p-3 text-xs text-red-700 flex items-center gap-2">
                  <span>⚠️</span>
                  <span>{formError}</span>
                </div>
              )}

              {/* Company Name Input */}
              <div>
                <label htmlFor="company-name" className="block text-xs font-semibold text-gray-700 uppercase tracking-wider mb-1">
                  Company Name <span className="text-red-500">*</span>
                </label>
                <input
                  id="company-name"
                  type="text"
                  required
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="e.g. Acme Corporation"
                  className="w-full rounded-lg border border-gray-300 px-3.5 py-2 text-sm text-gray-900 placeholder-gray-400 focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
                  disabled={submitting}
                />
              </div>

              {/* Bug Bounty URL Input */}
              <div>
                <label htmlFor="bounty-url" className="block text-xs font-semibold text-gray-700 uppercase tracking-wider mb-1">
                  Bug Bounty Program URL
                </label>
                <input
                  id="bounty-url"
                  type="url"
                  value={bugBountyUrl}
                  onChange={(e) => setBugBountyUrl(e.target.value)}
                  placeholder="https://hackerone.com/acme or https://bugcrowd.com/acme"
                  className="w-full rounded-lg border border-gray-300 px-3.5 py-2 text-sm text-gray-900 placeholder-gray-400 focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
                  disabled={submitting}
                />
              </div>

              {/* Scope Authorization Checkbox */}
              <div className="rounded-lg bg-amber-50/80 border border-amber-200 p-3.5 space-y-2">
                <label className="flex items-start gap-3 cursor-pointer">
                  <input
                    type="checkbox"
                    id="scope-authorization"
                    checked={scopeAuthorized}
                    onChange={(e) => setScopeAuthorized(e.target.checked)}
                    disabled={submitting}
                    className="mt-0.5 h-4 w-4 rounded border-amber-300 text-indigo-600 focus:ring-indigo-500"
                  />
                  <span className="text-xs text-amber-900 font-medium leading-relaxed">
                    ⚠️ I confirm that I have explicit permission to test this target through a bug bounty program, pentest contract, or other written authorization.
                  </span>
                </label>
              </div>

              {/* Actions */}
              <div className="flex items-center justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={handleCloseModal}
                  disabled={submitting}
                  className="rounded-lg border border-gray-300 bg-white px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 transition-colors disabled:opacity-50"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={!scopeAuthorized || !name.trim() || submitting}
                  className="inline-flex items-center gap-2 rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {submitting ? (
                    <>
                      <span className="animate-spin text-xs">⏳</span>
                      <span>Adding...</span>
                    </>
                  ) : (
                    "Add Company"
                  )}
                </button>
              </div>
            </form>

            {/* LearnMore below the form */}
            <div className="pt-2 border-t border-gray-100">
              <LearnMore contentId="concept:scope" />
            </div>
          </div>
        </div>
      )}
    </main>
  );
}
