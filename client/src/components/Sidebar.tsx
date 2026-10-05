"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const NAV_ITEMS = [
  { href: "/", label: "Dashboard", icon: "📊" },
  { href: "/companies", label: "Companies", icon: "🏢" },
  { href: "/scans", label: "Scans", icon: "🔍" },
  { href: "/findings", label: "Findings", icon: "🐛" },
  { href: "/reports", label: "Reports", icon: "📄" },
  { href: "/traffic", label: "Proxy Traffic", icon: "🌐" },
  { href: "/notifications", label: "Notifications", icon: "🔔" },
  { href: "/education", label: "Learn", icon: "🎓" },
  { href: "/wordlists", label: "Wordlists", icon: "📝" },
  { href: "/settings", label: "Settings", icon: "⚙️" },
];

export function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="fixed left-0 top-0 z-40 flex h-screen w-56 flex-col border-r border-gray-200 bg-white">
      {/* Logo */}
      <div className="flex h-16 items-center gap-2 border-b border-gray-200 px-5">
        <span className="text-2xl">🧭</span>
        <span className="text-lg font-bold text-gray-900">Waymark</span>
        <span className="ml-auto rounded bg-indigo-100 px-1.5 py-0.5 text-[10px] font-semibold text-indigo-700">
          v0.1
        </span>
      </div>

      {/* Navigation */}
      <nav className="flex-1 space-y-1 px-3 py-4">
        {NAV_ITEMS.map((item) => {
          const isActive =
            item.href === "/"
              ? pathname === "/"
              : pathname.startsWith(item.href);

          return (
            <Link
              key={item.href}
              href={item.href}
              className={`flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors ${
                isActive
                  ? "bg-indigo-50 text-indigo-700"
                  : "text-gray-600 hover:bg-gray-50 hover:text-gray-900"
              }`}
            >
              <span className="text-base">{item.icon}</span>
              {item.label}
            </Link>
          );
        })}
      </nav>

      {/* Footer */}
      <div className="border-t border-gray-200 p-4">
        <div className="rounded-lg bg-gradient-to-r from-indigo-50 to-purple-50 p-3">
          <p className="text-xs font-medium text-indigo-700">🎓 Tip of the Day</p>
          <p className="mt-1 text-xs text-gray-600">
            Always check scope before scanning. Testing without authorization is illegal.
          </p>
        </div>
      </div>
    </aside>
  );
}
