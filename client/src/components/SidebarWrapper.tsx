"use client";

import { Sidebar } from "./Sidebar";

/**
 * Client-side wrapper for the Sidebar component.
 * Needed because layout.tsx is a Server Component but
 * Sidebar uses usePathname() which requires "use client".
 */
export function SidebarWrapper() {
  return <Sidebar />;
}
