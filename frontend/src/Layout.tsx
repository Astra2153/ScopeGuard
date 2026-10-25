import { Outlet } from "react-router-dom";
import { useAuth } from "./auth";
import { btnGhostCls } from "./ui";

export default function Layout() {
  const { user, logout } = useAuth();
  return (
    <div className="min-h-screen">
      <header className="border-b border-slate-800 bg-slate-900">
        <div className="mx-auto flex max-w-5xl items-center justify-between px-4 py-3">
          <span className="text-lg font-semibold text-emerald-400">ScopeGuard</span>
          <div className="flex items-center gap-3 text-sm text-slate-300">
            <span>{user?.email}</span>
            <span className="rounded bg-slate-800 px-2 py-0.5 text-xs">{user?.role}</span>
            <span className="text-xs">{user?.mfa_enabled ? "MFA on" : "MFA off"}</span>
            <button className={btnGhostCls} onClick={() => void logout()}>
              Log out
            </button>
          </div>
        </div>
      </header>
      <main className="mx-auto max-w-5xl px-4 py-6">
        <Outlet />
      </main>
    </div>
  );
}
