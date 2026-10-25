export const inputCls =
  "w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 placeholder-slate-500 focus:border-emerald-500 focus:outline-none";
export const btnCls =
  "rounded-md bg-emerald-600 px-4 py-2 text-sm font-medium text-white hover:bg-emerald-500 disabled:opacity-50";
export const btnGhostCls =
  "rounded-md border border-slate-700 px-3 py-1.5 text-xs text-slate-300 hover:bg-slate-800";
export const btnDangerCls =
  "rounded-md border border-red-800 px-3 py-1.5 text-xs text-red-300 hover:bg-red-950";

export function ErrorBox({ message }: { message: string | null }) {
  if (!message) return null;
  return (
    <div
      role="alert"
      className="rounded-md border border-red-800 bg-red-950/50 px-3 py-2 text-sm text-red-200"
    >
      {message}
    </div>
  );
}
