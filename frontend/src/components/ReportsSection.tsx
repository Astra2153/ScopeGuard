import { useCallback, useEffect, useState } from "react";
import { api, ApiError } from "../api";
import type { ReportMeta, VerifyResult } from "../types";
import { btnCls, btnGhostCls, ErrorBox, sectionCls } from "../ui";

type Props = { engagementId: string; canWrite: boolean; refreshKey: number };

export default function ReportsSection({ engagementId, canWrite, refreshKey }: Props) {
  const [reports, setReports] = useState<ReportMeta[] | null>(null);
  const [viewed, setViewed] = useState<{ id: string; content: string } | null>(null);
  const [checks, setChecks] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      setReports(await api<ReportMeta[]>("GET", `/engagements/${engagementId}/reports`));
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not load reports.");
    }
  }, [engagementId]);

  useEffect(() => {
    void load();
  }, [load, refreshKey]);

  async function onCreate() {
    setError(null);
    setBusy(true);
    try {
      await api("POST", `/engagements/${engagementId}/reports`);
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not create the report.");
    } finally {
      setBusy(false);
    }
  }

  async function onView(id: string) {
    setError(null);
    try {
      const r = await api<ReportMeta & { content: string }>("GET", `/reports/${id}`);
      setViewed({ id, content: r.content });
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not load the report.");
    }
  }

  async function onVerify(id: string) {
    setError(null);
    try {
      const r = await api<VerifyResult>("GET", `/reports/${id}/verify`);
      const text = r.valid
        ? "Signature valid: the stored report is unchanged."
        : "INVALID: the stored report does not match its signature.";
      setChecks((c) => ({ ...c, [id]: text }));
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not verify the report.");
    }
  }

  return (
    <section className={sectionCls}>
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">Signed reports</h2>
        {canWrite && (
          <button className={btnCls} onClick={() => void onCreate()} disabled={busy}>
            {busy ? "Creating..." : "Create report"}
          </button>
        )}
      </div>
      <p className="text-xs text-slate-400">
        Each report is an immutable snapshot signed with Ed25519. Downloaded copies can be verified offline
        with tools/verify_report.py.
      </p>
      <ErrorBox message={error} />
      {reports === null ? (
        <p className="text-slate-400">Loading...</p>
      ) : reports.length === 0 ? (
        <p className="text-slate-400">No reports yet.</p>
      ) : (
        <ul className="divide-y divide-slate-800">
          {reports.map((r) => (
            <li key={r.id} className="space-y-2 py-3">
              <div className="flex flex-wrap items-center gap-2 text-sm">
                <span>{new Date(r.created_at).toLocaleString()}</span>
                <span className="text-xs text-slate-400">
                  key {r.key_id} - sha256 {r.sha256.slice(0, 12)}
                </span>
                <div className="ml-auto flex gap-2">
                  <button className={btnGhostCls} onClick={() => void onView(r.id)}>
                    View
                  </button>
                  <button className={btnGhostCls} onClick={() => void onVerify(r.id)}>
                    Verify
                  </button>
                  <a className={btnGhostCls} href={`/api/reports/${r.id}/download`}>
                    Download
                  </a>
                </div>
              </div>
              {checks[r.id] && <p className="text-xs text-slate-300">{checks[r.id]}</p>}
            </li>
          ))}
        </ul>
      )}
      {viewed && (
        <pre className="max-h-96 overflow-auto whitespace-pre-wrap rounded-md bg-slate-950 p-3 text-xs text-slate-300">
          {viewed.content}
        </pre>
      )}
    </section>
  );
}
