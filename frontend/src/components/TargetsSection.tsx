import { useCallback, useEffect, useState, type FormEvent } from "react";
import { api, ApiError } from "../api";
import type { ScanSummary, Target } from "../types";
import { btnCls, btnDangerCls, btnGhostCls, ErrorBox, inputCls, sectionCls } from "../ui";

type Props = { engagementId: string; canWrite: boolean; onChanged: () => void };

export default function TargetsSection({ engagementId, canWrite, onChanged }: Props) {
  const [targets, setTargets] = useState<Target[] | null>(null);
  const [url, setUrl] = useState("");
  const [notes, setNotes] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      setTargets(await api<Target[]>("GET", `/engagements/${engagementId}/targets`));
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not load targets.");
    }
  }, [engagementId]);

  useEffect(() => {
    void load();
  }, [load]);

  function note(id: string, text: string) {
    setNotes((n) => ({ ...n, [id]: text }));
  }

  async function onAdd(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      await api("POST", `/engagements/${engagementId}/targets`, { base_url: url });
      setUrl("");
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not add the target.");
    } finally {
      setBusy(false);
    }
  }

  async function onVerify(id: string) {
    setError(null);
    try {
      await api("POST", `/targets/${id}/verify`);
      note(id, "Ownership verified.");
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Verification failed.");
    }
  }

  async function onScan(id: string) {
    setError(null);
    note(id, "Scanning...");
    try {
      const r = await api<ScanSummary>("POST", `/targets/${id}/scan`);
      note(
        id,
        `Scan finished: ${r.created} new, ${r.reopened} reopened, ${r.unchanged} unchanged (${r.requests} requests).`,
      );
      onChanged();
    } catch (err) {
      note(id, "");
      setError(err instanceof ApiError ? err.message : "The scan failed.");
    }
  }

  async function onDelete(id: string) {
    if (!window.confirm("Remove this target?")) return;
    setError(null);
    try {
      await api("DELETE", `/targets/${id}`);
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not remove the target.");
    }
  }

  return (
    <section className={sectionCls}>
      <h2 className="text-lg font-semibold">Targets</h2>
      <p className="text-xs text-slate-400">
        Only scan systems you own or have written permission to test. A target must prove ownership
        before anything is sent to it.
      </p>
      <ErrorBox message={error} />
      {canWrite && (
        <form onSubmit={onAdd} className="flex gap-2">
          <input
            className={inputCls}
            placeholder="https://api.example.com"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            required
          />
          <button className={`${btnCls} whitespace-nowrap`} type="submit" disabled={busy}>
            Add target
          </button>
        </form>
      )}
      {targets === null ? (
        <p className="text-slate-400">Loading...</p>
      ) : targets.length === 0 ? (
        <p className="text-slate-400">No targets yet.</p>
      ) : (
        <ul className="divide-y divide-slate-800">
          {targets.map((t) => (
            <li key={t.id} className="space-y-2 py-3">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-medium">{t.base_url}</span>
                <span
                  className={`rounded px-2 py-0.5 text-xs ${
                    t.verified ? "bg-emerald-900 text-emerald-100" : "bg-yellow-900 text-yellow-100"
                  }`}
                >
                  {t.verified ? "ownership verified" : "not verified"}
                </span>
                {canWrite && (
                  <div className="ml-auto flex gap-2">
                    {!t.verified && (
                      <button className={btnGhostCls} onClick={() => void onVerify(t.id)}>
                        Verify
                      </button>
                    )}
                    {t.verified && (
                      <button className={btnGhostCls} onClick={() => void onScan(t.id)}>
                        Scan
                      </button>
                    )}
                    <button className={btnDangerCls} onClick={() => void onDelete(t.id)}>
                      Remove
                    </button>
                  </div>
                )}
              </div>
              {!t.verified && t.verification_token && (
                <div className="rounded-md bg-slate-950 p-3 text-xs text-slate-300">
                  <p>
                    To prove ownership, publish this token as the whole content of{" "}
                    <code>{t.verification_path}</code> on the target, then click Verify:
                  </p>
                  <code className="mt-1 block break-all text-emerald-300">
                    {t.verification_token}
                  </code>
                </div>
              )}
              {notes[t.id] && <p className="text-xs text-slate-400">{notes[t.id]}</p>}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
