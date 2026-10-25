import { useCallback, useEffect, useState, type FormEvent } from "react";
import { api, ApiError } from "../api";
import type { Finding } from "../types";
import { btnCls, btnDangerCls, ErrorBox, inputCls, sectionCls, severityCls } from "../ui";

const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const STATUSES = ["open", "not_fixed", "partially_fixed", "fixed"];

type Props = { engagementId: string; canWrite: boolean; refreshKey: number };

export default function FindingsSection({ engagementId, canWrite, refreshKey }: Props) {
  const [items, setItems] = useState<Finding[] | null>(null);
  const [title, setTitle] = useState("");
  const [severity, setSeverity] = useState("low");
  const [description, setDescription] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const rows = await api<Finding[]>("GET", `/engagements/${engagementId}/findings`);
      rows.sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity));
      setItems(rows);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not load findings.");
    }
  }, [engagementId]);

  useEffect(() => {
    void load();
  }, [load, refreshKey]);

  async function onAdd(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      await api("POST", `/engagements/${engagementId}/findings`, { title, severity, description });
      setTitle("");
      setDescription("");
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not add the finding.");
    } finally {
      setBusy(false);
    }
  }

  async function setStatus(id: string, status: string) {
    setError(null);
    try {
      await api("PATCH", `/findings/${id}`, { status });
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not update the finding.");
    }
  }

  async function remove(id: string) {
    if (!window.confirm("Delete this finding?")) return;
    setError(null);
    try {
      await api("DELETE", `/findings/${id}`);
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not delete the finding.");
    }
  }

  return (
    <section className={sectionCls}>
      <h2 className="text-lg font-semibold">Findings</h2>
      <ErrorBox message={error} />
      {canWrite && (
        <form onSubmit={onAdd} className="space-y-2">
          <div className="flex gap-2">
            <input
              className={inputCls}
              placeholder="Finding title"
              value={title}
              maxLength={300}
              onChange={(e) => setTitle(e.target.value)}
              required
            />
            <select
              className={`${inputCls} w-36`}
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
            >
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </div>
          <textarea
            className={inputCls}
            rows={2}
            placeholder="Description (optional)"
            value={description}
            maxLength={10000}
            onChange={(e) => setDescription(e.target.value)}
          />
          <button className={btnCls} type="submit" disabled={busy}>
            Add finding
          </button>
        </form>
      )}
      {items === null ? (
        <p className="text-slate-400">Loading...</p>
      ) : items.length === 0 ? (
        <p className="text-slate-400">No findings yet.</p>
      ) : (
        <ul className="divide-y divide-slate-800">
          {items.map((f) => (
            <li key={f.id} className="space-y-2 py-3">
              <div className="flex flex-wrap items-center gap-2">
                <span className={`rounded px-2 py-0.5 text-xs ${severityCls(f.severity)}`}>
                  {f.severity}
                </span>
                <span className="font-medium">{f.title}</span>
                <span className="rounded bg-slate-800 px-2 py-0.5 text-xs text-slate-400">
                  {f.source}
                </span>
                <div className="ml-auto flex items-center gap-2">
                  {canWrite ? (
                    <select
                      className="rounded-md border border-slate-700 bg-slate-900 px-2 py-1 text-xs"
                      value={f.status}
                      onChange={(e) => void setStatus(f.id, e.target.value)}
                    >
                      {STATUSES.map((s) => (
                        <option key={s} value={s}>
                          {s}
                        </option>
                      ))}
                    </select>
                  ) : (
                    <span className="text-xs text-slate-300">{f.status}</span>
                  )}
                  {canWrite && (
                    <button className={btnDangerCls} onClick={() => void remove(f.id)}>
                      Delete
                    </button>
                  )}
                </div>
              </div>
              {f.description && (
                <p className="whitespace-pre-wrap text-sm text-slate-400">{f.description}</p>
              )}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
