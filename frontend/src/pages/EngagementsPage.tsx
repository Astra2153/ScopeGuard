import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { api, ApiError } from "../api";
import { useAuth } from "../auth";
import { btnCls, btnDangerCls, ErrorBox, inputCls } from "../ui";

type Engagement = { id: string; name: string; owner_id: string; created_at: string };

export default function EngagementsPage() {
  const { user } = useAuth();
  const canWrite = user?.role === "tester" || user?.role === "admin";
  const [items, setItems] = useState<Engagement[] | null>(null);
  const [name, setName] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      setItems(await api<Engagement[]>("GET", "/engagements"));
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not load engagements.");
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function onCreate(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      await api("POST", "/engagements", { name });
      setName("");
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not create the engagement.");
    } finally {
      setBusy(false);
    }
  }

  async function onDelete(id: string) {
    if (!window.confirm("Delete this engagement and everything in it?")) return;
    setError(null);
    try {
      await api("DELETE", `/engagements/${id}`);
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not delete the engagement.");
    }
  }

  return (
    <div className="space-y-6">
      <h1 className="text-xl font-semibold">Engagements</h1>
      <ErrorBox message={error} />

      {canWrite && (
        <form onSubmit={onCreate} className="flex gap-2">
          <input
            className={inputCls}
            placeholder="New engagement name"
            value={name}
            maxLength={200}
            onChange={(e) => setName(e.target.value)}
            required
          />
          <button className={`${btnCls} whitespace-nowrap`} type="submit" disabled={busy}>
            Create
          </button>
        </form>
      )}

      {items === null ? (
        <p className="text-slate-400">Loading...</p>
      ) : items.length === 0 ? (
        <p className="text-slate-400">No engagements yet.</p>
      ) : (
        <ul className="divide-y divide-slate-800 rounded-lg border border-slate-800 bg-slate-900">
          {items.map((eng) => (
            <li key={eng.id} className="flex items-center justify-between px-4 py-3">
              <div>
                <Link to={`/engagements/${eng.id}`} className="font-medium text-emerald-400 hover:underline">{eng.name}</Link>
                <p className="text-xs text-slate-400">
                  Created {new Date(eng.created_at).toLocaleString()}
                </p>
              </div>
              {canWrite && (
                <button className={btnDangerCls} onClick={() => void onDelete(eng.id)}>
                  Delete
                </button>
              )}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

