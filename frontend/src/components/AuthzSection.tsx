import { useEffect, useState, type FormEvent } from "react";
import { api, ApiError } from "../api";
import type { AuthzSummary, Target } from "../types";
import { btnCls, ErrorBox, inputCls, sectionCls } from "../ui";

type Props = { engagementId: string; canWrite: boolean; onChanged: () => void; refreshKey: number };

const DEFAULT_SPEC = JSON.stringify(
  { openapi: "3.0.0", paths: { "/api/orders/{orderId}": { get: {} } } },
  null,
  2,
);

export default function AuthzSection({ engagementId, canWrite, onChanged, refreshKey }: Props) {
  const [targets, setTargets] = useState<Target[]>([]);
  const [targetId, setTargetId] = useState("");
  const [specText, setSpecText] = useState(DEFAULT_SPEC);
  const [authA, setAuthA] = useState("");
  const [authB, setAuthB] = useState("");
  const [paramName, setParamName] = useState("orderId");
  const [paramValue, setParamValue] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [result, setResult] = useState<AuthzSummary | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api<Target[]>("GET", `/engagements/${engagementId}/targets`)
      .then((rows) => {
        const verified = rows.filter((t) => t.verified);
        setTargets(verified);
        if (verified.length > 0) setTargetId((current) => current || verified[0].id);
      })
      .catch(() => setTargets([]));
  }, [engagementId, refreshKey]);

  if (!canWrite) return null;

  async function onRun(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    setResult(null);
    let spec: unknown;
    try {
      spec = JSON.parse(specText);
    } catch {
      setError("The OpenAPI spec is not valid JSON.");
      return;
    }
    setBusy(true);
    try {
      const r = await api<AuthzSummary>("POST", `/targets/${targetId}/authz-scan`, {
        confirm_authorized: true,
        spec,
        auth_a: { authorization: authA },
        auth_b: { authorization: authB },
        object_ids: { [paramName]: paramValue },
      });
      setResult(r);
      // The credentials were only needed for this one run, so they are cleared right away.
      setAuthA("");
      setAuthB("");
      onChanged();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "The authorization scan failed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className={sectionCls}>
      <h2 className="text-lg font-semibold">Authorization scan</h2>
      <p className="text-xs text-slate-400">
        Replays GET endpoints as the object owner (A), as another user (B) and with no credentials.
        A finding is confirmed only when B or the anonymous request receives the same data as the owner, and a
        request for a non-existent object does not. Credentials are used once and are never stored.
      </p>
      <ErrorBox message={error} />
      {targets.length === 0 ? (
        <p className="text-sm text-slate-400">Verify a target first to enable this scan.</p>
      ) : (
        <form onSubmit={onRun} className="space-y-3">
          <select
            className={inputCls}
            value={targetId}
            onChange={(e) => setTargetId(e.target.value)}
          >
            {targets.map((t) => (
              <option key={t.id} value={t.id}>
                {t.base_url}
              </option>
            ))}
          </select>
          <textarea
            className={`${inputCls} font-mono`}
            rows={6}
            value={specText}
            onChange={(e) => setSpecText(e.target.value)}
            aria-label="OpenAPI spec (JSON)"
          />
          <div className="grid gap-2 sm:grid-cols-2">
            <input
              className={inputCls}
              type="password"
              autoComplete="off"
              placeholder="Identity A: Authorization value (owner)"
              value={authA}
              onChange={(e) => setAuthA(e.target.value)}
              required
            />
            <input
              className={inputCls}
              type="password"
              autoComplete="off"
              placeholder="Identity B: Authorization value (other user)"
              value={authB}
              onChange={(e) => setAuthB(e.target.value)}
              required
            />
            <input
              className={inputCls}
              placeholder="Path parameter name"
              value={paramName}
              onChange={(e) => setParamName(e.target.value)}
              required
            />
            <input
              className={inputCls}
              placeholder="Object ID owned by A"
              value={paramValue}
              onChange={(e) => setParamValue(e.target.value)}
              required
            />
          </div>
          <label className="flex items-start gap-2 text-sm text-slate-300">
            <input
              type="checkbox"
              checked={confirmed}
              onChange={(e) => setConfirmed(e.target.checked)}
              className="mt-1"
            />
            <span>I have written authorization to test this target.</span>
          </label>
          <button className={btnCls} type="submit" disabled={busy || !confirmed}>
            {busy ? "Running..." : "Run authorization scan"}
          </button>
        </form>
      )}
      {result && (
        <div className="space-y-2 rounded-md bg-slate-950 p-3 text-sm">
          <p className="text-slate-300">
            {result.created} new, {result.reopened} reopened, {result.unchanged} unchanged (
            {result.requests} requests{result.incomplete ? ", incomplete" : ""}).
          </p>
          <ul className="space-y-1">
            {result.results.map((r) => (
              <li key={r.path} className="font-mono text-xs text-slate-300">
                {r.path}: {r.outcome}
                {r.anonymous_access ? " (also readable without credentials)" : ""}
              </li>
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}

