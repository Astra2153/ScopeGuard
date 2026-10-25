import { useState, type FormEvent } from "react";
import { Navigate } from "react-router-dom";
import { ApiError } from "../api";
import { useAuth } from "../auth";
import { btnCls, ErrorBox, inputCls } from "../ui";

export default function LoginPage() {
  const { user, loading, login, register } = useAuth();
  const [mode, setMode] = useState<"login" | "register">("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [otp, setOtp] = useState("");
  const [needsOtp, setNeedsOtp] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  if (!loading && user) return <Navigate to="/" replace />;

  async function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      if (mode === "register") await register(email, password);
      else await login(email, password, needsOtp ? otp : undefined);
    } catch (err) {
      if (err instanceof ApiError && err.message === "MFA code required") {
        setNeedsOtp(true);
        setError("Enter the 6-digit code from your authenticator app, or a backup code.");
      } else {
        setError(err instanceof ApiError ? err.message : "Something went wrong.");
      }
    } finally {
      setBusy(false);
    }
  }

  function switchMode() {
    setMode(mode === "login" ? "register" : "login");
    setError(null);
    setNeedsOtp(false);
    setOtp("");
  }

  return (
    <div className="flex min-h-screen items-center justify-center px-4">
      <form
        onSubmit={onSubmit}
        className="w-full max-w-sm space-y-4 rounded-lg border border-slate-800 bg-slate-900 p-6"
      >
        <h1 className="text-xl font-semibold text-emerald-400">ScopeGuard</h1>
        <p className="text-sm text-slate-400">
          {mode === "login" ? "Sign in to your account" : "Create an account"}
        </p>
        <ErrorBox message={error} />
        <input
          className={inputCls}
          type="email"
          placeholder="Email"
          autoComplete="username"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
        />
        <input
          className={inputCls}
          type="password"
          placeholder={mode === "register" ? "Password (at least 12 characters)" : "Password"}
          autoComplete={mode === "register" ? "new-password" : "current-password"}
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          minLength={mode === "register" ? 12 : undefined}
          required
        />
        {needsOtp && mode === "login" && (
          <input
            className={inputCls}
            type="text"
            placeholder="Authenticator or backup code"
            autoComplete="one-time-code"
            value={otp}
            onChange={(e) => setOtp(e.target.value)}
            required
          />
        )}
        <button className={`${btnCls} w-full`} type="submit" disabled={busy}>
          {busy ? "Please wait..." : mode === "login" ? "Sign in" : "Register"}
        </button>
        <button
          type="button"
          onClick={switchMode}
          className="w-full text-center text-xs text-slate-400 hover:text-slate-200"
        >
          {mode === "login" ? "No account? Register" : "Have an account? Sign in"}
        </button>
      </form>
    </div>
  );
}
