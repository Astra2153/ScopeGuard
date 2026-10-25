import { useEffect, useState } from "react";
import { Link, Navigate, useParams } from "react-router-dom";
import { api, ApiError } from "../api";
import { useAuth } from "../auth";
import AuthzSection from "../components/AuthzSection";
import FindingsSection from "../components/FindingsSection";
import ReportsSection from "../components/ReportsSection";
import TargetsSection from "../components/TargetsSection";
import type { Engagement } from "../types";
import { ErrorBox } from "../ui";

export default function EngagementDetailPage() {
  const { id } = useParams<{ id: string }>();
  const { user } = useAuth();
  const canWrite = user?.role === "tester" || user?.role === "admin";
  const [engagement, setEngagement] = useState<Engagement | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);

  useEffect(() => {
    if (!id) return;
    api<Engagement>("GET", `/engagements/${id}`)
      .then(setEngagement)
      .catch((err) => setError(err instanceof ApiError ? err.message : "Could not load the engagement."));
  }, [id]);

  if (!id) return <Navigate to="/" replace />;

  const changed = () => setRefreshKey((k) => k + 1);

  return (
    <div className="space-y-6">
      <Link to="/" className="text-sm text-slate-400 hover:text-slate-200">
        Back to engagements
      </Link>
      <ErrorBox message={error} />
      {engagement && (
        <>
          <h1 className="text-xl font-semibold">{engagement.name}</h1>
          <TargetsSection engagementId={id} canWrite={canWrite} onChanged={changed} />
          <AuthzSection engagementId={id} canWrite={canWrite} onChanged={changed} />
          <FindingsSection engagementId={id} canWrite={canWrite} refreshKey={refreshKey} />
          <ReportsSection engagementId={id} canWrite={canWrite} refreshKey={refreshKey} />
        </>
      )}
    </div>
  );
}
