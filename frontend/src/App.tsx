import { Navigate, Route, Routes } from "react-router-dom";
import { useAuth } from "./auth";
import Layout from "./Layout";
import EngagementDetailPage from "./pages/EngagementDetailPage";
import EngagementsPage from "./pages/EngagementsPage";
import LoginPage from "./pages/LoginPage";

function Protected() {
  const { user, loading } = useAuth();
  if (loading) return <p className="p-6 text-slate-400">Loading...</p>;
  if (!user) return <Navigate to="/login" replace />;
  return <Layout />;
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route element={<Protected />}>
        <Route path="/" element={<EngagementsPage />} />
        <Route path="/engagements/:id" element={<EngagementDetailPage />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
