export type Engagement = { id: string; name: string; owner_id: string; created_at: string };
export type Finding = {
  id: string;
  engagement_id: string;
  title: string;
  severity: string;
  status: string;
  source: string;
  description: string;
  created_at: string;
};
export type Target = {
  id: string;
  engagement_id: string;
  base_url: string;
  verified: boolean;
  verified_at: string | null;
  verification_path: string;
  verification_token?: string;
};
export type ScanSummary = {
  created: number;
  reopened: number;
  unchanged: number;
  requests: number;
  incomplete: boolean;
};
export type AuthzResult = { path: string; outcome: string; anonymous_access: boolean | null };
export type AuthzSummary = ScanSummary & { results: AuthzResult[] };
export type ReportMeta = {
  id: string;
  engagement_id: string;
  created_at: string;
  sha256: string;
  signature: string;
  key_id: string;
  algorithm: string;
  bytes: number;
};
export type VerifyResult = {
  valid: boolean;
  sha256_matches: boolean;
  signature_valid: boolean;
  signed_with_current_key: boolean;
};
