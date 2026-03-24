export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NEEDS_REVIEW';
export type OverallHealth = 'SECURE' | 'MOSTLY_SECURE' | 'AT_RISK' | 'CRITICAL_RISK' | 'SCAN_INCOMPLETE';
export type EvidenceStatus = 'CONFIRMED' | 'INFERRED';
export type ServiceType = 'ec2' | 's3' | 'iam' | 'vpc' | 'rds' | 'ebs' | 'ami' | 'elb';
export type LLMProvider = 'auto' | 'codex' | 'claude';
export type ErrorCategory = 'auth' | 'timeout' | 'unknown';
export type ScanStatus = 'running' | 'completed' | 'failed' | 'cancelled';

export interface Finding {
  id: string;
  resource_name: string;
  resource_id: string;
  resource_type: string;
  severity: Severity;
  issue_title: string;
  issue_description: string;
  impact: string;
  fix_command: string;
  fix_explanation: string;
  status: string;
  category: string;
  attack_path_ids: string[];
  aws_doc_reference: string;
}

export interface ChainStep {
  step: number;
  resource: string;
  resource_name: string;
  action: string;
  evidence_status: EvidenceStatus;
  evidence: string;
}

export interface AttackPath {
  id: string;
  title: string;
  severity: Severity;
  chain: ChainStep[];
  full_path_summary: string;
  impact: string;
  remediation_priority: { finding_id: string; action: string }[];
  related_finding_ids: string[];
}

export interface QuickWin {
  finding_id: string;
  action: string;
  effort: string;
  impact: string;
}

export interface AccountSummary {
  total_resources_scanned: number;
  total_findings: number;
  total_attack_paths: number;
  severity_breakdown: Record<Severity, number>;
  overall_health: OverallHealth;
}

export interface ServiceAnalysis {
  service: ServiceType;
  scan_timestamp: string;
  account_summary: AccountSummary;
  findings: Finding[];
  attack_paths: AttackPath[];
  narrative: string;
  quick_wins: QuickWin[];
}

// ── SSE event types ─────────────────────────────────────────────────────────

export interface ProgressEvent {
  type: 'progress';
  service: ServiceType;
  message: string;
}

export interface ResultEvent {
  type: 'result';
  service: ServiceType;
  analysis: ServiceAnalysis;
  scan_id?: string;
  session_id?: string;
}

export interface ErrorEvent {
  type: 'error';
  service: ServiceType;
  message: string;
  category?: ErrorCategory;
  scan_id?: string;
  session_id?: string;
}

export interface DoneEvent {
  type: 'done';
  session_id?: string;
}

export interface CancelledEvent {
  type: 'cancelled';
  service: ServiceType;
  message: string;
  scan_id?: string;
  session_id?: string;
}

export type SSEEvent = ProgressEvent | ResultEvent | ErrorEvent | DoneEvent | CancelledEvent;

// ── Request types ───────────────────────────────────────────────────────────

export interface AWSCredentials {
  accessKey: string;
  secretKey: string;
  sessionToken?: string | null;
}

export interface ScanRequest {
  services: ServiceType[];
  region: string;
  profile?: string | null;
  llm_provider: LLMProvider;
  session_id?: string | null;
}

export interface HealthResponse {
  status: string;
  supported_services: string[];
  available_llm_providers: string[];
  default_llm_provider: string | null;
}

// ── Scan history types ──────────────────────────────────────────────────────

export interface ScanSummary {
  id: string;
  session_id: string;
  service: ServiceType;
  region: string;
  status: ScanStatus;
  started_at: string;
  completed_at: string | null;
  total_findings: number;
  total_attack_paths: number;
  severity_critical: number;
  severity_high: number;
  severity_medium: number;
  severity_low: number;
  overall_health: OverallHealth | null;
  error_message: string | null;
}

export interface ScanDetail extends ScanSummary {
  analysis_json: ServiceAnalysis | null;
}
