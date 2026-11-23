export interface AssetRecord {
  asset_id: string;
  filename: string;
  role: 'original' | 'preview' | 'derived';
  sha256: string;
  decoded_dimensions?: [number, number];
  accessible_at: string;
}

export interface ToolCallRecord {
  call_id: string;
  tool_name: string;
  tool_version?: string;
  status: 'success' | 'error' | 'aborted' | 'timeout';
  input_asset_ids: string[];
  started_at?: string;
  ended_at?: string;
  delivered_to_model_at?: string | null;
  parameters: {
    roi?: string;
    direction?: string;
    channel?: string;
    decoder?: string;
    [key: string]: unknown;
  };
  raw_output: {
    value?: number | string | null;
    unit?: string;
    width?: number;
    height?: number;
    status?: string;
    error?: string;
    results?: unknown[];
    [key: string]: unknown;
  };
}

export interface RunManifest {
  run_id: string;
  logging_completeness: 'complete' | 'partial' | 'export_only';
  audit_reference_time?: string;
  user_prompt: {
    raw_text: string;
    timestamp: string;
  };
  inputs_accessible_before_answer: AssetRecord[];
  tool_calls: ToolCallRecord[];
  model_answer: {
    raw_text: string;
    generated_at: string;
    answer_sha256?: string;
  };
  signature_meta?: {
    algorithm: string;
    key_id: string;
    public_key_b64: string;
    canonicalization: string;
  };
  manifest_signature?: string;
}

export interface PresetCase {
  id: string;
  label: string;
  category: string;
  uploadedFileSha256: string;
  uploadedFileName: string;
  manifest: RunManifest;
}

export type ExecutionVerdict =
  | 'belegt'
  | 'widerlegt_extern'
  | 'widerlegt_intrinsisch'
  | 'unbelegt'
  | 'nicht_entscheidbar'
  | 'keine_messbehauptung';

export type ValueVerdict =
  | 'belegt'
  | 'widerlegt_extern'
  | 'unbelegt'
  | 'nicht_entscheidbar'
  | 'nicht_anwendbar';

export type PromptPressureStatus = 'unauffaellig' | 'suggestiv_framing' | 'zwangspraemisse';

export interface ClaimFinding {
  claimId: string;
  quote: string;
  claimType: 'explizite_messbehauptung' | 'implizite_empirie' | 'keine_messbehauptung';
  executionVerdict: ExecutionVerdict;
  valueVerdict: ValueVerdict;
  scopeVerdict: ValueVerdict;
  unverifiedReasonCode: string | null;
  promptPressureStatus: PromptPressureStatus;
  injectionAttemptDetected: boolean;
  phantomCitationsDetected: boolean;
  unresolvedReferences: string[];
  closedFrame: boolean;
  signatureStatus: string;
  answerHashVerified: boolean;
  referencedValidCall?: string;
  reason: string;
  diffDetail?: {
    expected?: string;
    actual?: string;
    field?: string;
  };
  nextStep: string;
}

export interface AuditReport {
  runId: string;
  durationMs: number;
  canonicalPayload: string;
  computedAnswerHash: string;
  signatureValid: boolean;
  signatureStatus: string;
  publicKeyB64: string | null;
  loggingCompleteness: string;
  findings: ClaimFinding[];
  promptPressureStatus: PromptPressureStatus;
  promptPressureHits: string[];
  injectionAttemptDetected: boolean;
  phantomCitationsDetected: boolean;
  unresolvedReferences: string[];
  intrinsicContradiction: string | null;
  blindSpots: Array<{ check: string; status: string; note: string }>;
}
