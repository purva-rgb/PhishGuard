import type { AnalysisReason, AnalysisResult, Confidence, Verdict } from '../types/analysis'

const DEFAULT_API_BASE_URL = 'http://127.0.0.1:8000'

const VERDICTS: ReadonlySet<string> = new Set(['SAFE', 'SUSPICIOUS', 'MALICIOUS'])
const CONFIDENCES: ReadonlySet<string> = new Set(['LOW', 'MEDIUM', 'HIGH'])

export const UNREACHABLE_MESSAGE =
  'Unable to reach the phishing analysis server. Make sure the backend is running.'
export const INVALID_INPUT_MESSAGE = 'Please enter a valid email or URL to analyze.'
export const GENERIC_FAILURE_MESSAGE = 'The email and URL could not be analyzed. Please try again.'
export const UNEXPECTED_RESPONSE_MESSAGE = 'The analysis returned an unexpected response.'

export class AnalysisApiError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'AnalysisApiError'
  }
}

function apiBaseUrl(): string {
  const configured = import.meta.env.VITE_API_BASE_URL
  if (typeof configured === 'string' && configured.trim()) {
    return configured.trim().replace(/\/+$/, '')
  }
  return DEFAULT_API_BASE_URL
}

function asNumber(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined
}

function asString(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined
}

function asStringList(value: unknown): string[] | undefined {
  if (!Array.isArray(value) || value.some((item) => typeof item !== 'string')) return undefined
  return value
}

function mapReason(value: unknown): AnalysisReason | null {
  if (!value || typeof value !== 'object') return null
  const raw = value as Record<string, unknown>
  const reason = asString(raw.reason)
  if (!reason) return null
  const mapped: AnalysisReason = { reason }
  const severity = asNumber(raw.severity)
  if (severity !== undefined) mapped.severity = severity
  const category = asString(raw.category)
  if (category) mapped.category = category
  const observed = asString(raw.observed_value)
  if (observed) mapped.observed_value = observed
  return mapped
}

function mapResponse(payload: unknown): AnalysisResult {
  if (!payload || typeof payload !== 'object') {
    throw new AnalysisApiError(UNEXPECTED_RESPONSE_MESSAGE)
  }
  const raw = payload as Record<string, unknown>
  const verdict = asString(raw.verdict)
  const confidence = asString(raw.confidence)
  const riskScore = asNumber(raw.risk_score)
  const summary = asString(raw.summary)
  const recommended = asString(raw.recommended_action)
  if (
    !verdict ||
    !VERDICTS.has(verdict) ||
    !confidence ||
    !CONFIDENCES.has(confidence) ||
    riskScore === undefined ||
    summary === undefined ||
    recommended === undefined ||
    !Array.isArray(raw.reasons)
  ) {
    throw new AnalysisApiError(UNEXPECTED_RESPONSE_MESSAGE)
  }

  const reasons = raw.reasons.map(mapReason)
  if (reasons.some((item) => item === null)) {
    throw new AnalysisApiError(UNEXPECTED_RESPONSE_MESSAGE)
  }

  const result: AnalysisResult = {
    verdict: verdict as Verdict,
    risk_score: riskScore,
    confidence: confidence as Confidence,
    summary,
    reasons: reasons as AnalysisReason[],
    recommended_action: recommended,
  }
  const evidenceCount = asNumber(raw.evidence_count)
  if (evidenceCount !== undefined) result.evidence_count = evidenceCount
  const categories = asStringList(raw.categories_detected)
  if (categories) result.categories_detected = categories
  const families = asStringList(raw.signal_families)
  if (families) result.signal_families = families
  return result
}

export async function analyzeEmail(emailText: string): Promise<AnalysisResult> {
  let response: Response
  try {
    response = await fetch(`${apiBaseUrl()}/api/analyze/email`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email_text: emailText }),
    })
  } catch {
    throw new AnalysisApiError(UNREACHABLE_MESSAGE)
  }

  if (response.status === 422) {
    throw new AnalysisApiError(INVALID_INPUT_MESSAGE)
  }
  if (!response.ok) {
    throw new AnalysisApiError(GENERIC_FAILURE_MESSAGE)
  }

  let payload: unknown
  try {
    payload = await response.json()
  } catch {
    throw new AnalysisApiError(UNEXPECTED_RESPONSE_MESSAGE)
  }
  return mapResponse(payload)
}
