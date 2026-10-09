export type Verdict = 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS'

export type Confidence = 'LOW' | 'MEDIUM' | 'HIGH'

export interface AnalysisReason {
  reason: string
  severity?: number
  category?: string
  observed_value?: string
}

export interface AnalysisResult {
  verdict: Verdict
  risk_score: number
  confidence: Confidence
  summary: string
  reasons: AnalysisReason[]
  recommended_action: string
  evidence_count?: number
  categories_detected?: string[]
  signal_families?: string[]
}
