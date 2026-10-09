import { DEMO_EMAIL } from '../data/demoEmail'
import type { AnalysisResult } from '../types/analysis'

// UI-development mock only. It does NOT implement any detection logic; Part 9 replaces it with
// the real backend call.

const MOCK_DELAY_MS = 400

const normalize = (text: string): string => text.replace(/\r\n/g, '\n').trim()

const MOCK_MALICIOUS_RESULT: AnalysisResult = {
  verdict: 'MALICIOUS',
  risk_score: 0.95,
  confidence: 'HIGH',
  summary: 'Multiple strong phishing indicators were detected.',
  reasons: [
    {
      reason: 'A link appears to use a lookalike or impersonation domain.',
      severity: 0.85,
      category: 'BRAND',
      observed_value: 'paypa1-login.xyz',
    },
    {
      reason: 'The Reply-To address uses a different domain from the sender.',
      severity: 0.8,
      category: 'HEADER',
      observed_value: 'security@paypa1-login.xyz \u2192 verify@randommail.xyz',
    },
    {
      reason: 'The email asks the recipient to verify an account or identity.',
      severity: 0.5,
      category: 'CONTENT',
    },
    {
      reason: 'The email uses urgency or threat language to pressure the recipient.',
      severity: 0.5,
      category: 'CONTENT',
    },
  ],
  recommended_action:
    'Do not click links or provide credentials. Verify the sender through an independent trusted channel and report the email.',
  evidence_count: 6,
  categories_detected: ['BRAND', 'CONTENT', 'DOMAIN', 'HEADER', 'URL'],
  signal_families: ['CONTENT', 'HEADER', 'URL'],
}

const MOCK_SUSPICIOUS_RESULT: AnalysisResult = {
  verdict: 'SUSPICIOUS',
  risk_score: 0.45,
  confidence: 'MEDIUM',
  summary: 'Some phishing indicators were detected, but the evidence is not conclusive.',
  reasons: [
    {
      reason: 'Simulated result: real email analysis is not connected yet.',
      severity: 0.4,
      category: 'DEMO',
    },
  ],
  recommended_action:
    'Do not click links or provide sensitive information until the sender and request are independently verified.',
  evidence_count: 1,
  categories_detected: ['DEMO'],
  signal_families: [],
}

export function analyzeMockEmail(emailText: string): Promise<AnalysisResult> {
  const result = normalize(emailText) === normalize(DEMO_EMAIL) ? MOCK_MALICIOUS_RESULT : MOCK_SUSPICIOUS_RESULT
  return new Promise((resolve) => {
    window.setTimeout(() => resolve(structuredClone(result)), MOCK_DELAY_MS)
  })
}
