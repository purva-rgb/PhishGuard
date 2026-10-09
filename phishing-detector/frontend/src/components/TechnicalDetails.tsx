import type { AnalysisResult } from '../types/analysis'

export default function TechnicalDetails({ result }: { result: AnalysisResult }) {
  const rows: [string, string][] = [
    ['Risk score', result.risk_score.toFixed(2)],
    ['Confidence', result.confidence],
    ['Evidence count', result.evidence_count !== undefined ? String(result.evidence_count) : 'n/a'],
    ['Signal categories', result.categories_detected?.join(', ') || 'none'],
    ['Signal families', result.signal_families?.join(', ') || 'none'],
  ]

  return (
    <details className="details">
      <summary>Technical Details</summary>
      <dl className="details-grid">
        {rows.map(([label, value]) => (
          <div key={label} className="details-row">
            <dt>{label}</dt>
            <dd>{value}</dd>
          </div>
        ))}
      </dl>
    </details>
  )
}
