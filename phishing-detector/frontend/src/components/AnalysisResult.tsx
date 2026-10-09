import type { AnalysisResult as AnalysisResultData } from '../types/analysis'
import { ShieldIcon } from './icons'
import ReasonList from './ReasonList'
import RecommendedAction from './RecommendedAction'
import TechnicalDetails from './TechnicalDetails'
import VerdictBadge from './VerdictBadge'

interface AnalysisResultProps {
  result: AnalysisResultData | null
  loading: boolean
}

function ResultBody({ result }: { result: AnalysisResultData }) {
  const percent = Math.round(result.risk_score * 100)

  return (
    <div className="result-body">
      <div className="result-top">
        <VerdictBadge verdict={result.verdict} />
        <div className="score-block">
          <p className="metric-label">Risk Score</p>
          <p className="score-value">
            {percent} <span className="score-out-of">/ 100</span>
          </p>
        </div>
        <div className="confidence-block">
          <p className="metric-label">Confidence</p>
          <p className="confidence-value">{result.confidence}</p>
        </div>
      </div>

      <div
        className={`score-bar verdict-bar-${result.verdict.toLowerCase()}`}
        role="meter"
        aria-label="Risk score"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={percent}
        aria-valuetext={`${percent} percent`}
      >
        <div className="score-bar-fill" style={{ width: `${percent}%` }} />
      </div>

      <p className="summary">{result.summary}</p>

      <ReasonList reasons={result.reasons} />
      <RecommendedAction action={result.recommended_action} />
      <TechnicalDetails result={result} />
    </div>
  )
}

export default function AnalysisResult({ result, loading }: AnalysisResultProps) {
  return (
    <section className="card result-card" aria-labelledby="result-title" aria-live="polite">
      <h2 id="result-title" className="card-title">
        Analysis
      </h2>

      {loading ? (
        <div className="empty-state">
          <span className="spinner spinner-large" aria-hidden="true" />
          <p className="empty-title">Analyzing...</p>
        </div>
      ) : result ? (
        <ResultBody result={result} />
      ) : (
        <div className="empty-state">
          <span className="empty-icon">
            <ShieldIcon size={28} />
          </span>
        </div>
      )}
    </section>
  )
}
