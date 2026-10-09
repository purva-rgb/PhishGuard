import type { AnalysisReason } from '../types/analysis'

const MAX_REASONS = 5
const MAX_OBSERVED_LENGTH = 120

function severityLevel(severity?: number): { text: string; className: string } {
  if (severity === undefined) return { text: 'Signal', className: 'sev-low' }
  if (severity >= 0.7) return { text: 'High', className: 'sev-high' }
  if (severity >= 0.4) return { text: 'Medium', className: 'sev-medium' }
  return { text: 'Low', className: 'sev-low' }
}

function shorten(value: string): string {
  return value.length > MAX_OBSERVED_LENGTH ? `${value.slice(0, MAX_OBSERVED_LENGTH - 3)}...` : value
}

export default function ReasonList({ reasons }: { reasons: AnalysisReason[] }) {
  const shown = reasons.slice(0, MAX_REASONS)

  return (
    <section className="panel" aria-labelledby="reasons-title">
      <h3 id="reasons-title" className="panel-title">
        Why this email and URL were flagged
      </h3>
      {shown.length === 0 ? (
        <p className="muted">No specific indicators were reported.</p>
      ) : (
        <ul className="reason-list">
          {shown.map((item, index) => {
            const level = severityLevel(item.severity)
            return (
              <li key={`${index}-${item.reason}`} className="reason">
                <span className={`reason-dot ${level.className}`} aria-hidden="true" />
                <div className="reason-body">
                  <p className="reason-text">{item.reason}</p>
                  {item.observed_value && (
                    <p className="reason-observed">{shorten(item.observed_value)}</p>
                  )}
                </div>
                <span className={`reason-severity ${level.className}`}>{level.text}</span>
              </li>
            )
          })}
        </ul>
      )}
    </section>
  )
}
