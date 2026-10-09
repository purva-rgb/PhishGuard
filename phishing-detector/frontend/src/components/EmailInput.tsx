import { EnvelopeIcon, LinkIcon, ShieldIcon } from './icons'

interface EmailInputProps {
  value: string
  error: string | null
  loading: boolean
  onChange: (value: string) => void
  onAnalyze: () => void
  onClear: () => void
}

export default function EmailInput({
  value,
  error,
  loading,
  onChange,
  onAnalyze,
  onClear,
}: EmailInputProps) {
  const describedBy = error ? 'email-error email-count' : 'email-count'

  return (
    <section className="card" aria-labelledby="input-title">
      <h2 id="input-title" className="card-title">
        Email &amp; URL Analysis
      </h2>

      <label className="field-label" htmlFor="email-text">
        Email or URL content
      </label>
      <textarea
        id="email-text"
        className="email-textarea"
        placeholder="Paste email or URL content here..."
        value={value}
        onChange={(event) => onChange(event.target.value)}
        aria-invalid={error ? true : undefined}
        aria-describedby={describedBy}
        spellCheck={false}
      />

      <div className="input-meta">
        <p id="email-count" className="char-count">
          {value.length.toLocaleString()} characters
        </p>
        {error && (
          <p id="email-error" className="field-error" role="alert">
            {error}
          </p>
        )}
      </div>

      <ul className="signal-row" aria-label="Signals analyzed">
        <li className="signal-chip">
          <EnvelopeIcon size={16} />
          Headers
        </li>
        <li className="signal-chip">
          <LinkIcon size={16} />
          URLs
        </li>
        <li className="signal-chip">
          <ShieldIcon size={16} />
          Content
        </li>
      </ul>

      <div className="button-row">
        <button type="button" className="btn btn-secondary" onClick={onClear}>
          Clear
        </button>
        <button
          type="button"
          className="btn btn-primary"
          onClick={onAnalyze}
          disabled={loading}
          aria-busy={loading}
        >
          {loading ? (
            <>
              <span className="spinner" aria-hidden="true" />
              Analyzing...
            </>
          ) : (
            'Analyze Email & URL'
          )}
        </button>
      </div>
    </section>
  )
}
