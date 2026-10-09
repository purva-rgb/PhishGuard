import { useRef, useState } from 'react'
import { AnalysisApiError, analyzeEmail } from './api/emailApi'
import AnalysisResult from './components/AnalysisResult'
import EmailInput from './components/EmailInput'
import Header from './components/Header'
import WireframeBackground from './components/WireframeBackground'
import type { AnalysisResult as AnalysisResultData } from './types/analysis'

const EMPTY_INPUT_MESSAGE = 'Please paste an email or URL before analyzing.'

export default function App() {
  const [emailText, setEmailText] = useState('')
  const [result, setResult] = useState<AnalysisResultData | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  // Incremented on every analyze/clear so a stale (cleared) request cannot overwrite the UI.
  const requestId = useRef(0)

  const handleChange = (value: string) => {
    setEmailText(value)
    if (error) setError(null)
  }

  const handleClear = () => {
    requestId.current += 1
    setEmailText('')
    setResult(null)
    setError(null)
    setLoading(false)
  }

  const handleAnalyze = async () => {
    if (!emailText.trim()) {
      setResult(null)
      setError(EMPTY_INPUT_MESSAGE)
      return
    }

    const current = ++requestId.current
    setError(null)
    setResult(null)
    setLoading(true)
    try {
      const analysis = await analyzeEmail(emailText)
      if (current === requestId.current) setResult(analysis)
    } catch (caught) {
      if (current !== requestId.current) return
      setResult(null)
      setError(
        caught instanceof AnalysisApiError
          ? caught.message
          : 'The email and URL could not be analyzed. Please try again.',
      )
    } finally {
      if (current === requestId.current) setLoading(false)
    }
  }

  return (
    <div className="page">
      <WireframeBackground />
      <div className="app">
        <Header />
        <main className="layout">
          <EmailInput
            value={emailText}
            error={error}
            loading={loading}
            onChange={handleChange}
            onAnalyze={handleAnalyze}
            onClear={handleClear}
          />
          <AnalysisResult result={result} loading={loading} />
        </main>
      </div>
    </div>
  )
}
