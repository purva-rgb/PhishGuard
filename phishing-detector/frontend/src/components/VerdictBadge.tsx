import type { Verdict } from '../types/analysis'
import { BlockIcon, CheckIcon, WarningIcon } from './icons'

const VERDICT_DISPLAY: Record<Verdict, { label: string; className: string }> = {
  SAFE: { label: 'Low Risk', className: 'verdict-safe' },
  SUSPICIOUS: { label: 'Medium Risk', className: 'verdict-suspicious' },
  MALICIOUS: { label: 'High Risk', className: 'verdict-malicious' },
}

function VerdictIcon({ verdict }: { verdict: Verdict }) {
  if (verdict === 'SAFE') return <CheckIcon size={28} />
  if (verdict === 'SUSPICIOUS') return <WarningIcon size={28} />
  return <BlockIcon size={28} />
}

export default function VerdictBadge({ verdict }: { verdict: Verdict }) {
  const { label, className } = VERDICT_DISPLAY[verdict]
  return (
    <div className={`verdict ${className}`}>
      <VerdictIcon verdict={verdict} />
      <div>
        <p className="verdict-name">{verdict}</p>
        <p className="verdict-label">{label}</p>
      </div>
    </div>
  )
}
