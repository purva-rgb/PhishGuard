import { ShieldIcon } from './icons'

export default function Header() {
  return (
    <header className="header">
      <div className="brand">
        <span className="brand-mark">
          <ShieldIcon size={26} />
        </span>
        <div>
          <h1 className="brand-name">PhishGuard</h1>
          <p className="brand-sub">Email &amp; URL Phishing Detector</p>
        </div>
      </div>
    </header>
  )
}
