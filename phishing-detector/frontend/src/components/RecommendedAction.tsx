export default function RecommendedAction({ action }: { action: string }) {
  return (
    <section className="panel action-panel" aria-labelledby="action-title">
      <h3 id="action-title" className="panel-title">
        Recommended Action
      </h3>
      <p className="action-text">{action}</p>
    </section>
  )
}
