export interface ArchitectureDetail {
  id: string
  title: string
  responsibility: string
  owner: string
  publicSurface: string
  nonOwner: string
}

interface ArchitectureDetailPanelProps {
  detail: ArchitectureDetail
  onClose: () => void
}

export default function ArchitectureDetailPanel({
  detail,
  onClose,
}: ArchitectureDetailPanelProps) {
  return (
    <aside
      className="architecture-detail"
      role="region"
      aria-label={`${detail.title} details`}
    >
      <div className="architecture-detail__heading">
        <div>
          <p className="architecture-kicker">Selected boundary</p>
          <h3>{detail.title}</h3>
        </div>
        <button type="button" onClick={onClose} aria-label={`Close ${detail.title} details`}>
          Close
        </button>
      </div>
      <dl>
        <div>
          <dt>Responsibility</dt>
          <dd>{detail.responsibility}</dd>
        </div>
        <div>
          <dt>Owner</dt>
          <dd>{detail.owner}</dd>
        </div>
        <div>
          <dt>Public API / artifact</dt>
          <dd><code>{detail.publicSurface}</code></dd>
        </div>
        <div>
          <dt>AEGIS does not own</dt>
          <dd>{detail.nonOwner}</dd>
        </div>
      </dl>
    </aside>
  )
}
