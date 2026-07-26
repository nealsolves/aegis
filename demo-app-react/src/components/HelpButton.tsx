interface Props {
  isOpen: boolean
  onOpen: () => void
}

export default function HelpButton({ isOpen, onOpen }: Props) {
  return (
    <button
      type="button"
      className="help-launcher__button"
      onClick={onOpen}
      aria-label="Open lab guide"
      aria-expanded={isOpen}
    >
      <span className="help-launcher__icon" aria-hidden="true">
        ?
      </span>
      Guide
    </button>
  )
}
