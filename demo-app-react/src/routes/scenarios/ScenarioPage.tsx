import {
  useCallback,
  useEffect,
  useRef,
  useState,
} from 'react'
import type { CSSProperties } from 'react'
import { ArrowLeft, ArrowRight, ExternalLink } from 'lucide-react'
import { Link, useParams } from 'react-router-dom'
import { useAigc } from '@/context/AigcContext'
import { useDemoService } from '@/context/DemoServiceContext'
import { demoRequest } from '@/lib/demoApi'
import type { ScenarioRunResponse } from '@/types/demo'
import { parseScenarioRunResponse } from './parseScenarioRunResponse'
import ScenarioTimeline from './ScenarioTimeline'
import {
  isScenarioId,
  SCENARIO_CONTENT,
  type ScenarioContent,
  type ScenarioId,
} from './scenarioContent'

function isAbortError(error: unknown) {
  return error instanceof DOMException && error.name === 'AbortError'
}

function serviceMessage(status: ReturnType<typeof useDemoService>['status']) {
  switch (status) {
    case 'ready':
      return 'Choose your judgment, then run the governed case.'
    case 'checking':
    case 'starting':
      return 'Waiting for the demo service.'
    case 'mismatch':
      return 'The demo service uses an incompatible API contract.'
    case 'unavailable':
      return 'The demo service is unavailable. Use the service control above to retry.'
  }
}

function NotFoundPage() {
  return (
    <main className="scenario-not-found">
      <p className="intro-eyebrow">Demo scenarios</p>
      <h1>Scenario not found</h1>
      <p>The requested case is not part of this deterministic demo.</p>
      <Link to="/demo/scenarios">
        <ArrowLeft aria-hidden="true" />
        Return to all scenarios
      </Link>
    </main>
  )
}

function ScenarioHeader({ content }: { content: ScenarioContent }) {
  return (
    <header className="scenario-hero">
      <div>
        <Link className="scenario-back-link" to="/demo/scenarios">
          <ArrowLeft aria-hidden="true" />
          All scenarios
        </Link>
        <p className="scenario-kicker">Governed case file · {content.id}</p>
        <h1>{content.title}</h1>
        <p className="scenario-role">{content.visitorRole}</p>
      </div>
      <aside className="scenario-boundary" aria-label="AEGIS boundary">
        <strong>{content.boundary?.title ?? 'AEGIS checks the draft before delivery.'}</strong>
        <p>
          {content.boundary?.text ?? (
            'The assistant drafts the answer. AEGIS independently enforces the encoded runtime policy. If a draft is blocked, the host revises it; AEGIS does not write the replacement.'
          )}
        </p>
      </aside>
    </header>
  )
}

function ScenarioController({
  scenarioId,
}: {
  scenarioId: string | undefined
}) {
  const { apiUrl } = useAigc()
  const { status } = useDemoService()
  const [selection, setSelection] = useState<{
    scenarioId: ScenarioId
    index: number
  } | null>(null)
  const [response, setResponse] = useState<ScenarioRunResponse | null>(null)
  const [requestError, setRequestError] = useState<{
    scenarioId: ScenarioId
    message: string
  } | null>(null)
  const [runningScenarioId, setRunningScenarioId] = useState<ScenarioId | null>(
    null,
  )
  const requestSequenceRef = useRef(0)
  const requestControllerRef = useRef<AbortController | null>(null)

  const content = isScenarioId(scenarioId)
    ? SCENARIO_CONTENT[scenarioId]
    : null

  useEffect(() => () => {
    requestSequenceRef.current += 1
    requestControllerRef.current?.abort()
  }, [])

  const selectedChoice = content && selection?.scenarioId === content.id
    ? selection.index
    : null
  const isAgenticComparison = content?.interactionMode === 'agentic_comparison'
  const selectedVariant = isAgenticComparison
    ? content.variants[0] ?? null
    : selectedChoice === null
      ? null
      : content?.variants[selectedChoice] ?? null

  const runScenario = useCallback(async (overrideVariant?: string) => {
    if (!content || (!isAgenticComparison && selectedChoice === null)) return
    const requestedVariant = overrideVariant ?? selectedVariant
    if (!requestedVariant || status !== 'ready') return

    requestControllerRef.current?.abort()
    const controller = new AbortController()
    requestControllerRef.current = controller
    const sequence = requestSequenceRef.current + 1
    requestSequenceRef.current = sequence
    const variant = requestedVariant

    setRunningScenarioId(content.id)
    setRequestError(null)
    setResponse(null)

    try {
      const responseBody = await demoRequest<unknown>(
        apiUrl,
        `/api/demo/scenarios/${content.id}/runs`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ variant }),
          signal: controller.signal,
        },
      )
      const nextResponse = parseScenarioRunResponse(responseBody, {
        scenarioId: content.id,
        variant,
      })
      if (
        requestSequenceRef.current === sequence
        && !controller.signal.aborted
      ) {
        setResponse(nextResponse)
      }
    } catch (error) {
      if (
        requestSequenceRef.current === sequence
        && !controller.signal.aborted
        && !isAbortError(error)
      ) {
        setRequestError({
          scenarioId: content.id,
          message: error instanceof Error
            ? error.message
            : 'The scenario request failed.',
        })
      }
    } finally {
      if (requestSequenceRef.current === sequence) {
        setRunningScenarioId(null)
      }
    }
  }, [
    apiUrl,
    content,
    isAgenticComparison,
    selectedChoice,
    selectedVariant,
    status,
  ])

  if (!content) return <NotFoundPage />

  const isRunning = runningScenarioId === content.id

  const currentResponse = response?.scenario_id === content.id
    ? response
    : null

  const currentRequestError = requestError?.scenarioId === content.id
    ? requestError.message
    : null
  const runDisabled = (
    (!isAgenticComparison && selectedChoice === null)
    || (selectedVariant !== null && status !== 'ready')
  )

  return (
    <main className="scenario-page">
      <ScenarioHeader content={content} />

      <div className="scenario-case-file">
        <section
          className="scenario-region"
          aria-labelledby="scenario-incident-title"
        >
          <div className="scenario-region__label">01</div>
          <div>
            <h2 id="scenario-incident-title">Incident</h2>
            <p className="scenario-incident">{content.incident}</p>
            <ol className="scenario-story" aria-label="Case story">
              {content.setup.map((beat, index) => (
                <li
                  data-tone={beat.tone ?? 'neutral'}
                  key={`${content.id}-${beat.label}`}
                  style={{ '--story-order': index } as CSSProperties}
                >
                  <span>{String(index + 1).padStart(2, '0')}</span>
                  <div>
                    <p>{beat.label}</p>
                    <h3>{beat.title}</h3>
                    <p>{beat.text}</p>
                  </div>
                </li>
              ))}
            </ol>
            {content.sources && (
              <div className="scenario-sources">
                <span>Case reference</span>
                {content.sources.map((source) => (
                  <a
                    href={source.href}
                    key={source.href}
                    rel="noreferrer"
                    target="_blank"
                  >
                    {source.label}
                    <ExternalLink aria-hidden="true" />
                  </a>
                ))}
              </div>
            )}
          </div>
        </section>

        <section
          className="scenario-region"
          aria-labelledby="scenario-judgment-title"
        >
          <div className="scenario-region__label">02</div>
          <div>
            <h2 id="scenario-judgment-title">
              {isAgenticComparison ? 'Agentic flow' : 'Your judgment'}
            </h2>
            <p className="scenario-judgment-lead">
              {isAgenticComparison
                ? 'Run the same autonomous payment attempt with and without runtime policy enforcement.'
                : 'Choose how the fictional workflow should proceed.'}
            </p>

            {!isAgenticComparison && (
              <div
                className="scenario-choices"
                role="radiogroup"
                aria-label="Judgment choices"
              >
                {content.choices.map((choice, index) => (
                  <label
                    className="scenario-choice"
                    data-selected={selectedChoice === index}
                    key={choice.id}
                  >
                    <input
                      checked={selectedChoice === index}
                      name={`${content.id}-judgment`}
                      onChange={() => {
                        setSelection({ scenarioId: content.id, index })
                      }}
                      type="radio"
                    />
                    <span className="scenario-choice__marker" aria-hidden="true">
                      {String.fromCharCode(65 + index)}
                    </span>
                    <span>{choice.label}</span>
                  </label>
                ))}
              </div>
            )}

            <div className="scenario-run-row">
              <button
                type="button"
                aria-busy={isRunning}
                disabled={runDisabled}
                onClick={() => void runScenario()}
              >
                {isAgenticComparison ? 'Run agentic comparison' : 'Run judgment'}
                <ArrowRight aria-hidden="true" />
              </button>
              <p role="status" aria-live="polite">
                {isRunning
                  ? 'Requesting the server evaluation.'
                  : isAgenticComparison && status === 'ready'
                    ? 'Ready to run the autonomous payment attempt.'
                    : serviceMessage(status)}
              </p>
            </div>

            {currentRequestError && (
              <div className="scenario-request-error" role="alert">
                <strong>The server did not return a scenario result.</strong>
                <p>{currentRequestError}</p>
              </div>
            )}
          </div>
        </section>

        <ScenarioTimeline
          key={`${content.id}-${currentResponse?.variant ?? 'empty'}`}
          response={currentResponse}
          scenarioId={content.id}
        />
        {content.id === 'atlas' && currentResponse?.variant === 'first_attempt' && (
          <section className="scenario-correction" aria-labelledby="atlas-correction-title">
            <p>Correction replay</p>
            <h2 id="atlas-correction-title">Revise the host-owned answer</h2>
            <p>
              Atlas AI changes the decision to not covered and cites BRV-04.
              AEGIS then checks the revised draft again.
            </p>
            <button
              type="button"
              disabled={isRunning || status !== 'ready'}
              onClick={() => void runScenario('corrected')}
            >
              Run corrected answer
              <ArrowRight aria-hidden="true" />
            </button>
          </section>
        )}
      </div>
    </main>
  )
}

export default function ScenarioPage() {
  const { scenarioId } = useParams()

  return (
    <ScenarioController
      key={scenarioId ?? 'scenario-not-found'}
      scenarioId={scenarioId}
    />
  )
}
