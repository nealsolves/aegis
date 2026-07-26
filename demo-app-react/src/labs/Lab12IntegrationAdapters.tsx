import {
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
  type KeyboardEvent,
} from 'react'
import { AlertCircle, Check, Pause, X } from 'lucide-react'
import type { ResultHelpContext } from '@/components/HelpDrawer'
import { useAigc } from '@/context/AigcContext'
import { useDemoService } from '@/context/DemoServiceContext'
import { demoRequest } from '@/lib/demoApi'
import type {
  AdapterId,
  AdapterRunResponse,
  DemoOutcome,
} from '@/types/demo'
import { parseAdapterRunResponse } from './parseAdapterRunResponse'

interface FixtureChoice {
  id: string
  label: string
}

interface AdapterConfig {
  label: string
  fixtures: readonly FixtureChoice[]
}

const ADAPTER_CONFIG = {
  bedrock: {
    label: 'Amazon Bedrock',
    fixtures: [
      { id: 'valid_trace', label: 'Positive fixture' },
      { id: 'wrong_alias', label: 'Typed-negative fixture' },
    ],
  },
  openai_agents: {
    label: 'OpenAI Agents',
    fixtures: [
      { id: 'governed_graph', label: 'Positive fixture' },
      { id: 'predeclared_tool_call', label: 'Typed-negative fixture' },
    ],
  },
  a2a: {
    label: 'A2A',
    fixtures: [
      { id: 'completed_task', label: 'Positive fixture' },
      { id: 'grpc_binding', label: 'Typed-negative fixture' },
    ],
  },
} satisfies Record<AdapterId, AdapterConfig>

interface Props {
  onResultHelpContext?: (context: ResultHelpContext | null) => void
}

function isAdapterId(value: string): value is AdapterId {
  return Object.prototype.hasOwnProperty.call(ADAPTER_CONFIG, value)
}

function uniqueListedAdapters(values: readonly string[]): AdapterId[] {
  const seen = new Set<AdapterId>()
  return values.filter((value): value is AdapterId => {
    if (!isAdapterId(value) || seen.has(value)) return false
    seen.add(value)
    return true
  })
}

function errorMessage(error: unknown) {
  return error instanceof Error ? error.message : 'The adapter run failed.'
}

function jsonText(value: unknown) {
  return JSON.stringify(value, null, 2)
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function returnedPolicyChecks(
  response: AdapterRunResponse,
): { field: string; value: unknown }[] {
  if (
    response.artifact
    && Object.prototype.hasOwnProperty.call(
      response.artifact,
      'gates_evaluated',
    )
  ) {
    return [{
      field: 'gates_evaluated',
      value: response.artifact.gates_evaluated,
    }]
  }

  if (response.artifact && isRecord(response.artifact.metadata)) {
    return [{
      field: 'metadata',
      value: response.artifact.metadata,
    }]
  }

  if (
    Object.prototype.hasOwnProperty.call(
      response.normalized_evidence,
      'reason_code',
    )
  ) {
    return [{
      field: 'reason_code',
      value: response.normalized_evidence.reason_code,
    }]
  }

  return []
}

function resultHelpContext(
  response: AdapterRunResponse,
): ResultHelpContext {
  return {
    ...(response.error?.code ? { reasonCode: response.error.code } : {}),
    fields: Object.keys(response.normalized_evidence),
  }
}

function decisionPresentation(decision: DemoOutcome) {
  if (decision === 'PASS') {
    return { icon: Check, label: 'Pass', className: 'adapter-decision--pass' }
  }
  if (decision === 'FAIL') {
    return { icon: X, label: 'Fail', className: 'adapter-decision--fail' }
  }
  return { icon: Pause, label: 'Paused', className: 'adapter-decision--paused' }
}

export default function Lab12IntegrationAdapters({
  onResultHelpContext = () => undefined,
}: Props) {
  const { apiUrl } = useAigc()
  const { manifest, status } = useDemoService()
  const manifestAdapters = status === 'ready' && manifest
    ? manifest.adapters
    : []
  const availableAdapters = uniqueListedAdapters(manifestAdapters)

  const [adapterChoice, setAdapterChoice] = useState<AdapterId | null>(null)
  let selectedAdapter = availableAdapters[0] ?? null
  if (
    adapterChoice && availableAdapters.includes(adapterChoice)
  ) {
    selectedAdapter = adapterChoice
  }

  const fixtureChoices = selectedAdapter
    ? ADAPTER_CONFIG[selectedAdapter].fixtures
    : []

  const [fixtureChoice, setFixtureChoice] = useState<string | null>(null)
  let selectedFixture = fixtureChoices.length > 0
    ? fixtureChoices[0].id
    : null
  if (fixtureChoices.some(
    fixture => fixture.id === fixtureChoice,
  )) {
    selectedFixture = fixtureChoice
  }

  const [response, setResponse] = useState<AdapterRunResponse | null>(null)
  const [runError, setRunError] = useState<string | null>(null)
  const [isRunning, setIsRunning] = useState(false)
  const requestSequenceRef = useRef(0)
  const controllerRef = useRef<AbortController | null>(null)
  const tabRefs = useRef<Partial<Record<AdapterId, HTMLButtonElement | null>>>({})
  const effectiveSelectionKey = selectedAdapter && selectedFixture
    ? `${selectedAdapter}:${selectedFixture}`
    : 'unavailable'
  const selectionLifecycleKeyRef = useRef(effectiveSelectionKey)

  useLayoutEffect(() => {
    if (selectionLifecycleKeyRef.current === effectiveSelectionKey) return

    selectionLifecycleKeyRef.current = effectiveSelectionKey
    requestSequenceRef.current += 1
    controllerRef.current?.abort()
    controllerRef.current = null
    setIsRunning(false)
    setResponse(null)
    setRunError(null)
    setAdapterChoice(selectedAdapter)
    setFixtureChoice(selectedFixture)
    onResultHelpContext(null)
  }, [
    effectiveSelectionKey,
    onResultHelpContext,
    selectedAdapter,
    selectedFixture,
  ])

  useEffect(() => () => {
    requestSequenceRef.current += 1
    controllerRef.current?.abort()
  }, [])

  const selectAdapter = (adapterId: AdapterId) => {
    setAdapterChoice(adapterId)
    setFixtureChoice(ADAPTER_CONFIG[adapterId].fixtures[0].id)
  }

  const handleTabKeyDown = (
    event: KeyboardEvent<HTMLButtonElement>,
    adapterId: AdapterId,
  ) => {
    const currentIndex = availableAdapters.indexOf(adapterId)
    let nextIndex: number | null = null
    if (event.key === 'Home') nextIndex = 0
    if (event.key === 'End') nextIndex = availableAdapters.length - 1
    if (event.key === 'ArrowRight') {
      nextIndex = (currentIndex + 1) % availableAdapters.length
    }
    if (event.key === 'ArrowLeft') {
      nextIndex = (
        currentIndex - 1 + availableAdapters.length
      ) % availableAdapters.length
    }
    if (nextIndex === null) return
    event.preventDefault()
    const nextAdapter = availableAdapters[nextIndex]
    selectAdapter(nextAdapter)
    tabRefs.current[nextAdapter]?.focus()
  }

  const selectFixture = (fixtureId: string) => {
    if (!fixtureChoices.some(fixture => fixture.id === fixtureId)) return
    setFixtureChoice(fixtureId)
  }

  const run = async () => {
    if (
      status !== 'ready'
      || !selectedAdapter
      || !selectedFixture
      || !availableAdapters.includes(selectedAdapter)
      || !fixtureChoices.some(fixture => fixture.id === selectedFixture)
    ) {
      return
    }

    controllerRef.current?.abort()
    const controller = new AbortController()
    controllerRef.current = controller
    const requestSequence = requestSequenceRef.current + 1
    requestSequenceRef.current = requestSequence
    const requestSelectionKey = effectiveSelectionKey
    setResponse(null)
    setRunError(null)
    setIsRunning(true)
    onResultHelpContext(null)

    try {
      const unknownResponse = await demoRequest<unknown>(
        apiUrl,
        `/api/demo/adapters/${selectedAdapter}/runs`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ fixture_id: selectedFixture }),
          signal: controller.signal,
        },
      )
      const parsed = parseAdapterRunResponse(unknownResponse, {
        adapterId: selectedAdapter,
        fixtureId: selectedFixture,
      })
      if (
        controller.signal.aborted
        || requestSequenceRef.current !== requestSequence
        || selectionLifecycleKeyRef.current !== requestSelectionKey
      ) {
        return
      }
      setResponse(parsed)
      onResultHelpContext(resultHelpContext(parsed))
    } catch (error) {
      if (
        controller.signal.aborted
        || requestSequenceRef.current !== requestSequence
        || selectionLifecycleKeyRef.current !== requestSelectionKey
      ) {
        return
      }
      setRunError(errorMessage(error))
      setResponse(null)
      onResultHelpContext(null)
    } finally {
      if (
        !controller.signal.aborted
        && requestSequenceRef.current === requestSequence
        && selectionLifecycleKeyRef.current === requestSelectionKey
      ) {
        setIsRunning(false)
      }
    }
  }

  const canRun = (
    status === 'ready'
    && selectedAdapter !== null
    && selectedFixture !== null
    && availableAdapters.includes(selectedAdapter)
    && fixtureChoices.some(fixture => fixture.id === selectedFixture)
    && !isRunning
  )

  return (
    <main className="adapter-lab">
      <header className="adapter-lab__intro">
        <p className="scenario-kicker">Release-gated adapter fixtures</p>
        <h1>Inspect normalization at the governance boundary.</h1>
        <p>
          Select an adapter exposed by the current demo manifest. The service
          runs a server-owned deterministic fixture through the installed
          AEGIS adapter and returns the records shown below.
        </p>
      </header>

      {availableAdapters.length > 0 ? (
        <>
          <div
            className="adapter-tabs"
            role="tablist"
            aria-label="Integration adapters"
          >
            {availableAdapters.map(adapterId => (
              <button
                type="button"
                role="tab"
                id={`adapter-tab-${adapterId}`}
                aria-controls={`adapter-panel-${adapterId}`}
                aria-selected={selectedAdapter === adapterId}
                tabIndex={selectedAdapter === adapterId ? 0 : -1}
                ref={node => {
                  tabRefs.current[adapterId] = node
                }}
                onClick={() => selectAdapter(adapterId)}
                onKeyDown={event => handleTabKeyDown(event, adapterId)}
                key={adapterId}
              >
                {ADAPTER_CONFIG[adapterId].label}
              </button>
            ))}
          </div>

          {selectedAdapter && (
            <section
              className="adapter-run-panel"
              role="tabpanel"
              id={`adapter-panel-${selectedAdapter}`}
              aria-labelledby={`adapter-tab-${selectedAdapter}`}
            >
              <div>
                <p>Deterministic fixture</p>
                <h2>{ADAPTER_CONFIG[selectedAdapter].label}</h2>
                <p>
                  Choose a positive or typed-negative server fixture. Labels
                  describe the case category; the current response supplies
                  every displayed decision and artifact.
                </p>
              </div>
              <div className="adapter-run-panel__controls">
                <label htmlFor="adapter-fixture">Fixture case</label>
                <select
                  id="adapter-fixture"
                  aria-label="Fixture case"
                  value={selectedFixture ?? ''}
                  onChange={event => selectFixture(event.target.value)}
                >
                  {fixtureChoices.map(fixture => (
                    <option value={fixture.id} key={fixture.id}>
                      {fixture.label}
                    </option>
                  ))}
                </select>

                <button
                  type="button"
                  disabled={!canRun}
                  onClick={() => void run()}
                >
                  {isRunning ? 'Running fixture…' : 'Run adapter fixture'}
                </button>
              </div>
            </section>
          )}
        </>
      ) : (
        <section className="adapter-lab__empty" aria-live="polite">
          <AlertCircle aria-hidden="true" />
          <div>
            <h2>No integration adapter is ready</h2>
            <p>
              Run remains unavailable until the demo service is ready and its
              manifest lists a release-gated adapter.
            </p>
            <button type="button" disabled>
              Run adapter fixture
            </button>
          </div>
        </section>
      )}

      {runError && (
        <div className="adapter-lab__error" role="alert">
          <AlertCircle aria-hidden="true" />
          <div>
            <strong>Adapter run did not complete</strong>
            <p>{runError}</p>
          </div>
        </div>
      )}

      {response
        && response.adapter_id === selectedAdapter
        && response.fixture_id === selectedFixture
        && <AdapterResult response={response} />}
    </main>
  )
}

function AdapterResult({ response }: { response: AdapterRunResponse }) {
  const checks = returnedPolicyChecks(response)
  const decision = decisionPresentation(response.decision)
  const DecisionIcon = decision.icon

  return (
    <div
      className="adapter-result"
      data-testid="adapter-result"
      aria-live="polite"
      aria-atomic="true"
    >
      <section className="adapter-result-panel adapter-result-panel--native">
        <p className="adapter-result-panel__label">Returned provider record</p>
        <h2>Native fixture</h2>
        <p>
          Provider- or protocol-native input supplied by the current response.
        </p>
        <pre>{jsonText(response.provider_input)}</pre>
      </section>

      <section className="adapter-result-panel adapter-result-panel--normalized">
        <p className="adapter-result-panel__label">Returned AEGIS record</p>
        <h2>Normalized invocation and evidence</h2>
        <p>
          Adapter-normalized evidence returned separately from the native
          fixture.
        </p>
        <pre>{jsonText(response.normalized_evidence)}</pre>
      </section>

      <section className="adapter-result-panel">
        <p className="adapter-result-panel__label">Returned check fields</p>
        <h2>Policy checks</h2>
        {checks.length > 0 ? (
          <dl className="adapter-policy-checks">
            {checks.map(check => (
              <div key={check.field}>
                <dt>{check.field}</dt>
                <dd><code>{jsonText(check.value)}</code></dd>
              </div>
            ))}
          </dl>
        ) : (
          <p>The current response contains no policy-check detail field.</p>
        )}
      </section>

      <section className="adapter-result-panel">
        <p className="adapter-result-panel__label">Returned outcome</p>
        <h2>Decision</h2>
        <div className={`adapter-decision ${decision.className}`}>
          <DecisionIcon aria-hidden="true" />
          <div>
            <strong>{decision.label}</strong>
            <p>The current response reports {response.decision}.</p>
            {response.error && (
              <>
                <code>{response.error.code}</code>
                <p>{response.error.message}</p>
              </>
            )}
          </div>
        </div>
      </section>

      <section className="adapter-result-panel">
        <p className="adapter-result-panel__label">Returned evidence</p>
        <h2>Artifact</h2>
        <div className="adapter-artifacts">
          <div>
            <h3>Invocation artifact</h3>
            {response.artifact ? (
              <pre>{jsonText(response.artifact)}</pre>
            ) : (
              <p>No invocation artifact was returned.</p>
            )}
          </div>
          <div>
            <h3>Workflow artifact</h3>
            {response.workflow_artifact ? (
              <pre>{jsonText(response.workflow_artifact)}</pre>
            ) : (
              <p>No workflow artifact was returned.</p>
            )}
          </div>
          <div>
            <h3>Run source</h3>
            <pre>{jsonText(response.source)}</pre>
          </div>
        </div>
      </section>
    </div>
  )
}
