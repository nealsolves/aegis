import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from '@testing-library/react'
import { AigcProvider } from '@/context/AigcContext'
import { DemoServiceProvider } from '@/context/DemoServiceContext'
import { ThemeProvider } from '@/theme/ThemeContext'
import App from '@/App'

const REQUIRED_CATEGORIES = [
  'What AEGIS does',
  'Agentic workflows',
  'Evidence and data',
  'Platforms and adapters',
  'Install and demo',
] as const

const REQUIRED_QUESTIONS = [
  'Why is a model thought trace not enough for governance?',
  'Does AEGIS replace my model provider, agent framework, or security controls?',
  'Can AEGIS govern a multi-agent workflow?',
  'What data does AEGIS store, and where does it go?',
  'Are signing and AuditChain required?',
  'Does the demo call a live model?',
  'What happens when the Render API is unavailable?',
  'What does the AEGIS Bedrock adapter do?',
  'What does AEGIS add when I already use Amazon Bedrock AgentCore?',
  'Can AEGIS and AgentCore policy controls run together?',
] as const

const REQUIRED_SOURCES = [
  'https://www-cdn.anthropic.com/b9ca6db27f02a9ddf0d4fdb51b26432c99a27be0.pdf',
  'https://openai.com/index/chain-of-thought-monitoring/',
  'https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy.html',
  'https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-create.html',
  'https://github.com/nealsolves/aegis/blob/main/docs/reference/external/BEDROCK_ADAPTER.md',
] as const

const HEALTH = {
  status: 'ok',
  api_contract_version: '1',
  sdk_version: '0.9.0b1',
  source: {
    branch: 'main',
    commit: 'backend-commit',
  },
}

const MANIFEST = {
  api_contract_version: '1',
  sdk_version: '0.9.0b1',
  fixture_set_version: '2026-07-25',
  scenarios: ['atlas', 'meridian', 'northstar'],
  adapters: ['a2a', 'bedrock', 'openai_agents'],
  source: {
    branch: 'main',
    commit: 'backend-commit',
    sdk_version: '0.9.0b1',
  },
}

function jsonResponse(body: unknown, init?: ResponseInit) {
  return new Response(JSON.stringify(body), {
    headers: { 'Content-Type': 'application/json' },
    ...init,
  })
}

function renderFaq() {
  window.location.hash = '#/faq'

  return render(
    <ThemeProvider>
      <AigcProvider>
        <DemoServiceProvider>
          <App />
        </DemoServiceProvider>
      </AigcProvider>
    </ThemeProvider>,
  )
}

function faqItem(question: string) {
  const questionText = screen.getByText(question)
  const summary = questionText.closest('summary')
  const details = questionText.closest('details')

  expect(summary).not.toBeNull()
  expect(details).not.toBeNull()

  return {
    details: details!,
    summary: summary!,
  }
}

function answerText(question: string) {
  return faqItem(question).details.textContent ?? ''
}

describe('FaqPage', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn(() => new Promise<Response>(() => undefined)))
  })

  afterEach(() => {
    cleanup()
    window.location.hash = ''
    vi.useRealTimers()
    vi.unstubAllGlobals()
  })

  it('publishes every approved category and question on the public FAQ route', () => {
    renderFaq()

    expect(
      screen.getByRole('heading', { name: 'Questions with named owners and sources.' }),
    ).toBeInTheDocument()

    for (const category of REQUIRED_CATEGORIES) {
      expect(screen.getByRole('heading', { name: category })).toBeInTheDocument()
    }
    for (const question of REQUIRED_QUESTIONS) {
      expect(screen.getByText(question)).toBeInTheDocument()
    }
  })

  it('uses native, focusable disclosures for every answer', () => {
    renderFaq()

    for (const question of REQUIRED_QUESTIONS) {
      const { details, summary } = faqItem(question)

      expect(summary).toHaveProperty('tabIndex', 0)
      summary.focus()
      expect(summary).toHaveFocus()
      fireEvent.click(summary)
      expect(details).toHaveAttribute('open')
    }
  })

  it('links every required primary source with safe external-link behavior', () => {
    const { container } = renderFaq()
    const links = Array.from(container.querySelectorAll<HTMLAnchorElement>(
      '.faq-sources a',
    ))

    for (const href of REQUIRED_SOURCES) {
      const link = links.find(candidate => candidate.href === href)
      expect(link).toBeDefined()
      expect(link).toHaveAttribute('target', '_blank')
      expect(link?.rel.split(/\s+/)).toEqual(
        expect.arrayContaining(['noopener', 'noreferrer']),
      )
      expect(link).not.toHaveAccessibleName(href)
    }
  })

  it('treats thought traces as useful monitoring signals, not governance records', () => {
    renderFaq()
    const answer = answerText(REQUIRED_QUESTIONS[0])

    expect(answer).toMatch(/useful monitoring signal/i)
    expect(answer).toMatch(/not a governance record/i)
    expect(answer).toMatch(/incomplete or unfaithful/i)
    expect(answer).toMatch(/which policy ran/i)
    expect(answer).toMatch(/approvals, budgets, or execution order/i)
    expect(answer).toMatch(/artifact integrity/i)
  })

  it('keeps provider, framework, security, and workflow execution with their owners', () => {
    renderFaq()
    const replacementAnswer = answerText(REQUIRED_QUESTIONS[1])
    const workflowAnswer = answerText(REQUIRED_QUESTIONS[2])

    expect(replacementAnswer).toMatch(/^Does AEGIS replace.*?No\./)
    expect(replacementAnswer).toMatch(/host and its providers own execution/i)
    expect(replacementAnswer).toMatch(/does not replace IAM/i)

    expect(workflowAnswer).toMatch(/AEGIS governs agentic workflows/i)
    expect(workflowAnswer).toMatch(
      /participants, sequence, handoffs, approvals, budgets, and lifecycle/i,
    )
    expect(workflowAnswer).toMatch(
      /host application or agent framework executes agents, model calls, tools, and retries/i,
    )
    expect(workflowAnswer).toMatch(/separate invocation and workflow evidence/i)
  })

  it('states the public storage, signing, and AuditChain contracts precisely', () => {
    renderFaq()
    const storageAnswer = answerText(REQUIRED_QUESTIONS[3])
    const signingAnswer = answerText(REQUIRED_QUESTIONS[4])

    expect(storageAnswer).toMatch(/returns audit artifacts to the host/i)
    expect(storageAnswer).toMatch(/default is no audit sink/i)
    expect(storageAnswer).toMatch(/host-selected file, callback, or custom sink/i)
    expect(storageAnswer).toMatch(/not a hosted control plane/i)
    expect(storageAnswer).toMatch(/does not silently send/i)

    expect(signingAnswer).toMatch(/evidence artifact is core/i)
    expect(signingAnswer).toMatch(
      /HMAC signing and AuditChain are optional tamper-evidence layers/i,
    )
  })

  it('describes the deterministic demo and Render outage without implying a live call', () => {
    renderFaq()
    const liveAnswer = answerText(REQUIRED_QUESTIONS[5])
    const renderAnswer = answerText(REQUIRED_QUESTIONS[6])

    expect(liveAnswer).toMatch(/deterministic fixtures/i)
    expect(liveAnswer).toMatch(/does not make a live provider call/i)
    expect(renderAnswer).toMatch(
      /Starting the demo API\. Render may need about a minute after a period of inactivity\./,
    )
    expect(renderAnswer).toMatch(/never presented as a governance result/i)
  })

  it('defines the Bedrock adapter as host-supplied evidence normalization only', () => {
    renderFaq()
    const answer = answerText(REQUIRED_QUESTIONS[7])

    expect(answer).toMatch(/host supplies the request, response, and parsed trace evidence/i)
    expect(answer).toMatch(/normalizes supported evidence for AEGIS/i)
    expect(answer).toMatch(/creates no Bedrock client/i)
    expect(answer).toMatch(/holds no AWS credentials/i)
    expect(answer).toMatch(/invokes no model, agent, or tool/i)
    expect(answer).toMatch(/owns no transport, retries, or deployment/i)
    expect(answer).toMatch(/deterministic demo validation/i)
    expect(answer).toMatch(/not universal AgentCore or live-environment compatibility/i)
  })

  it('distinguishes AgentCore Gateway policy from AEGIS without an enforcement overclaim', () => {
    renderFaq()
    const comparisonAnswer = answerText(REQUIRED_QUESTIONS[8])
    const coexistenceAnswer = answerText(REQUIRED_QUESTIONS[9])

    expect(comparisonAnswer).toMatch(
      /AgentCore owns managed runtime and deployment/i,
    )
    expect(comparisonAnswer).toMatch(
      /identity, memory, Gateway, observability, browser, and code tools/i,
    )
    expect(comparisonAnswer).toMatch(
      /Cedar policy deterministically authorizes tool requests through AgentCore Gateway/i,
    )
    expect(comparisonAnswer).toMatch(/AEGIS is an in-process governance SDK/i)
    expect(comparisonAnswer).toMatch(/pre-call and post-call checks/i)
    expect(comparisonAnswer).toMatch(/portable invocation and workflow evidence/i)
    expect(comparisonAnswer).toMatch(/does not replace AgentCore/i)

    expect(coexistenceAnswer).toMatch(/^Can AEGIS and AgentCore.*?Yes\./)
    expect(coexistenceAnswer).toMatch(/They can run together/i)
    expect(coexistenceAnswer).toMatch(
      /does not prove that every combined execution path has been validated/i,
    )
  })

  it('publishes Bedrock demo verification only when a ready manifest lists bedrock', async () => {
    vi.stubGlobal('fetch', vi.fn()
      .mockResolvedValueOnce(jsonResponse(HEALTH))
      .mockResolvedValueOnce(jsonResponse(MANIFEST)))

    renderFaq()

    await waitFor(() => {
      expect(screen.getByText(
        'This demo build publishes Bedrock adapter verification for deterministic fixtures.',
      )).toBeInTheDocument()
    })
    expect(screen.queryByText(
      'Bedrock adapter verification is not published for this demo build.',
    )).not.toBeInTheDocument()
  })

  it('uses the exact unpublished status when a ready manifest omits bedrock', async () => {
    vi.stubGlobal('fetch', vi.fn()
      .mockResolvedValueOnce(jsonResponse(HEALTH))
      .mockResolvedValueOnce(jsonResponse({
        ...MANIFEST,
        adapters: ['a2a', 'openai_agents'],
      })))

    renderFaq()

    await waitFor(() => {
      expect(screen.getByText(
        'Bedrock adapter verification is not published for this demo build.',
      )).toBeInTheDocument()
    })
    expect(screen.queryByText(
      'This demo build publishes Bedrock adapter verification for deterministic fixtures.',
    )).not.toBeInTheDocument()
  })

  it('uses a neutral status while readiness is checking or unavailable', async () => {
    const neutralStatus = (
      'Current Bedrock adapter verification status is unavailable until '
      + 'the demo manifest is ready.'
    )
    const pending = renderFaq()

    expect(screen.getByText(neutralStatus)).toBeInTheDocument()
    expect(screen.queryByText(
      'Bedrock adapter verification is not published for this demo build.',
    )).not.toBeInTheDocument()
    expect(screen.queryByText(
      'This demo build publishes Bedrock adapter verification for deterministic fixtures.',
    )).not.toBeInTheDocument()

    pending.unmount()
    vi.useFakeTimers()
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(
      jsonResponse({ detail: 'Service Unavailable' }, { status: 503 }),
    ))
    renderFaq()

    for (const delay of [0, 1000, 2000, 4000, 8000, 15000, 30000]) {
      await act(async () => {
        await vi.advanceTimersByTimeAsync(delay)
      })
    }

    expect(screen.getByText(neutralStatus)).toBeInTheDocument()
    expect(screen.queryByText(
      'Bedrock adapter verification is not published for this demo build.',
    )).not.toBeInTheDocument()
    expect(screen.queryByText(
      'This demo build publishes Bedrock adapter verification for deterministic fixtures.',
    )).not.toBeInTheDocument()
  })
})
