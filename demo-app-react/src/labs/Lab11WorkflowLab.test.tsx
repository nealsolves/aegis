import { fireEvent, render, screen } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import Lab11WorkflowLab from './Lab11WorkflowLab'
import { useApi } from '@/hooks/useApi'

vi.mock('@/context/AigcContext', () => ({
  useAigc: () => ({ apiUrl: 'http://localhost:8000', addAudit: vi.fn(), auditHistory: [] }),
}))

vi.mock('@/hooks/useApi', () => ({
  useApi: vi.fn(),
}))

type ApiHookState = {
  call: (path: string, body?: unknown) => Promise<unknown>
  loading: boolean
  error: string | null
}

let useApiStates: ApiHookState[] = []
let useApiCallCount = 0

function buildApiState(overrides: Partial<ApiHookState> = {}): ApiHookState {
  return {
    call: async () => null,
    loading: false,
    error: null,
    ...overrides,
  }
}

function mockUseApiStates(states: ApiHookState[]) {
  useApiStates = states
  useApiCallCount = 0
  vi.mocked(useApi).mockImplementation(() => {
    const state = useApiStates[useApiCallCount % useApiStates.length]
    useApiCallCount += 1
    return state
  })
}

beforeEach(() => {
  mockUseApiStates([
    buildApiState(),
    buildApiState(),
    buildApiState(),
    buildApiState(),
  ])
})

describe('Lab11WorkflowLab', () => {
  it('renders the lab comment line', () => {
    render(<Lab11WorkflowLab />)
    expect(screen.getByText(/workflow governance/i)).toBeInTheDocument()
  })

  it('renders Start Here tab button', () => {
    render(<Lab11WorkflowLab />)
    expect(screen.getByRole('button', { name: /start here/i })).toBeInTheDocument()
  })

  it('renders Failure & Fix tab button', () => {
    render(<Lab11WorkflowLab />)
    expect(screen.getByRole('button', { name: /failure.*fix/i })).toBeInTheDocument()
  })

  it('renders Governed vs Ungoverned tab button', () => {
    render(<Lab11WorkflowLab />)
    expect(screen.getByRole('button', { name: /governed vs ungoverned/i })).toBeInTheDocument()
  })

  it('renders Evidence View tab button', () => {
    render(<Lab11WorkflowLab />)
    expect(screen.getByRole('button', { name: /evidence view/i })).toBeInTheDocument()
  })

  it('renders Run Minimal button on Start Here tab', () => {
    render(<Lab11WorkflowLab />)
    expect(screen.getByRole('button', { name: /run minimal/i })).toBeInTheDocument()
  })

  it('disables diagnosis while a failure run is still in flight', () => {
    mockUseApiStates([
      buildApiState({ loading: true }),
      buildApiState(),
      buildApiState(),
      buildApiState(),
    ])

    render(<Lab11WorkflowLab />)
    fireEvent.click(screen.getByRole('button', { name: /failure.*fix/i }))

    expect(screen.getByRole('button', { name: /run doctor diagnosis/i })).toBeDisabled()
  })

  it('shows guidance when doctor has no prior failure to diagnose', async () => {
    const diagnoseCall = vi.fn(async () => ({
      findings: [],
      source: 'no_prior_failure',
    }))

    mockUseApiStates([
      buildApiState(),
      buildApiState(),
      buildApiState({ call: diagnoseCall }),
      buildApiState(),
    ])

    render(<Lab11WorkflowLab />)
    fireEvent.click(screen.getByRole('button', { name: /failure.*fix/i }))
    fireEvent.click(screen.getByRole('button', { name: /run doctor diagnosis/i }))

    expect(diagnoseCall).toHaveBeenCalledWith('/api/workflow/v090/diagnose')
    expect(await screen.findByText(/trigger failure first to generate a workflow run/i)).toBeInTheDocument()
  })

  it('calls the workflow trace endpoint from Evidence View', async () => {
    const traceCall = vi.fn(async () => ({
      traces: [{
        trace_schema_version: '0.9.0',
        session_id: 'session-1',
        status: 'COMPLETED',
        step_count: 2,
        unresolved_checksums: [],
        steps: [{
          sequence: 1,
          step_id: 'step-1',
          resolved: true,
          invocation_artifact_checksum: 'abc123',
          invocation_summary: {
            enforcement_result: 'PASS',
            model_provider: 'anthropic',
            model_identifier: 'claude-sonnet-4-6',
            role: 'ai-assistant',
          },
        }],
      }],
      artifact: {
        workflow_schema_version: '0.9.0',
        artifact_type: 'workflow',
        session_id: 'session-1',
        policy_file: 'policy.yaml',
        status: 'COMPLETED',
        started_at: 1,
        finalized_at: 2,
        steps: [],
        invocation_audit_checksums: [],
        failure_summary: null,
        metadata: {},
      },
    }))

    mockUseApiStates([
      buildApiState(),
      buildApiState(),
      buildApiState(),
      buildApiState({ call: traceCall }),
    ])

    render(<Lab11WorkflowLab />)
    fireEvent.click(screen.getByRole('button', { name: /evidence view/i }))
    fireEvent.click(screen.getByRole('button', { name: /build evidence trace/i }))

    expect(traceCall).toHaveBeenCalledWith('/api/workflow/v090/trace')
    expect(await screen.findByText(/resolved invocation steps/i)).toBeInTheDocument()
  })

  it('runs the failure, diagnosis, and fix flow against the workflow API contract', async () => {
    const runCall = vi.fn(async (_path: string, body?: unknown) => {
      const scenario = (body as { scenario?: string; run_id?: string } | undefined)?.scenario
      if (scenario === 'failure') {
        return {
          artifact: {
            workflow_schema_version: '0.9.0',
            artifact_type: 'workflow',
            session_id: 'failed-session',
            policy_file: 'policy.yaml',
            status: 'FAILED',
            started_at: 1,
            finalized_at: 2,
            steps: [],
            invocation_audit_checksums: [],
            failure_summary: { exception_type: 'CustomGateViolationError', message: 'source_ids missing' },
            metadata: {},
          },
          error: 'source_ids missing',
          run_id: 'run-123',
        }
      }
      return {
        artifact: {
          workflow_schema_version: '0.9.0',
          artifact_type: 'workflow',
          session_id: 'fixed-session',
          policy_file: 'policy.yaml',
          status: 'COMPLETED',
          started_at: 3,
          finalized_at: 4,
          steps: [{ step_id: 'step-1', participant_id: null, invocation_artifact_checksum: 'abc' }],
          invocation_audit_checksums: ['abc'],
          failure_summary: null,
          metadata: {},
        },
        error: null,
        run_id: 'run-123',
      }
    })
    const diagnoseCall = vi.fn(async () => ({
      findings: [{
        severity: 'INFO',
        code: 'WORKFLOW_SOURCE_REQUIRED',
        message: 'source_ids are required',
        next_action: 'Restore provenance source_ids and rerun.',
      }],
      source: 'failure_starter_dir',
    }))

    mockUseApiStates([
      buildApiState({ call: runCall }),
      buildApiState(),
      buildApiState({ call: diagnoseCall }),
      buildApiState(),
    ])

    render(<Lab11WorkflowLab />)
    fireEvent.click(screen.getByRole('button', { name: /failure.*fix/i }))
    fireEvent.click(screen.getByRole('button', { name: /trigger failure/i }))
    expect(await screen.findByText(/failure result/i)).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: /run doctor diagnosis/i }))
    expect(await screen.findByText(/WORKFLOW_SOURCE_REQUIRED/i)).toBeInTheDocument()
    expect(diagnoseCall).toHaveBeenCalledWith('/api/workflow/v090/diagnose?run_id=run-123')

    fireEvent.click(screen.getByRole('button', { name: /apply fix.*rerun/i }))
    expect(await screen.findByText(/post-fix result/i)).toBeInTheDocument()
    expect(runCall).toHaveBeenLastCalledWith('/api/workflow/v090/run', {
      scenario: 'regulated',
      run_id: 'run-123',
    })
  })

  it('does not contain private Python imports or stale aigc CLI strings', () => {
    render(<Lab11WorkflowLab />)
    expect(document.body.textContent).not.toMatch(/aegis\._internal/)
    expect(document.body.textContent).not.toMatch(/\baigc\s/)
  })
})
