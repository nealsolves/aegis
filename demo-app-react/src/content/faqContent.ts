export interface FaqSource {
  label: string
  href: string
}

export type FaqBlock =
  | {
      type: 'paragraph'
      text: string
    }
  | {
      type: 'list'
      items: readonly string[]
    }

export interface FaqItem {
  id: string
  question: string
  answer: readonly FaqBlock[]
  sources?: readonly FaqSource[]
  requiresAdapter?: 'bedrock'
}

export interface FaqCategory {
  id: string
  title: string
  description: string
  items: readonly FaqItem[]
}

const AEGIS_RUNTIME_SOURCE = {
  label: 'AEGIS runtime model',
  href: 'https://github.com/nealsolves/aegis/blob/main/README.md#runtime-model',
} as const

const AEGIS_WORKFLOW_SOURCE = {
  label: 'AEGIS workflow quickstart',
  href: (
    'https://github.com/nealsolves/aegis/blob/main/'
    + 'docs/reference/WORKFLOW_QUICKSTART.md#what-just-happened'
  ),
} as const

const AEGIS_SINK_SOURCE = {
  label: 'AEGIS audit persistence cookbook',
  href: (
    'https://github.com/nealsolves/aegis/blob/main/'
    + 'docs/USAGE.md#recipe-5-persisting-audit-artifacts'
  ),
} as const

const AEGIS_INTEGRITY_SOURCE = {
  label: 'AEGIS signing and AuditChain contract',
  href: (
    'https://github.com/nealsolves/aegis/blob/main/'
    + 'docs/PUBLIC_INTEGRATION_CONTRACT.md#38-artifact-signing'
  ),
} as const

const AEGIS_BEDROCK_SOURCE = {
  label: 'AEGIS Bedrock adapter contract',
  href: (
    'https://github.com/nealsolves/aegis/blob/main/'
    + 'docs/reference/external/BEDROCK_ADAPTER.md'
  ),
} as const

const ANTHROPIC_COT_SOURCE = {
  label: 'Anthropic: Reasoning Models Don’t Always Say What They Think',
  href: (
    'https://www-cdn.anthropic.com/'
    + 'b9ca6db27f02a9ddf0d4fdb51b26432c99a27be0.pdf'
  ),
} as const

const OPENAI_COT_SOURCE = {
  label: 'OpenAI: Detecting misbehavior in frontier reasoning models',
  href: 'https://openai.com/index/chain-of-thought-monitoring/',
} as const

const AGENTCORE_OVERVIEW_SOURCE = {
  label: 'AWS: Amazon Bedrock AgentCore overview',
  href: (
    'https://docs.aws.amazon.com/bedrock-agentcore/latest/'
    + 'devguide/what-is-bedrock-agentcore.html'
  ),
} as const

const AGENTCORE_POLICY_SOURCE = {
  label: 'AWS: Policy in Amazon Bedrock AgentCore',
  href: 'https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy.html',
} as const

const AGENTCORE_GATEWAY_SOURCE = {
  label: 'AWS: Create an Amazon Bedrock AgentCore Gateway',
  href: (
    'https://docs.aws.amazon.com/bedrock-agentcore/latest/'
    + 'devguide/gateway-create.html'
  ),
} as const

export const faqPageCopy = {
  eyebrow: 'Public FAQ',
  title: 'Questions with named owners and sources.',
  description: (
    'Each answer separates host execution, provider services, and AEGIS '
    + 'governance. Open a question for the direct answer, ownership boundary, '
    + 'and supporting public sources.'
  ),
  sourcesLabel: 'Sources',
  verificationLabel: 'Demo verification status',
} as const

export const bedrockVerificationCopy = {
  verified: (
    'This demo build publishes Bedrock adapter verification for '
    + 'deterministic fixtures.'
  ),
  notPublished: (
    'Bedrock adapter verification is not published for this demo build.'
  ),
  unavailable: (
    'Current Bedrock adapter verification status is unavailable until '
    + 'the demo manifest is ready.'
  ),
} as const

export const faqCategories: readonly FaqCategory[] = [
  {
    id: 'what-aegis-does',
    title: 'What AEGIS does',
    description: 'Policy checks and evidence at the host’s invocation boundary.',
    items: [
      {
        id: 'thought-trace',
        question: 'Why is a model thought trace not enough for governance?',
        answer: [
          {
            type: 'paragraph',
            text: (
              'A model thought trace is a useful monitoring signal, not a '
              + 'governance record. Research shows that a trace can help spot '
              + 'unwanted behavior, but it can be incomplete or unfaithful.'
            ),
          },
          {
            type: 'paragraph',
            text: (
              'A trace does not by itself prove which policy ran, whether '
              + 'pre-call input and post-call output checks occurred, which '
              + 'approvals, budgets, or execution order applied, or whether '
              + 'artifact integrity still holds. AEGIS records those host-run '
              + 'checks and their resulting evidence separately from model '
              + 'reasoning.'
            ),
          },
        ],
        sources: [ANTHROPIC_COT_SOURCE, OPENAI_COT_SOURCE, AEGIS_RUNTIME_SOURCE],
      },

      {
        id: 'does-not-replace',
        question: (
          'Does AEGIS replace my model provider, agent framework, or '
          + 'security controls?'
        ),
        answer: [
          {
            type: 'paragraph',
            text: (
              'No. The host and its providers own execution, credentials, '
              + 'networking, model and tool calls, retries, deployment, and '
              + 'business state.'
            ),
          },
          {
            type: 'paragraph',
            text: (
              'AEGIS runs in host code around an invocation or workflow step '
              + 'to apply declared rules and return evidence. It does not '
              + 'replace IAM, Cedar Gateway policy, provider security, an '
              + 'agent framework, or the host runtime.'
            ),
          },
        ],
        sources: [AEGIS_RUNTIME_SOURCE, AEGIS_BEDROCK_SOURCE],
      },

    ],
  },
  {
    id: 'agentic-workflows',
    title: 'Agentic workflows',
    description: 'Workflow constraints are governed; workflow execution stays with the host.',
    items: [
      {
        id: 'multi-agent-workflow',
        question: 'Can AEGIS govern a multi-agent workflow?',
        answer: [
          {
            type: 'paragraph',
            text: (
              'Yes. AEGIS governs agentic workflows by checking participants, '
              + 'sequence, handoffs, approvals, budgets, and lifecycle against '
              + 'the selected policy.'
            ),
          },
          {
            type: 'paragraph',
            text: (
              'The host application or agent framework executes agents, model '
              + 'calls, tools, and retries. AEGIS emits separate invocation and '
              + 'workflow evidence so an operator can correlate each governed '
              + 'step with the completed or interrupted workflow.'
            ),
          },
        ],
        sources: [AEGIS_WORKFLOW_SOURCE, AEGIS_RUNTIME_SOURCE],
      },

    ],
  },
  {
    id: 'evidence-and-data',
    title: 'Evidence and data',
    description: 'The host chooses persistence and optional tamper-evidence controls.',
    items: [
      {
        id: 'data-storage',
        question: 'What data does AEGIS store, and where does it go?',
        answer: [
          {
            type: 'paragraph',
            text: (
              'AEGIS returns audit artifacts to the host. The default is no '
              + 'audit sink, so persistent storage begins only when the host '
              + 'configures a destination.'
            ),
          },
          {
            type: 'paragraph',
            text: (
              'A host-selected file, callback, or custom sink can receive a '
              + 'deep copy of each artifact. Workflow session state and the '
              + 'workflow artifact remain in the host process unless the host '
              + 'persists them. AEGIS is not a hosted control plane and does '
              + 'not silently send demo or customer data to an AEGIS service.'
            ),
          },
        ],
        sources: [AEGIS_SINK_SOURCE, AEGIS_RUNTIME_SOURCE],
      },

      {
        id: 'signing-and-chain',
        question: 'Are signing and AuditChain required?',
        answer: [
          {
            type: 'paragraph',
            text: (
              'No. The evidence artifact is core; HMAC signing and AuditChain '
              + 'are optional tamper-evidence layers.'
            ),
          },
          {
            type: 'paragraph',
            text: (
              'A configured HMAC signer covers an artifact’s canonical JSON. '
              + 'AuditChain links ordered artifacts and can detect changes, '
              + 'insertion, deletion, or reordering within the supplied chain. '
              + 'The host decides whether those controls fit its key '
              + 'management and retention model.'
            ),
          },
        ],
        sources: [AEGIS_INTEGRITY_SOURCE],
      },

    ],
  },
  {
    id: 'platforms-and-adapters',
    title: 'Platforms and adapters',
    description: 'Adapters normalize evidence without taking over provider execution.',
    items: [
      {
        id: 'bedrock-adapter',
        question: 'What does the AEGIS Bedrock adapter do?',
        answer: [
          {
            type: 'paragraph',
            text: (
              'The AEGIS Bedrock adapter normalizes host-supplied evidence at '
              + 'the governance boundary. The host supplies the request, '
              + 'response, and parsed trace evidence; the adapter normalizes '
              + 'supported evidence for AEGIS policy and workflow checks.'
            ),
          },
          {
            type: 'paragraph',
            text: (
              'It creates no Bedrock client, holds no AWS credentials, invokes '
              + 'no model, agent, or tool, and owns no transport, retries, or '
              + 'deployment. Raw traces, prompts, tool arguments, credentials, '
              + 'and model outputs are not copied into adapter metadata. '
              + 'Invocation and workflow artifacts remain separate.'
            ),
          },
        ],
        sources: [AEGIS_BEDROCK_SOURCE],
        requiresAdapter: 'bedrock',
      },

      {
        id: 'agentcore-difference',
        question: (
          'What does AEGIS add when I already use Amazon Bedrock AgentCore?'
        ),
        answer: [
          {
            type: 'paragraph',
            text: (
              'AEGIS adds host-integrated invocation and workflow checks '
              + 'around host-owned model calls and workflow steps. These '
              + 'include pre-call and post-call checks for roles, inputs, '
              + 'outputs, and risk, plus workflow constraints for '
              + 'participants, order, handoffs, approvals, budgets, and '
              + 'lifecycle. It returns portable invocation and workflow '
              + 'evidence tied to the AEGIS policy.'
            ),
          },
          {
            type: 'paragraph',
            text: (
              'AgentCore is an agentic platform. Its modular services include '
              + 'Runtime, Memory, Gateway, Identity, Code Interpreter, Browser, '
              + 'and Observability, and those services can be used together or '
              + 'independently.'
            ),
          },
          {
            type: 'paragraph',
            text: (
              'AgentCore Gateway Policy uses Cedar. At that boundary, Cedar '
              + 'policy deterministically authorizes tool requests through '
              + 'AgentCore Gateway before tool access. It can use identity and '
              + 'tool input parameters, and AWS provides monitoring and logs '
              + 'for policy decisions. AEGIS does not replace AgentCore or its '
              + 'controls.'
            ),
          },
        ],
        sources: [
          AGENTCORE_OVERVIEW_SOURCE,
          AGENTCORE_POLICY_SOURCE,
          AGENTCORE_GATEWAY_SOURCE,
          AEGIS_RUNTIME_SOURCE,
          AEGIS_WORKFLOW_SOURCE,
        ],
      },

      {
        id: 'agentcore-together',
        question: 'Can AEGIS and AgentCore policy controls run together?',
        answer: [
          {
            type: 'paragraph',
            text: (
              'Yes. They can run together. AgentCore Gateway Policy can '
              + 'authorize tool requests through the Gateway while AEGIS '
              + 'applies invocation and workflow checks in host code.'
            ),
          },
          {
            type: 'paragraph',
            text: (
              'The host remains responsible for placing both controls on the '
              + 'intended paths and preserving their evidence. Coexistence at '
              + 'separate boundaries does not prove that every combined '
              + 'execution path has been validated.'
            ),
          },
        ],
        sources: [
          AGENTCORE_POLICY_SOURCE,
          AGENTCORE_GATEWAY_SOURCE,
          AEGIS_BEDROCK_SOURCE,
        ],
      },

    ],
  },
  {
    id: 'install-and-demo',
    title: 'Install and demo',
    description: 'The public demo is deterministic and reports service state directly.',
    items: [
      {
        id: 'live-model',
        question: 'Does the demo call a live model?',
        answer: [
          {
            type: 'paragraph',
            text: (
              'No. The public demo runs deterministic fixtures through the '
              + 'demo API and does not make a live provider call.'
            ),
          },
          {
            type: 'paragraph',
            text: (
              'The server owns the fixed scenario and adapter inputs and runs '
              + 'the published AEGIS paths. The browser asks for a named '
              + 'fixture and displays the returned decision and evidence; it '
              + 'does not ask for provider credentials.'
            ),
          },
        ],
        sources: [AEGIS_RUNTIME_SOURCE, AEGIS_BEDROCK_SOURCE],
      },

      {
        id: 'render-unavailable',
        question: 'What happens when the Render API is unavailable?',
        answer: [
          {
            type: 'paragraph',
            text: (
              'The demo reports that the service is starting or unavailable '
              + 'and does not turn that state into an AEGIS decision.'
            ),
          },
          {
            type: 'paragraph',
            text: (
              'Starting the demo API. Render may need about a minute after '
              + 'a period of inactivity.'
            ),
          },
          {
            type: 'paragraph',
            text: (
              'Run controls stay unavailable until readiness succeeds. A '
              + 'request failure is shown as a service error and is never '
              + 'presented as a governance result.'
            ),
          },
        ],
      },

    ],
  },
]
