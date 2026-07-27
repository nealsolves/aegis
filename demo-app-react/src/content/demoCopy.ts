export const publicNavCopy = {
  ariaLabel: 'Primary navigation',
  brand: 'AEGIS',
  brandLabel: 'AEGIS home',
  descriptor: 'Auditable Enforcement and Governance for Intelligent Systems',
  links: [
    { id: 'install', label: 'Install', to: '/#install', emphasis: false },
    {
      id: 'demo',
      label: 'Open demo',
      currentLabel: 'Demo',
      to: '/demo/architecture',
      emphasis: true,
    },
    { id: 'faq', label: 'FAQ', to: '/faq', emphasis: false },
  ],
  github: {
    label: 'GitHub',
    href: 'https://github.com/nealsolves/aegis',
  },
  theme: {
    dark: 'dark',
    light: 'light',
    switchTo: 'Switch to',
    mode: 'mode',
  },
} as const

export const demoNavCopy = {
  ariaLabel: 'Demo navigation',
  links: [
    { label: 'Architecture', to: '/demo/architecture' },
    { label: 'Scenarios', to: '/demo/scenarios' },
    { label: 'Labs', to: '/demo/labs' },
    { label: 'FAQ', to: '/faq' },
  ],
} as const

export const demoServiceNoticeCopy = {
  starting:
    'Starting the demo API. Render may need about a minute after a period of inactivity.',
  retry: 'Retry',
  unavailable: (operation: string | undefined = undefined) =>
    `The governance run did not complete because the ${operation || 'readiness check'} operation failed.`,
  mismatch: (
    frontendContractVersion: string | undefined = undefined,
    backendContractVersion: string | undefined = undefined,
  ) =>
    `Demo API contract mismatch. Frontend contract ${frontendContractVersion || '1'}; backend contract ${backendContractVersion || 'missing'}.`,
} as const

export const introCopy = {
  hero: {
    eyebrow: 'Runtime governance for AI calls and agent workflows',
    title: 'The deterministic wrapper around a probabilistic core.',
    lead:
      'AI works in possibilities. Enterprise systems need a definite decision: '
      + 'allow, block, pause, or escalate. AEGIS enforces your enterprise policy '
      + 'at the boundary—before an AI acts and before its output becomes an '
      + 'operational outcome.',
    workflow:
      'AEGIS applies declared policy to participants, steps, handoffs, approvals, '
      + 'budgets, and session lifecycle.',
    host:
      'Your application or agent framework continues to execute models, agents, '
      + 'and tools.',
    actions: [
      { label: 'See the demo', to: '/demo/architecture', emphasis: true },
      { label: 'Install AEGIS', to: '/#install', emphasis: false },
    ],
    callFlowLabel: 'The governed boundary',
    callFlow: [
      {
        owner: 'Enterprise application',
        title: 'Declare the request',
        detail: 'The host supplies the role, input, policy, and runtime context.',
        kind: 'host',
      },
      {
        owner: 'Deterministic pre-call gate',
        title: 'Allow, block, pause, or escalate',
        detail: 'AEGIS applies enterprise policy before the model, agent, or tool runs.',
        kind: 'policy',
      },
      {
        owner: 'Probabilistic core',
        title: 'Execute the model or agent',
        detail: 'The host keeps its provider client, credentials, retries, and business state.',
        kind: 'host-owned',
      },
      {
        owner: 'Deterministic post-call gate',
        title: 'Accept or reject the output',
        detail: 'AEGIS applies output rules before the host uses the result.',
        kind: 'policy',
      },
      {
        owner: 'Independent evidence',
        title: 'Record the governance decision',
        detail: 'The artifact carries reason codes, policy metadata, checksums, and workflow context.',
        kind: 'evidence',
      },
    ],
  },
  ownership: {
    id: 'what-it-does',
    eyebrow: 'The enterprise boundary',
    title: 'Let AI handle possibility. Make policy decide permission.',
    intro:
      'Models and agents can reason through ambiguity. Enterprise permission '
      + 'resolves against declared, versioned policy before a proposed action '
      + 'becomes an operational outcome.',
    areas: [
      {
        title: 'Probabilistic core',
        detail:
          'Models and agents reason, plan, generate, and propose tool actions '
          + 'across ambiguous situations.',
      },
      {
        title: 'Deterministic governance',
        detail:
          'AEGIS enforces roles, preconditions, tool limits, approvals, budgets, '
          + 'output rules, and risk treatment.',
      },
      {
        title: 'Enterprise operation',
        detail:
          'Your application owns orchestration, credentials, execution, business '
          + 'state, downstream action, and storage of governance evidence.',
      },
    ],
  },
  comparison: {
    eyebrow: 'Independent governance evidence',
    title: 'An explanation is not a control.',
    intro:
      'A thought trace can help a team understand model behavior. It remains an '
      + 'account produced by the system being inspected. Enterprise governance '
      + 'needs a separate record showing which policy ran, what was allowed or '
      + 'blocked, and why.',
    columns: [
      {
        title: "The model's account",
        label: 'Useful clues for understanding behavior',
        items: [
          'Produced by the model being inspected.',
          'Helps with debugging and behavioral inspection.',
          'May omit an influence or construct a plausible explanation after the fact.',
          'Cannot independently authorize or stop an enterprise action.',
          'Does not prove which enterprise policy was executed.',
        ],
      },
      {
        title: "The system's receipt",
        label: 'Independent evidence of the governance decision',
        items: [
          'Produced by AEGIS outside the model.',
          'Tied to a versioned policy and ordered enforcement gates.',
          'Records allow, block, pause, or escalation outcomes.',
          'Can stop a request before execution or reject output before use.',
          'Captures reason codes, checksums, policy metadata, and workflow context.',
        ],
      },
    ],
    source: {
      lead: 'Primary research on thought-trace faithfulness:',
      label: 'Language Models Don’t Always Say What They Think',
      href: 'https://arxiv.org/abs/2305.04388',
    },
  },
  install: {
    id: 'install',
    eyebrow: 'First integration',
    title:
      'Add AEGIS to an AI invocation or agentic workflow you already own.',
    intro:
      'Apply policy before execution and validate the result after it. The '
      + 'host-owned call remains visible between the two checkpoints.',
    command: 'pip install aegis-ai-governance==0.9.0b1',
    commandLabel: 'Install the AEGIS public beta',
    steps: [
      {
        title: 'Install',
        detail: 'Install the published beta in your Python environment.',
      },
      {
        title: 'Choose policy',
        detail: 'Use a supplied policy profile or a YAML policy.',
      },
      {
        title: 'Split the checks',
        detail: 'Run pre-call enforcement before the host call and post-call enforcement after it.',
      },
      {
        title: 'Store evidence',
        detail: 'Send the returned artifact through a supported sink.',
      },
    ],
    sampleLabel: 'Split enforcement Python example',
    sampleLines: [
      { text: 'from aegis import enforce_post_call, enforce_pre_call', kind: 'context' },
      { text: '', kind: 'context' },
      { text: 'pre = enforce_pre_call(', kind: 'pre' },
      { text: '    {', kind: 'pre' },
      { text: '        "policy_file": "policies/support.yaml",', kind: 'pre' },
      { text: '        "model_provider": "anthropic",', kind: 'pre' },
      { text: '        "model_identifier": "claude-sonnet-4-6",', kind: 'pre' },
      { text: '        "role": "support_agent",', kind: 'pre' },
      { text: '        "input": {"query": customer_message},', kind: 'pre' },
      { text: '        "context": {"customer_verified": True},', kind: 'pre' },
      { text: '    }', kind: 'pre' },
      { text: ')', kind: 'pre' },
      { text: '', kind: 'context' },
      { text: '# Host-owned model call', kind: 'host' },
      { text: 'reply = model.generate(customer_message)', kind: 'host' },
      { text: '', kind: 'context' },
      { text: 'artifact = enforce_post_call(pre, {"result": reply})', kind: 'post' },
    ],
  },
  principle: {
    eyebrow: 'The operating principle',
    title: 'Governance is infrastructure.',
    intro:
      'Models, providers, and agent frameworks can change. Your governance '
      + 'boundary remains declared, executable, independently observable, and '
      + 'auditable.',
  },
  entries: {
    eyebrow: 'Explore the demo',
    title: 'Choose where to start',
    regionLabel: 'Choose where to start',
    intro:
      'Understand the ownership boundary, follow a governed enterprise case, '
      + 'or inspect one control at a time.',
    cards: [
      {
        title: 'Architecture',
        description: 'Understand the ownership boundary and technical map.',
        to: '/demo/architecture',
      },
      {
        title: 'Scenarios',
        description: 'Follow governed enterprise cases.',
        to: '/demo/scenarios',
      },
      {
        title: 'Labs',
        description: 'Inspect individual controls and evidence.',
        to: '/demo/labs',
      },
    ],
    faqLead: 'Need a direct answer?',
    faqLabel: 'Read the FAQ',
    faqTo: '/faq',
  },
} as const

export const placeholderCopy = {
  scenarios: {
    eyebrow: 'Demo',
    title: 'Scenarios',
    description:
      'The scenario route is ready. The Atlas Travel, Northstar Health, and Meridian Finance roleplays arrive in the next demo build.',
  },
  labs: {
    eyebrow: 'Demo',
    title: 'Labs',
    description:
      'The grouped lab index arrives in the next demo build. Existing lab deep links remain available.',
  },
  faq: {
    eyebrow: 'Public guide',
    title: 'FAQ',
    description:
      'The public FAQ arrives in the next demo build. Architecture and existing labs remain available now.',
  },
} as const
