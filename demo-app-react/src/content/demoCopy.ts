export const publicNavCopy = {
  ariaLabel: 'Primary navigation',
  brand: 'AEGIS',
  brandLabel: 'AEGIS home',
  descriptor: 'policy checkpoints',
  links: [
    { label: 'What it does', to: '/#what-it-does', emphasis: false },
    { label: 'Install', to: '/#install', emphasis: false },
    { label: 'Open demo', to: '/demo/architecture', emphasis: true },
    { label: 'FAQ', to: '/faq', emphasis: false },
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

export const labRoutesCopy = [
  { num: 1, title: 'Risk Scoring', short: 'Risk', heroTitle: 'Risk Scoring' },
  { num: 2, title: 'Signing', short: 'Sign', heroTitle: 'Signing & Verification' },
  { num: 3, title: 'Audit Chain', short: 'Chain', heroTitle: 'Audit Chain' },
  { num: 4, title: 'Composition', short: 'Compose', heroTitle: 'Policy Composition' },
  { num: 5, title: 'Loaders', short: 'Loaders', heroTitle: 'Loaders & Versioning' },
  { num: 6, title: 'Custom Gates', short: 'Gates', heroTitle: 'Custom Gates' },
  { num: 7, title: 'Compliance', short: 'Comply', heroTitle: 'Compliance Dashboard' },
  {
    num: 8,
    title: 'Knowledge Base',
    short: 'KB',
    heroTitle: 'Governed Knowledge Base',
  },
  {
    num: 9,
    title: 'Governed vs Ungoverned',
    short: 'Compare',
    heroTitle: 'Governed vs. Ungoverned',
  },
  {
    num: 10,
    title: 'Split Enforcement',
    short: 'Split',
    heroTitle: 'Split Enforcement Explorer',
  },
  {
    num: 11,
    title: 'Workflow Lab (v0.9.0 Beta)',
    short: 'Workflow',
    heroTitle: 'Workflow Governance (v0.9.0 Beta)',
  },
] as const

export const labNavCopy = {
  ariaLabel: 'Lab navigation',
} as const

export const introCopy = {
  hero: {
    eyebrow: 'Policy checkpoints for AI calls and agent workflows',
    title: 'Put policy between the request and the result.',
    lead:
      'AEGIS checks an AI call before it runs and checks the result before your application uses it. Your policy decides who may act, which tools are allowed, what output is acceptable, and when a person must approve.',
    workflow:
      'AEGIS governs participants, step order, handoffs, approvals, budgets, and session lifecycle.',
    host:
      'Your application or agent framework still executes the agents, model calls, and tools.',
    actions: [
      { label: 'See the demo', to: '/demo/architecture', emphasis: true },
      { label: 'Install AEGIS', to: '/#install', emphasis: false },
    ],
    callFlowLabel: 'One governed call',
    callFlow: [
      {
        owner: 'Host application',
        title: 'Prepare the request',
        detail: 'The host supplies the prompt, role, policy, and context.',
        kind: 'host',
      },
      {
        owner: 'AEGIS pre-call check',
        title: 'Allow, block, or pause',
        detail: 'Policy is applied before the model or tool runs.',
        kind: 'policy',
      },
      {
        owner: 'Host application',
        title: 'Execute the model or tool',
        detail: 'The host keeps its provider client, credentials, retries, and business state.',
        kind: 'host-owned',
      },
      {
        owner: 'AEGIS post-call check',
        title: 'Accept or reject the output',
        detail: 'Output rules run before the host application uses the result.',
        kind: 'policy',
      },
      {
        owner: 'Evidence',
        title: 'Record the decision',
        detail: 'The artifact includes reason codes, policy version, checksums, and workflow context.',
        kind: 'evidence',
      },
    ],
  },
  ownership: {
    id: 'what-it-does',
    eyebrow: 'Ownership boundary',
    title: 'Your application runs the work. AEGIS applies the checkpoints.',
    intro:
      'The boundary remains explicit for one model call and for a multi-step agent workflow.',
    areas: [
      {
        title: 'Your application',
        detail:
          'Orchestration, provider clients, credentials, retries, model calls, tool execution, and business state.',
      },
      {
        title: 'AEGIS',
        detail:
          'Policies, roles, participants, transitions, handoffs, approvals, budgets, output rules, lifecycle, and risk treatment.',
      },
      {
        title: 'Evidence',
        detail:
          'Separate invocation and workflow artifacts, with trace and export for operator review.',
      },
    ],
  },
  comparison: {
    eyebrow: 'External governance evidence',
    title: 'Use each record for the job it can support.',
    intro:
      'A model thought trace can help with debugging and behavioral inspection. An external governance record applies policy and records the resulting decision.',
    columns: [
      {
        title: 'Model thought trace: useful for inspection',
        items: [
          'Generated by the model being inspected.',
          'Useful for debugging and behavioral inspection.',
          'May omit an influence or produce a plausible account after the fact.',
          'Cannot independently stop an unauthorized action before execution.',
          'Does not prove which company policy was applied.',
        ],
      },
      {
        title: 'AEGIS governance record: produced outside the model',
        items: [
          'Generated outside the model.',
          'Tied to a versioned policy and ordered checks.',
          'May stop a request before the model or tool runs.',
          'May reject output before the host application uses it.',
          'Records the decision, reason codes, checksums, policy metadata, and workflow context.',
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
    title: 'Add AEGIS around the call you already own.',
    intro:
      'Run one check before execution and one after. The host model call stays visible between the policy checkpoints.',
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
  entries: {
    eyebrow: 'Explore the demo',
    title: 'Choose where to start',
    regionLabel: 'Choose where to start',
    intro:
      'Start with the product boundary, follow a governed case, or inspect one control at a time.',
    cards: [
      {
        title: 'Architecture',
        description: 'See ownership and technical maps.',
        to: '/demo/architecture',
      },
      {
        title: 'Scenarios',
        description: 'Work through three roleplay cases.',
        to: '/demo/scenarios',
      },
      {
        title: 'Labs',
        description: 'Use isolated controls with route-specific help.',
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
