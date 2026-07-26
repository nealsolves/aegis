export type LabCapabilityId =
  | 'decisions'
  | 'policies-gates'
  | 'evidence'
  | 'systems-workflows'

export interface LabJourney {
  order: number
  phase: 'Request' | 'Boundary' | 'Workflow'
  action: string
}

export interface LabMeta {
  id: number
  path: string
  title: string
  shortTitle: string
  heroTitle: string
  capability: LabCapabilityId
  eyebrow: string
  description: string
  journey?: LabJourney
}

export interface LabCapabilityGroup {
  id: LabCapabilityId
  title: string
  question: string
  description: string
  labIds: readonly number[]
}

export const LABS: readonly LabMeta[] = [
  {
    id: 1,
    path: '/lab/1',
    title: 'Risk Scoring',
    shortTitle: 'Risk',
    heroTitle: 'Risk Scoring',
    capability: 'decisions',
    eyebrow: 'Decision signal',
    description:
      'See how invocation signals produce a risk score and change enforcement.',
  },
  {
    id: 2,
    path: '/lab/2',
    title: 'Signing and Verification',
    shortTitle: 'Sign',
    heroTitle: 'Signing and Verification',
    capability: 'evidence',
    eyebrow: 'Evidence integrity',
    description:
      'Sign a governance artifact, verify it, and inspect what changes when the record is altered.',
  },
  {
    id: 3,
    path: '/lab/3',
    title: 'Audit Chain',
    shortTitle: 'Chain',
    heroTitle: 'Audit Chain',
    capability: 'evidence',
    eyebrow: 'Evidence history',
    description:
      'Link governance records into an ordered history and verify the chain.',
  },
  {
    id: 4,
    path: '/lab/4',
    title: 'Policy Composition',
    shortTitle: 'Compose',
    heroTitle: 'Policy Composition',
    capability: 'policies-gates',
    eyebrow: 'Policy construction',
    description:
      'Combine policy sources and inspect the rules applied at the boundary.',
  },
  {
    id: 5,
    path: '/lab/5',
    title: 'Loaders and Versioning',
    shortTitle: 'Loaders',
    heroTitle: 'Loaders and Versioning',
    capability: 'policies-gates',
    eyebrow: 'Policy lifecycle',
    description:
      'Load policy definitions and see how versions remain visible in governance evidence.',
  },
  {
    id: 6,
    path: '/lab/6',
    title: 'Custom Gates',
    shortTitle: 'Gates',
    heroTitle: 'Custom Gates',
    capability: 'policies-gates',
    eyebrow: 'Policy extension',
    description:
      'Add a focused governance check and inspect how it changes the decision.',
  },
  {
    id: 7,
    path: '/lab/7',
    title: 'Compliance Dashboard',
    shortTitle: 'Comply',
    heroTitle: 'Compliance Dashboard',
    capability: 'evidence',
    eyebrow: 'Operator evidence',
    description:
      'Review governance records as an operator and inspect the evidence behind each status.',
  },
  {
    id: 8,
    path: '/lab/8',
    title: 'Governed Knowledge Base',
    shortTitle: 'Knowledge base',
    heroTitle: 'Governed Knowledge Base',
    capability: 'systems-workflows',
    eyebrow: 'Governed retrieval',
    description:
      'Apply policy to retrieval and inspect the evidence returned with the knowledge result.',
  },
  {
    id: 9,
    path: '/lab/9',
    title: 'Governed vs. Ungoverned',
    shortTitle: 'Compare',
    heroTitle: 'Governed vs. Ungoverned',
    capability: 'decisions',
    eyebrow: 'Decision boundary',
    description:
      'Run the same request with and without policy enforcement, then compare the outcomes and evidence.',
    journey: { order: 1, phase: 'Request', action: 'Compare enforcement' },
  },
  {
    id: 10,
    path: '/lab/10',
    title: 'Split Enforcement',
    shortTitle: 'Split',
    heroTitle: 'Split Enforcement Explorer',
    capability: 'decisions',
    eyebrow: 'Enforcement boundary',
    description:
      'Inspect the checks before an AI call and the checks applied after a result returns.',
    journey: { order: 2, phase: 'Boundary', action: 'Explore checkpoints' },
  },
  {
    id: 11,
    path: '/lab/11',
    title: 'Workflow Governance',
    shortTitle: 'Workflow',
    heroTitle: 'Workflow Governance',
    capability: 'systems-workflows',
    eyebrow: 'Workflow boundary',
    description:
      'Govern participants, transitions, approvals, and evidence across a multi-step session.',
    journey: { order: 3, phase: 'Workflow', action: 'Govern the handoff' },
  },
  {
    id: 12,
    path: '/lab/12',
    title: 'Integration Adapters',
    shortTitle: 'Adapters',
    heroTitle: 'Integration Adapters',
    capability: 'systems-workflows',
    eyebrow: 'Provider boundary',
    description:
      'Inspect how supported adapters normalize provider and protocol evidence for governance.',
  },
]

export const LAB_GROUPS: readonly LabCapabilityGroup[] = [
  {
    id: 'decisions',
    title: 'Decisions',
    question: 'What should happen?',
    description: 'Compare judgments and see where enforcement changes an AI call.',
    labIds: [9, 10, 1],
  },
  {
    id: 'policies-gates',
    title: 'Policies and gates',
    question: 'Which rules apply?',
    description: 'Build, load, and extend the rules applied at the governance boundary.',
    labIds: [4, 5, 6],
  },
  {
    id: 'evidence',
    title: 'Evidence',
    question: 'What can you prove?',
    description: 'Inspect integrity, audit history, and operator-facing records.',
    labIds: [2, 3, 7],
  },
  {
    id: 'systems-workflows',
    title: 'Systems and workflows',
    question: 'How does it connect?',
    description: 'Govern retrieval, multi-step sessions, and adapter-normalized evidence.',
    labIds: [8, 11, 12],
  },
]

export const LABS_BY_ID = Object.freeze(
  Object.fromEntries(LABS.map(lab => [lab.id, lab])),
) as Readonly<Record<number, LabMeta>>

export const FIRST_VISIT_LABS: readonly LabMeta[] = Object.freeze(
  LABS
    .filter(lab => lab.journey !== undefined)
    .sort((left, right) => left.journey!.order - right.journey!.order),
)

export function getLabById(id: number): LabMeta | undefined {
  return LABS_BY_ID[id]
}

export function getLabGroup(
  capability: LabCapabilityId,
): LabCapabilityGroup {
  const group = LAB_GROUPS.find(candidate => candidate.id === capability)
  if (!group) {
    throw new Error(`Unknown lab capability: ${capability}`)
  }
  return group
}
