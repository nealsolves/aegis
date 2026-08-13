export type ScenarioId = 'atlas' | 'northstar' | 'meridian'

export interface ScenarioContent {
  id: ScenarioId
  title: string
  visitorRole: string
  incident: string
  setup: readonly { label: string; title: string; text: string; tone?: string }[]
  choices: readonly { id: string; label: string; consequence?: string }[]
  variants: readonly (string | null)[]
  interactionMode?: 'judgment' | 'agentic_comparison'
  boundary?: { title: string; text: string }
  sources?: readonly { label: string; href: string }[]
}

export const SCENARIO_CONTENT: Record<ScenarioId, ScenarioContent> = {
  atlas: {
    id: 'atlas',
    title: 'A confident answer can still be wrong',
    visitorRole:
      'You lead customer support at Atlas Travel. An AI-written answer is waiting for your decision.',
    incident:
      'A traveler asks whether the storm policy covers a missed connection. Atlas AI says yes. The company policy says no for this situation under rule BRV-04. Without runtime governance, the confident but wrong answer can reach the traveler and cost Atlas Travel money.',
    setup: [
      {
        label: 'Traveler',
        title: 'A simple coverage question',
        text: 'Does the storm policy cover my missed connection?',
      },
      {
        label: 'Atlas AI Assistant',
        title: 'A confident answer',
        text: 'Yes. The storm policy covers your missed connection.',
        tone: 'warning',
      },
      {
        label: 'Policy manual',
        title: 'The documented rule says no',
        text: 'BRV-04 says this missed connection is not covered. The rule only protects the decision when it is encoded and enforced at runtime.',
        tone: 'policy',
      },
      {
        label: 'Customer-support lead',
        title: 'The draft is waiting',
        text: 'Do you pause for a policy check, or send the confident answer as written?',
      },
    ],
    choices: [
      {
        id: 'atlas-pause',
        label: 'Pause and let AEGIS check the answer',
      },
      {
        id: 'atlas-send',
        label: 'Send the answer as written',
      },
    ],
    variants: ['first_attempt', 'first_attempt'],
  },
  northstar: {
    id: 'northstar',
    title: 'Northstar clinic scheduling',
    visitorRole:
      'You coordinate scheduling at fictional Northstar Clinic. Your judgment determines which role may view the record and whether clinical review is recorded before scheduling proceeds.',
    incident:
      'A scheduling workflow for fictional record NS-204 asks for clinical details outside its assigned scheduling scope. The appointment still needs a useful, limited summary. This case is wholly fictional.',
    setup: [
      { label: 'Request', title: 'Prepare a scheduling summary', text: 'The clinic needs a useful summary for record NS-204.' },
      { label: 'Boundary', title: 'Scheduling is not clinical care', text: 'The scheduling role requests clinical detail outside its assigned scope.', tone: 'warning' },
      { label: 'Review', title: 'Clinical judgment needs approval', text: 'An authorized nurse and physician approval keep the final summary scheduling-only.', tone: 'policy' },
    ],
    choices: [
      {
        id: 'northstar-first',
        label: 'Keep the scheduling role and allow access to clinical details',
      },
      {
        id: 'northstar-authorized',
        label: 'Retry with the authorized nurse role',
      },
      {
        id: 'northstar-corrected',
        label: 'Record physician approval and keep the summary scheduling-only',
      },
    ],
    variants: ['first_attempt', 'authorized_retry', 'corrected'],
  },
  meridian: {
    id: 'meridian',
    title: 'Can an AI assistant authorize this payment?',
    visitorRole:
      'Meridian AI Assistant operates autonomously. No person reviews or approves its decision in this flow.',
    incident:
      'Meridian AI Assistant receives invoice MV-248 and attempts to authorize payment. The agent has not completed the required vendor verification and risk review.',
    setup: [
      { label: 'Invoice', title: 'MV-248 enters the agentic workflow', text: 'Meridian AI Assistant receives the invoice and decides what to do next.' },
      { label: 'AI action', title: 'The assistant authorizes payment', text: 'The autonomous agent attempts to authorize payment without completing the required checks.', tone: 'warning' },
      { label: 'Without AEGIS', title: 'Payment authorized', text: 'No policy-based governance evaluates the action before execution.', tone: 'warning' },
      { label: 'With AEGIS', title: 'Unauthorized payment blocked', text: 'AEGIS enforces the payment policy during runtime and stops the action before execution.', tone: 'policy' },
    ],
    choices: [],
    variants: ['first_attempt'],
    interactionMode: 'agentic_comparison',
    boundary: {
      title: 'AEGIS governs the action before execution.',
      text: 'The AI assistant attempts the payment action autonomously. AEGIS independently evaluates the runtime policy and blocks the unauthorized action before it reaches the payment system.',
    },
  },
}

export const SCENARIO_ORDER: readonly ScenarioId[] = [
  'atlas',
  'northstar',
  'meridian',
]

export function isScenarioId(value: string | undefined): value is ScenarioId {
  return value !== undefined
    && SCENARIO_ORDER.some((scenarioId) => scenarioId === value)
}
