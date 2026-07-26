export type ScenarioId = 'atlas' | 'northstar' | 'meridian'

export interface ScenarioContent {
  id: ScenarioId
  title: string
  visitorRole: string
  incident: string
  choices: readonly { id: string; label: string }[]
  variants: readonly string[]
  sources?: readonly { label: string; href: string }[]
}

export const SCENARIO_CONTENT: Record<ScenarioId, ScenarioContent> = {
  atlas: {
    id: 'atlas',
    title: 'Atlas travel support',
    visitorRole:
      'You oversee support operations at fictional Atlas Travel Desk. Your judgment determines what guidance may be returned to the traveler.',
    incident:
      'A traveler relied on inaccurate guidance about a fictional compassionate travel credit. A 2024 tribunal decision about inaccurate chatbot guidance on bereavement fares inspired this high-level pattern. Every actor, policy, amount, and event in this case is invented.',
    choices: [
      {
        id: 'atlas-first',
        label: 'Send the prepared guidance without attaching a policy source',
      },
      {
        id: 'atlas-corrected',
        label: 'Attach the supplied policy source and retry the review',
      },
    ],
    variants: ['first_attempt', 'corrected'],
    sources: [
      {
        label: 'Civil Resolution Tribunal decision',
        href: 'https://decisions.civilresolutionbc.ca/crt/crtd/en/item/525448/index.do',
      },
    ],
  },
  northstar: {
    id: 'northstar',
    title: 'Northstar clinic scheduling',
    visitorRole:
      'You coordinate scheduling at fictional Northstar Clinic. Your judgment determines which role may view the record and whether clinical review is recorded before scheduling proceeds.',
    incident:
      'A scheduling workflow for fictional record NS-204 asks for clinical details outside its assigned scheduling scope. The appointment still needs a useful, limited summary. This case is wholly fictional.',
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
    title: 'Meridian invoice review',
    visitorRole:
      'You lead accounts payable at fictional Meridian Services. Your judgment determines whether invoice MV-248 follows the required review order before any payment record is prepared.',
    incident:
      'The workflow has recorded the invoice and now requests payment preparation before vendor verification and risk review. No money moves in this deterministic case. This case is wholly fictional.',
    choices: [
      {
        id: 'meridian-first',
        label: 'Prepare the payment record before vendor verification',
      },
      {
        id: 'meridian-corrected',
        label: 'Restart and follow the required review order',
      },
    ],
    variants: ['first_attempt', 'corrected'],
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
