import {
  FIRST_VISIT_LABS,
  LABS,
  LAB_GROUPS,
  getLabById,
  getLabGroup,
} from './labCatalog'

describe('labCatalog', () => {
  it('contains every stable lab route exactly once', () => {
    expect(LABS.map(lab => lab.id)).toEqual(
      Array.from({ length: 12 }, (_, index) => index + 1),
    )
    expect(new Set(LABS.map(lab => lab.id)).size).toBe(12)
    expect(LABS.map(lab => lab.path)).toEqual(
      Array.from({ length: 12 }, (_, index) => `/lab/${index + 1}`),
    )
  })

  it('groups every lab in the approved capability order', () => {
    expect(LAB_GROUPS.map(group => [group.title, group.question, group.labIds]))
      .toEqual([
        ['Decisions', 'What should happen?', [9, 10, 1]],
        ['Policies and gates', 'Which rules apply?', [4, 5, 6]],
        ['Evidence', 'What can you prove?', [2, 3, 7]],
        ['Systems and workflows', 'How does it connect?', [8, 11, 12]],
      ])
  })

  it('defines the approved number-free first-visit journey', () => {
    expect(
      FIRST_VISIT_LABS.map(lab => [
        lab.id,
        lab.journey?.phase,
        lab.journey?.action,
      ]),
    ).toEqual([
      [9, 'Request', 'Compare enforcement'],
      [10, 'Boundary', 'Explore checkpoints'],
      [11, 'Workflow', 'Govern the handoff'],
    ])
  })

  it('keeps visitor-facing catalog strings free of Lab N labels', () => {
    const publicCopy = [
      ...LABS.flatMap(lab => [
        lab.title,
        lab.heroTitle,
        lab.eyebrow,
        lab.description,
        lab.journey?.phase ?? '',
        lab.journey?.action ?? '',
      ]),
      ...LAB_GROUPS.flatMap(group => [
        group.title,
        group.question,
        group.description,
      ]),
    ].join(' ')

    expect(publicCopy).not.toMatch(/\bLab\s+\d+\b/)
  })

  it('resolves labs and groups through typed lookup helpers', () => {
    expect(getLabById(9)?.heroTitle).toBe('Governed vs. Ungoverned')
    expect(getLabById(99)).toBeUndefined()
    expect(getLabGroup('systems-workflows').labIds).toEqual([8, 11, 12])
  })
})
