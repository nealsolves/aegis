import { helpContent } from './helpContent'

function guideText(labId: number) {
  const guide = helpContent[labId]
  return [
    guide.title,
    guide.overview,
    guide.whyItMatters,
    guide.whatThisLabShows.join(' '),
    guide.howToNavigate.join(' '),
    guide.steps.map(step => `${step.title} ${step.instruction} ${step.tip ?? ''}`).join(' '),
    guide.takeaway,
    (guide.glossary ?? []).map(entry => `${entry.term} ${entry.definition}`).join(' '),
  ].join(' ')
}

describe('helpContent', () => {
  it('has an architecture entry and entries for all 11 labs', () => {
    expect(helpContent[0]).toBeDefined()
    for (let i = 1; i <= 11; i++) {
      expect(helpContent[i]).toBeDefined()
    }
  })

  it('every guide has a non-empty title, overview, whyItMatters, and takeaway', () => {
    for (let i = 0; i <= 11; i++) {
      expect(helpContent[i].title.length).toBeGreaterThan(0)
      expect(helpContent[i].overview.length).toBeGreaterThan(0)
      expect(helpContent[i].whyItMatters.length).toBeGreaterThan(0)
      expect(helpContent[i].takeaway.length).toBeGreaterThan(0)
    }
  })

  it('every guide has at least 3 steps', () => {
    for (let i = 0; i <= 11; i++) {
      expect(helpContent[i].steps.length).toBeGreaterThanOrEqual(3)
    }
  })

  it('every guide has framework sections for learning and navigation', () => {
    for (let i = 0; i <= 11; i++) {
      expect(helpContent[i].whatThisLabShows.length).toBeGreaterThanOrEqual(2)
      expect(helpContent[i].howToNavigate.length).toBeGreaterThanOrEqual(2)
    }
  })

  it('every step has a non-empty title and instruction', () => {
    for (let i = 0; i <= 11; i++) {
      for (const step of helpContent[i].steps) {
        expect(step.title.length).toBeGreaterThan(0)
        expect(step.instruction.length).toBeGreaterThan(0)
      }
    }
  })

  // Fidelity tests — catch content drift between help drawer and actual UI

  it('architecture overview does not claim signing is always present', () => {
    const overview = helpContent[0].overview
    expect(overview).not.toMatch(/signed audit record regardless/i)
    // Signing should be described as opt-in
    expect(overview).toMatch(/opt-in/i)
  })

  it('architecture pipeline step includes pre_output gates', () => {
    const pipelineStep = helpContent[0].steps.find(s => s.title.toLowerCase().includes('pipeline'))
    expect(pipelineStep).toBeDefined()
    expect(pipelineStep!.instruction).toMatch(/pre_output/i)
  })

  it('architecture framework explains that AEGIS is a runtime governance layer', () => {
    expect(helpContent[0].overview).toMatch(/runtime governance layer/i)
    expect(helpContent[0].takeaway).toMatch(/deterministic governance wrapper/i)
  })

  it('architecture guide names the v0.9 candidate and current ownership boundaries', () => {
    const content = guideText(0)
    for (const expected of [
      'aegis-ai-governance==0.9.0b1',
      'host owns',
      'GovernanceSession',
      'invocation artifact',
      'workflow artifact',
      'Bedrock',
      'A2A',
      'OpenAI Agents',
      'submodule',
    ]) {
      expect(content).toContain(expected)
    }
  })

  it('keeps each lab guide aligned with exact visible controls', () => {
    const exactLabels: Record<number, string[]> = {
      1: ['Preset Scenario', 'Risk Mode', 'Enforcement Flow', 'Run Enforcement →'],
      2: ['Generate', 'Sign Artifact →', 'tamper payload', 'Verify'],
      3: ['+ Entry 1', 'Verify Chain', 'reset', 'Export Chain (JSON)'],
      4: ['intersect', 'union', 'replace', 'Merge →'],
      5: ['Loaders', 'Versioning', 'Testing', 'FileSystem', 'InMemory', 'Load →', 'Parse →', 'Validate Dates →', 'Run Tests →'],
      6: ['Select Gate', 'Authorized Session', 'Run Gate →'],
      7: ['Load Sample Data', 'JSON', 'CSV', 'aegis compliance export'],
      8: ['Single source (pass)', 'Unsourced (fail)', 'Multi-source (pass)', 'Run KB Query'],
      9: ['Low risk (governed PASS)', 'High risk (governed FAIL)', 'Compare'],
      10: ['Low risk (both phases pass)', 'Pre-call block (Phase A fails)', 'Run Split Trace'],
      11: ['Start Here', 'Run Minimal', 'Failure & Fix', 'workflow doctor', 'Build Evidence Trace', 'workflow trace'],
    }

    for (const [labId, labels] of Object.entries(exactLabels)) {
      const content = guideText(Number(labId))
      for (const label of labels) {
        expect(content).toContain(label)
      }
    }
  })

  it('lab 1 framework keeps risk modes and threshold behavior explicit', () => {
    const content = [
      helpContent[1].overview,
      helpContent[1].whyItMatters,
      helpContent[1].whatThisLabShows.join(' '),
      helpContent[1].howToNavigate.join(' '),
      helpContent[1].steps.map(s => s.instruction + (s.tip ?? '')).join(' '),
    ].join(' ')
    expect(content).toMatch(/strict/i)
    expect(content).toMatch(/risk_scored/i)
    expect(content).toMatch(/warn_only/i)
    expect(content).toMatch(/0\.70|0.7/i)
  })

  it('lab 4 glossary uses intersect, union, replace — not merge/override/strict strategy', () => {
    const glossary = helpContent[4].glossary ?? []
    const terms = glossary.map(g => g.term.toLowerCase())
    expect(terms).toContain('intersect')
    expect(terms).toContain('union')
    expect(terms).toContain('replace')
    expect(terms).not.toContain('merge strategy')
    expect(terms).not.toContain('override strategy')
    expect(terms).not.toContain('strict strategy')
  })

  it('lab 5 steps do not mention EnvLoader or RegistryLoader', () => {
    const content = helpContent[5].steps.map(s => s.instruction + (s.tip ?? '')).join(' ')
    const glossaryTerms = (helpContent[5].glossary ?? []).map(g => g.term).join(' ')
    expect(content + glossaryTerms).not.toMatch(/EnvLoader/i)
    expect(content + glossaryTerms).not.toMatch(/RegistryLoader/i)
  })

  it('lab 5 glossary includes FilePolicyLoader and InMemoryPolicyLoader', () => {
    const terms = (helpContent[5].glossary ?? []).map(g => g.term)
    expect(terms.some(t => t.toLowerCase().includes('filepolicyloader'))).toBe(true)
    expect(terms.some(t => t.toLowerCase().includes('inmemorypolicyloader') || t.toLowerCase().includes('inmemoryloader'))).toBe(true)
  })

  it('lab 5 navigation references the current tab names', () => {
    const content = helpContent[5].howToNavigate.join(' ')
    expect(content).toMatch(/Loaders/i)
    expect(content).toMatch(/Versioning/i)
    expect(content).toMatch(/Testing/i)
  })

  it('lab 6 steps do not claim different sets of gates per scenario', () => {
    const content = helpContent[6].steps.map(s => s.instruction + (s.tip ?? '')).join(' ')
    expect(content).not.toMatch(/different set.*gate/i)
  })

  it('lab 6 glossary includes gates_evaluated', () => {
    const terms = (helpContent[6].glossary ?? []).map(g => g.term.toLowerCase())
    expect(terms).toContain('gates_evaluated')
  })

  it('lab 6 framework names all four supported insertion points', () => {
    const content = [
      helpContent[6].overview,
      helpContent[6].whatThisLabShows.join(' '),
      helpContent[6].steps.map(s => s.instruction + (s.tip ?? '')).join(' '),
    ].join(' ')
    expect(content).toMatch(/pre_authorization/i)
    expect(content).toMatch(/post_authorization/i)
    expect(content).toMatch(/pre_output/i)
    expect(content).toMatch(/post_output/i)
  })

  it('lab 7 describes sample mode as an explicit action, not silent default', () => {
    const content = [
      helpContent[7].overview,
      helpContent[7].whatThisLabShows.join(' '),
      helpContent[7].steps.map(s => s.instruction + (s.tip ?? '')).join(' '),
    ].join(' ')
    // Must mention explicit loading of sample data
    expect(content).toMatch(/load sample data/i)
    // Must not imply it is the default or silent
    expect(content).not.toMatch(/silently/i)
  })

  it('lab 7 does not claim signed indicator proves verification', () => {
    const content = helpContent[7].steps.map(s => s.instruction + (s.tip ?? '')).join(' ')
    const glossary = (helpContent[7].glossary ?? []).map(g => g.definition).join(' ')
    expect(content + glossary).not.toMatch(/valid hmac signature/i)
  })

  it('lab 7 framework mentions both UI export formats and the CLI handoff', () => {
    const content = [
      helpContent[7].whatThisLabShows.join(' '),
      helpContent[7].howToNavigate.join(' '),
      helpContent[7].steps.map(s => s.instruction + (s.tip ?? '')).join(' '),
    ].join(' ')
    expect(content).toMatch(/JSON/i)
    expect(content).toMatch(/CSV/i)
    expect(content).toMatch(/aegis compliance export/i)
  })

  it('labs 8-11 keep the newer guides aligned with the established guide naming and depth', () => {
    for (const labId of [8, 9, 10, 11] as const) {
      expect(helpContent[labId].title).toMatch(/Guide$/)
      expect(helpContent[labId].steps.length).toBeGreaterThanOrEqual(4)
      expect((helpContent[labId].glossary ?? []).length).toBeGreaterThanOrEqual(3)
    }
  })

  it('lab 8 guide uses the current knowledge-base labels and provenance cues', () => {
    const content = [
      helpContent[8].overview,
      helpContent[8].howToNavigate.join(' '),
      helpContent[8].steps.map(s => s.title + ' ' + s.instruction + ' ' + (s.tip ?? '')).join(' '),
      (helpContent[8].glossary ?? []).map(g => `${g.term} ${g.definition}`).join(' '),
    ].join(' ')
    expect(content).toMatch(/Run KB Query/i)
    expect(content).toMatch(/Single source \(pass\)/i)
    expect(content).toMatch(/Unsourced \(fail\)/i)
    expect(content).toMatch(/Multi-source \(pass\)/i)
    expect(content).toMatch(/source IDs/i)
    expect(content).toMatch(/custom:provenance_gate/i)
  })

  it('lab 9 guide stays aligned with the side-by-side metadata UI', () => {
    const content = [
      helpContent[9].overview,
      helpContent[9].howToNavigate.join(' '),
      helpContent[9].steps.map(s => s.title + ' ' + s.instruction + ' ' + (s.tip ?? '')).join(' '),
      (helpContent[9].glossary ?? []).map(g => `${g.term} ${g.definition}`).join(' '),
    ].join(' ')
    expect(content).toMatch(/Compare/i)
    expect(content).toMatch(/metadata\.mode/i)
    expect(content).toMatch(/gates_evaluated/i)
    expect(content).toMatch(/risk_scoring/i)
    expect(content).not.toMatch(/Expand both raw artifacts/i)
  })

  it('lab 10 guide uses the current split explorer labels and enforcement mode language', () => {
    const content = [
      helpContent[10].overview,
      helpContent[10].howToNavigate.join(' '),
      helpContent[10].steps.map(s => s.title + ' ' + s.instruction + ' ' + (s.tip ?? '')).join(' '),
      (helpContent[10].glossary ?? []).map(g => `${g.term} ${g.definition}`).join(' '),
    ].join(' ')
    expect(content).toMatch(/Run Split Trace/i)
    expect(content).toMatch(/Low risk \(both phases pass\)/i)
    expect(content).toMatch(/Pre-call block \(Phase A fails\)/i)
    expect(content).toMatch(/split_pre_call_only/i)
    expect(content).toMatch(/enforcement_mode/i)
    expect(content).not.toMatch(/Low risk \(full pass\)/i)
  })

  it('lab 11 guide covers workflow diagnosis and trace evidence', () => {
    const content = [
      helpContent[11].overview,
      helpContent[11].howToNavigate.join(' '),
      helpContent[11].steps.map(s => s.title + ' ' + s.instruction + ' ' + (s.tip ?? '')).join(' '),
      (helpContent[11].glossary ?? []).map(g => `${g.term} ${g.definition}`).join(' '),
    ].join(' ')
    expect(content).toMatch(/Run Minimal/i)
    expect(content).toMatch(/Failure & Fix/i)
    expect(content).toMatch(/workflow doctor/i)
    expect(content).toMatch(/Build Evidence Trace/i)
    expect(content).toMatch(/workflow trace/i)
  })

  it('architecture content explains split default mode and unified opt-out', () => {
    const content = [
      helpContent[0].overview,
      helpContent[0].whatThisLabShows.join(' '),
      helpContent[0].steps.map(s => s.instruction + (s.tip ?? '')).join(' '),
      (helpContent[0].glossary ?? []).map(g => `${g.term} ${g.definition}`).join(' '),
    ].join(' ')
    expect(content).toMatch(/split enforcement.*default/i)
    expect(content).toMatch(/pre_call_enforcement=False.*unified/i)
  })
})
