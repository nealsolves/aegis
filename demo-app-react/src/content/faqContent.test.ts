const RENDER_COLD_START_COPY = (
  'Starting the demo API. Render may need about a minute after a period of inactivity.'
)

describe('faqContent ownership', () => {
  afterEach(() => {
    vi.doUnmock('@/content/demoCopy')
    vi.resetModules()
  })

  it('owns its public Render prose without loading generic demo copy', async () => {
    vi.resetModules()
    vi.doMock('@/content/demoCopy', () => {
      throw new Error('FAQ content must not load public prose from demoCopy')
    })

    const { faqCategories } = await import('@/content/faqContent')
    const renderAnswer = faqCategories
      .flatMap(category => category.items)
      .find(item => item.id === 'render-unavailable')

    expect(renderAnswer?.answer).toContainEqual({
      type: 'paragraph',
      text: RENDER_COLD_START_COPY,
    })
  })
})
