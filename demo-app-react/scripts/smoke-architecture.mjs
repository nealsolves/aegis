#!/usr/bin/env node
import { chromium } from 'playwright'
import { pathToFileURL } from 'node:url'

function parseArguments(argv) {
  const options = {
    frontendUrl: '',
    expectedApiOrigin: '',
    timeoutMs: 15_000,
    viewports: [],
  }

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index]
    const value = argv[index + 1]
    if (argument === '--frontend-url' && value) {
      options.frontendUrl = value
      index += 1
    } else if (argument === '--expected-api-origin' && value) {
      options.expectedApiOrigin = value
      index += 1
    } else if (argument === '--timeout-ms' && value) {
      options.timeoutMs = Number(value)
      index += 1
    } else if (argument === '--viewport' && value) {
      const [name, width, height] = value.split(':')
      options.viewports.push({
        name,
        width: Number(width),
        height: Number(height),
      })
      index += 1
    } else {
      throw new Error(`Unknown or incomplete argument: ${argument}`)
    }
  }

  if (!options.frontendUrl) {
    throw new Error('--frontend-url is required')
  }
  if (!options.expectedApiOrigin) {
    throw new Error('--expected-api-origin is required')
  }
  try {
    options.expectedApiOrigin = new URL(options.expectedApiOrigin).origin
  } catch {
    throw new Error('--expected-api-origin must be an absolute URL')
  }
  if (!Number.isFinite(options.timeoutMs) || options.timeoutMs <= 0) {
    throw new Error('--timeout-ms must be a positive finite number')
  }
  if (
    options.viewports.length === 0
    || options.viewports.some(
      ({ name, width, height }) => (
        !name
        || !Number.isInteger(width)
        || width <= 0
        || !Number.isInteger(height)
        || height <= 0
      ),
    )
  ) {
    throw new Error('At least one valid --viewport name:width:height is required')
  }

  return options
}

export function assertExpectedApiResponses(
  responses,
  expectedApiOrigin,
  viewportName,
) {
  const expectedOrigin = new URL(expectedApiOrigin).origin
  const expectedPaths = ['/health', '/api/demo/manifest']

  for (const expectedPath of expectedPaths) {
    const response = responses.find((candidate) => (
      new URL(candidate.url).pathname === expectedPath
    ))
    if (!response) {
      throw new Error(
        `${viewportName}: browser did not request ${expectedPath}`,
      )
    }
    const responseUrl = new URL(response.url)
    if (responseUrl.origin !== expectedOrigin) {
      throw new Error(
        `${viewportName}: expected API origin ${expectedOrigin}; `
        + `${expectedPath} used ${responseUrl.origin}`,
      )
    }
    if (response.status !== 200) {
      throw new Error(
        `${viewportName}: ${expectedPath} returned HTTP ${response.status}`,
      )
    }
    if (response.body?.api_contract_version !== '1') {
      throw new Error(
        `${viewportName}: ${expectedPath} did not return contract 1`,
      )
    }
  }
}

function rectanglesIntersect(first, second) {
  return (
    first.left < second.right
    && first.right > second.left
    && first.top < second.bottom
    && first.bottom > second.top
  )
}

async function assertNoDocumentOverflow(page, viewportName) {
  const dimensions = await page.evaluate(() => ({
    clientWidth: document.documentElement.clientWidth,
    scrollWidth: document.documentElement.scrollWidth,
  }))
  if (dimensions.scrollWidth > dimensions.clientWidth) {
    throw new Error(
      `${viewportName}: document overflows horizontally `
      + `(${dimensions.scrollWidth} > ${dimensions.clientWidth})`,
    )
  }
}

async function assertOwnershipFlow(page, viewportName, isPhone) {
  const visibleSelector = isPhone
    ? '[data-testid="ownership-flow-mobile"]'
    : '[data-testid="ownership-flow-desktop"]'
  const hiddenSelector = isPhone
    ? '[data-testid="ownership-flow-desktop"]'
    : '[data-testid="ownership-flow-mobile"]'

  await page.locator(visibleSelector).waitFor({ state: 'visible' })
  if (await page.locator(hiddenSelector).isVisible()) {
    throw new Error(`${viewportName}: both responsive ownership flows are visible`)
  }

  const measurements = await page.locator(visibleSelector).evaluate((flow) => {
    const nodes = [...flow.querySelectorAll('[data-flow-node]')]
    const lanes = [
      ...flow.querySelectorAll(
        '[data-connector-lane], [data-vertical-connector-lane]',
      ),
    ]
    const nodeRects = nodes.map((node) => node.getBoundingClientRect().toJSON())
    const laneRects = lanes.map((lane) => lane.getBoundingClientRect().toJSON())
    const overflowingNodes = nodes
      .filter(
        (node) => (
          node.scrollWidth > node.clientWidth
          || node.scrollHeight > node.clientHeight
        ),
      )
      .map((node) => node.getAttribute('data-flow-node'))

    return {
      nodeRects,
      laneRects,
      nodeCount: nodes.length,
      laneCount: lanes.length,
      overflowingNodes,
    }
  })

  if (measurements.nodeCount !== 6 || measurements.laneCount !== 5) {
    throw new Error(
      `${viewportName}: expected 6 ownership nodes and 5 connector lanes; `
      + `received ${measurements.nodeCount} and ${measurements.laneCount}`,
    )
  }
  if (measurements.overflowingNodes.length > 0) {
    throw new Error(
      `${viewportName}: ownership text overflows in `
      + measurements.overflowingNodes.join(', '),
    )
  }

  for (const lane of measurements.laneRects) {
    for (const node of measurements.nodeRects) {
      if (rectanglesIntersect(lane, node)) {
        throw new Error(`${viewportName}: a connector lane intersects a node`)
      }
    }
  }
}

async function assertTechnicalMap(page, viewportName, isPhone) {
  await page.getByRole('tab', { name: 'Technical map' }).click()
  await page.getByRole('heading', { name: 'Technical map', exact: true }).waitFor()

  if (isPhone) {
    const mobile = page.locator('[data-testid="technical-map-mobile"]')
    await mobile.waitFor({ state: 'visible' })
    if (await page.locator('[data-testid="technical-map-desktop"]').count()) {
      throw new Error(`${viewportName}: desktop technical map mounted on phone`)
    }
    const cardCount = await mobile.locator('button').count()
    if (cardCount !== 8) {
      throw new Error(
        `${viewportName}: expected 8 technical cards; received ${cardCount}`,
      )
    }
    if (await mobile.locator('svg, img').count()) {
      throw new Error(`${viewportName}: image technical map mounted on phone`)
    }
    return
  }

  const desktop = page.locator('[data-testid="technical-map-desktop"]')
  await desktop.waitFor({ state: 'visible' })
  if (await page.locator('[data-testid="technical-map-mobile"]').count()) {
    throw new Error(`${viewportName}: phone technical cards mounted on desktop`)
  }
  const image = desktop.getByRole('img', {
    name: 'AEGIS v0.9 beta component architecture',
  })
  await image.waitFor({ state: 'visible' })
  const loaded = await image.evaluate(
    (element) => element.complete && element.naturalWidth > 0,
  )
  if (!loaded) {
    throw new Error(`${viewportName}: generated component diagram did not load`)
  }
}

async function checkViewport(
  browser,
  frontendUrl,
  expectedApiOrigin,
  viewport,
  timeoutMs,
) {
  const context = await browser.newContext({
    viewport: {
      width: viewport.width,
      height: viewport.height,
    },
  })
  const page = await context.newPage()
  page.setDefaultTimeout(timeoutMs)
  page.setDefaultNavigationTimeout(timeoutMs)
  const browserErrors = []
  page.on('console', (message) => {
    if (message.type() === 'error') {
      browserErrors.push(`console: ${message.text()}`)
    }
  })
  page.on('pageerror', (error) => {
    browserErrors.push(`page: ${error.message}`)
  })

  try {
    const healthResponse = page.waitForResponse(
      response => new URL(response.url()).pathname === '/health',
    )
    const manifestResponse = page.waitForResponse(
      response => new URL(response.url()).pathname === '/api/demo/manifest',
    )
    await page.goto(frontendUrl, { waitUntil: 'domcontentloaded' })
    const apiResponses = await Promise.all(
      [await healthResponse, await manifestResponse].map(async response => ({
        url: response.url(),
        status: response.status(),
        body: await response.json().catch(() => null),
      })),
    )
    assertExpectedApiResponses(
      apiResponses,
      expectedApiOrigin,
      viewport.name,
    )
    await page.getByRole('heading', {
      name: 'Put policy between the request and the result.',
      exact: true,
    }).waitFor()
    await page.getByRole('navigation', { name: 'Primary navigation' }).waitFor()
    await assertNoDocumentOverflow(page, `${viewport.name} introduction`)

    const architectureUrl = new URL(frontendUrl)
    architectureUrl.hash = '/demo/architecture'
    await page.goto(architectureUrl.toString(), { waitUntil: 'domcontentloaded' })
    await page.getByRole('heading', {
      name: 'Architecture is an ownership contract.',
      exact: true,
    }).waitFor()
    const howTab = page.getByRole('tab', { name: 'How it works' })
    if (await howTab.getAttribute('aria-selected') !== 'true') {
      throw new Error(`${viewport.name}: How it works is not the default view`)
    }

    const isPhone = viewport.width <= 767
    await assertOwnershipFlow(page, viewport.name, isPhone)
    await assertNoDocumentOverflow(page, `${viewport.name} ownership flow`)
    await assertTechnicalMap(page, viewport.name, isPhone)
    await assertNoDocumentOverflow(page, `${viewport.name} technical map`)

    if (browserErrors.length > 0) {
      throw new Error(`${viewport.name}: ${browserErrors.join('; ')}`)
    }
  } finally {
    await context.close()
  }
}

async function main() {
  const options = parseArguments(process.argv.slice(2))
  const browser = await chromium.launch()
  const checked = []
  try {
    for (const viewport of options.viewports) {
      await checkViewport(
        browser,
        options.frontendUrl,
        options.expectedApiOrigin,
        viewport,
        options.timeoutMs,
      )
      checked.push(viewport.name)
    }
  } finally {
    await browser.close()
  }

  process.stdout.write(`${JSON.stringify({ checked })}\n`)
}

if (
  process.argv[1]
  && import.meta.url === pathToFileURL(process.argv[1]).href
) {
  main().catch((error) => {
    process.stderr.write(`${error.stack || error.message}\n`)
    process.exitCode = 1
  })
}
