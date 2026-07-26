#!/usr/bin/env node
import { readFile } from 'node:fs/promises'
import ts from 'typescript'

const INLINE_TAGS = new Set([
  'a',
  'abbr',
  'b',
  'code',
  'em',
  'i',
  'kbd',
  'mark',
  'small',
  'span',
  'strong',
  'sub',
  'sup',
  'time',
])

const PUBLIC_ATTRIBUTES = new Set([
  'alt',
  'aria-description',
  'aria-label',
  'placeholder',
  'title',
])

const PUBLIC_NAMES = new Set([
  'body',
  'caption',
  'content',
  'definition',
  'description',
  'emptyState',
  'eyebrow',
  'heading',
  'incident',
  'label',
  'lead',
  'message',
  'nonOwner',
  'owner',
  'publicSurface',
  'question',
  'reason',
  'responsibility',
  'role',
  'sourcesLabel',
  'subtitle',
  'summary',
  'term',
  'text',
  'tip',
  'title',
  'verificationLabel',
  'visitorRole',
])

const IMPLEMENTATION_PREFIX = /^(?:https?:\/\/|[./#]|data:|var\(--|rgba?\(|hsla?\()/
const INTERNAL_IDENTIFIER = /^[A-Za-z][A-Za-z0-9]*(?:[_-][A-Za-z0-9]+)*$/
const PUBLIC_NAME_SUFFIX = /(?:copy|label|title|description|message|text|question|summary|heading|caption|tip|term|definition|eyebrow|lead|subtitle|notice|error)$/i

function nodeName(node) {
  if (!node) return ''
  if (ts.isIdentifier(node) || ts.isPrivateIdentifier(node)) return node.text
  if (ts.isStringLiteralLike(node) || ts.isNumericLiteral(node)) return node.text
  return node.getText()
}

function staticText(node) {
  if (!node) return null
  if (ts.isStringLiteralLike(node)) return node.text
  if (ts.isParenthesizedExpression(node)) return staticText(node.expression)
  if (
    ts.isBinaryExpression(node)
    && node.operatorToken.kind === ts.SyntaxKind.PlusToken
  ) {
    const left = staticText(node.left)
    const right = staticText(node.right)
    return left === null || right === null ? null : left + right
  }
  if (ts.isTemplateExpression(node)) {
    let value = node.head.text
    for (const span of node.templateSpans) {
      const expression = staticText(span.expression)
      if (expression === null) return null
      value += expression + span.literal.text
    }
    return value
  }
  if (ts.isJsxExpression(node)) return staticText(node.expression)
  return null
}

function isInsideJsx(node) {
  for (let parent = node.parent; parent; parent = parent.parent) {
    if (
      ts.isJsxElement(parent)
      || ts.isJsxFragment(parent)
      || ts.isJsxSelfClosingElement(parent)
    ) {
      return true
    }
  }
  return false
}

function isInsideType(node) {
  for (let parent = node.parent; parent; parent = parent.parent) {
    if (ts.isTypeNode(parent)) return true
    if (ts.isStatement(parent) || ts.isExpression(parent)) return false
  }
  return false
}

function staticRoot(node) {
  let root = node
  while (
    root.parent
    && (
      (
        ts.isBinaryExpression(root.parent)
        && root.parent.operatorToken.kind === ts.SyntaxKind.PlusToken
      )
      || ts.isParenthesizedExpression(root.parent)
      || ts.isTemplateSpan(root.parent)
      || ts.isTemplateExpression(root.parent)
    )
  ) {
    root = root.parent
  }
  return root
}

function contextName(node) {
  const parent = node.parent
  if (ts.isPropertyAssignment(parent) && parent.initializer === node) {
    return nodeName(parent.name)
  }
  if (ts.isVariableDeclaration(parent) && parent.initializer === node) {
    return nodeName(parent.name)
  }
  return ''
}

function isPublicStaticValue(node, value) {
  const stripped = value.trim()
  if (!stripped || IMPLEMENTATION_PREFIX.test(stripped)) return false
  if (
    ts.isImportDeclaration(node.parent)
    || ts.isExportDeclaration(node.parent)
    || (
      ts.isPropertyAssignment(node.parent)
      && node.parent.name === node
    )
    || isInsideType(node)
  ) {
    return false
  }

  const name = contextName(node)
  if (PUBLIC_NAMES.has(name) || PUBLIC_NAME_SUFFIX.test(name)) return true
  return !INTERNAL_IDENTIFIER.test(stripped)
}

function extractFile(path, source) {
  const sourceFile = ts.createSourceFile(
    path,
    source,
    ts.ScriptTarget.Latest,
    true,
    path.endsWith('.tsx') ? ts.ScriptKind.TSX : ts.ScriptKind.TS,
  )
  const blocks = []
  let current = null

  function sourceLine(node) {
    return sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile)).line + 1
  }

  function flush() {
    if (!current) return
    const text = current.text.trim()
    if (text) blocks.push({ ...current, text })
    current = null
  }

  function boundary() {
    flush()
  }

  function append(value, node) {
    const normalized = value.replace(/\s+/g, ' ')
    if (!normalized || (!current && !normalized.trim())) return
    if (!current) {
      current = {
        line: sourceLine(node),
        pos: node.getStart(sourceFile),
        text: '',
      }
    }
    current.text += normalized
  }

  function standalone(value, node) {
    boundary()
    append(value, node)
    boundary()
  }

  function renderExpression(node) {
    if (!node) return
    const value = staticText(node)
    if (value !== null) {
      append(value, node)
      return
    }
    if (ts.isParenthesizedExpression(node)) {
      renderExpression(node.expression)
      return
    }
    if (ts.isConditionalExpression(node)) {
      boundary()
      renderExpression(node.whenTrue)
      boundary()
      renderExpression(node.whenFalse)
      boundary()
      return
    }
    if (
      ts.isBinaryExpression(node)
      && (
        node.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken
        || node.operatorToken.kind === ts.SyntaxKind.BarBarToken
        || node.operatorToken.kind === ts.SyntaxKind.QuestionQuestionToken
      )
    ) {
      boundary()
      renderExpression(node.right)
      boundary()
      return
    }
    if (
      ts.isJsxElement(node)
      || ts.isJsxFragment(node)
      || ts.isJsxSelfClosingElement(node)
    ) {
      renderJsx(node)
      return
    }
    if (ts.isArrowFunction(node) || ts.isFunctionExpression(node)) {
      renderExpression(node.body)
      return
    }
    if (ts.isArrayLiteralExpression(node)) {
      for (const element of node.elements) {
        boundary()
        renderExpression(element)
      }
      boundary()
      return
    }

    ts.forEachChild(node, (child) => {
      if (
        ts.isJsxElement(child)
        || ts.isJsxFragment(child)
        || ts.isJsxSelfClosingElement(child)
      ) {
        renderJsx(child)
      }
    })
  }

  function extractPublicAttributes(attributes) {
    for (const attribute of attributes.properties) {
      if (!ts.isJsxAttribute(attribute)) continue
      const name = attribute.name.getText(sourceFile)
      if (!PUBLIC_ATTRIBUTES.has(name)) continue
      const value = staticText(attribute.initializer)
      if (value !== null) standalone(value, attribute)
    }
  }

  function renderJsx(node) {
    if (ts.isJsxFragment(node)) {
      for (const child of node.children) renderJsxChild(child)
      return
    }

    const opening = ts.isJsxElement(node) ? node.openingElement : node
    const tagName = opening.tagName.getText(sourceFile).toLowerCase()
    const isBlock = !INLINE_TAGS.has(tagName)
    if (isBlock) boundary()
    extractPublicAttributes(opening.attributes)
    if (ts.isJsxElement(node)) {
      for (const child of node.children) renderJsxChild(child)
    }
    if (isBlock) boundary()
  }

  function renderJsxChild(child) {
    if (ts.isJsxText(child)) {
      append(child.text, child)
    } else if (ts.isJsxExpression(child)) {
      renderExpression(child.expression)
    } else {
      renderJsx(child)
    }
  }

  function visitJsx(node) {
    if (
      ts.isJsxElement(node)
      || ts.isJsxFragment(node)
      || ts.isJsxSelfClosingElement(node)
    ) {
      renderJsx(node)
      return
    }
    ts.forEachChild(node, visitJsx)
  }

  visitJsx(sourceFile)
  boundary()

  function visitStatic(node) {
    if (
      ts.isJsxElement(node)
      || ts.isJsxFragment(node)
      || ts.isJsxSelfClosingElement(node)
      || isInsideJsx(node)
    ) {
      return
    }

    const root = staticRoot(node)
    if (root !== node) return
    const value = staticText(node)
    if (value !== null && isPublicStaticValue(node, value)) {
      standalone(value, node)
      return
    }
    ts.forEachChild(node, visitStatic)
  }

  visitStatic(sourceFile)
  boundary()

  blocks.sort((left, right) => left.pos - right.pos)
  return { path, blocks: blocks.map(({ text, line }) => ({ text, line })) }
}

const results = []
for (const path of process.argv.slice(2)) {
  results.push(extractFile(path, await readFile(path, 'utf8')))
}
process.stdout.write(`${JSON.stringify(results)}\n`)
