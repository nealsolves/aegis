# AI Systems Rules

## Purpose

Control model, prompt, data, tool, reliability, safety, cost, and vendor risks
for systems whose behavior depends on probabilistic AI components.

## Applicability

Applies when `uses_llm` or an equivalent AI/model fact is true, including prompt
changes, model/provider changes, retrieval, fine-tuning, agents, evaluations, or
AI tool permissions.

## Required inputs

- Approved use case, risk and authority decision, model/provider, prompts,
  tools, data classifications, regions, budgets, failure/fallback behavior, and
  current evaluation baseline.
- Provider terms for retention, training, residency, limits, and safety plus the
  exact prompt/model/configuration versions under review.

## Mandatory controls

- Require model and provider approval under project and external policy before
  new use. Record capability, data, security, regional, contractual, support,
  portability, and cost rationale.
- Maintain prompt and version tracking for system/developer prompts, templates,
  model identifiers, parameters, tools, retrieval sources, guardrails, and
  evaluation datasets.
- Treat prompt injection as untrusted-input control: separate instructions from
  data, delimit content, constrain retrieval, distrust model-produced commands,
  and test direct/indirect attacks.
- Enforce tool authorization outside the model with least privilege, typed
  arguments, target constraints, confirmation/escalation for authority decisions,
  and audit records. Model intent never grants new permission.
- Perform output validation before using model output in code, queries, access
  decisions, communications, or side effects. Use schema, bounds, allowlists,
  provenance, and domain checks as applicable.
- Declare provider retention and training behavior for inputs, outputs, prompts,
  feedback, and fine-tuning. Prevent prohibited data use and honor deletion.
- Bound cost and retries with budgets, timeouts, maximum attempts, backoff,
  concurrency, and graceful exhaustion. Avoid retry loops that multiply spend or
  side effects.
- Run evaluations against representative success, refusal, safety, injection,
  bias/abuse, tool-use, and failure cases. Preserve reviewed goldens and require
  explanation for material regressions rather than blindly updating them.
- Define hallucination handling through verification, uncertainty, citations or
  source grounding where needed, safe refusal, and containment of consequential
  outputs.
- Preserve human authority for material business, legal, financial, regulatory,
  new sensitive-data use, and critical residual-risk decisions. Present bounded
  options and a recommendation.
- Provide fallbacks for provider/model outage, quota, latency, refusal, unsafe
  output, and evaluation failure. Choose fail-open only with explicit evidence
  and policy authority.
- Add observability for model/provider/version, latency, tokens/cost, retry,
  guardrail decisions, evaluation drift, and tool effects without logging
  sensitive prompts or outputs.
- Address safety and abuse with misuse cases, rate/identity controls, content or
  action constraints, reporting, and incident response proportional to harm.
- Preserve reproducibility by recording versions, parameters, seeds when
  supported, retrieval snapshot/reference, evaluation inputs, and known
  nondeterminism.
- Enforce regional and vendor limits for data processing, availability,
  contractual use, model access, and approved substitutes.

## Evidence

Record approval, model/provider/prompt/tool versions, data handling, injection
and authorization tests, output schemas/checks, cost and retry limits,
evaluations and goldens, fallback results, observability, safety findings,
reproducibility limits, and regional/vendor decisions.

## Exceptions

Exceptions cannot grant a model authority it does not possess, bypass external
data restrictions, permit unbounded spend, or accept critical residual risk.
Record scope, owner, expiry, compensation, and reevaluation trigger.

## Solo interpretation

A solo owner may build and evaluate within configured authority. Use a fresh
adversarial evaluation pass for high-risk tool use or data handling; humans
intervene only for the identified irreducible authority decision.

## Overlay notes

Security, privacy, regulated, regional, vendor, production, and cost overlays are
additive. Provider defaults do not override project policy or external authority.

## Completion checklist

- [ ] Model/provider, prompts, tools, data, region, and authority are approved.
- [ ] Injection, output, evaluation, golden, hallucination, and fallback controls
  are verified.
- [ ] Cost/retry, observability, safety/abuse, and reproducibility are bounded.
- [ ] Residual AI decisions and exceptions are within authority.
