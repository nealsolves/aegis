# AEGIS: Turning AI Governance Into a Runtime Contract

*Release-accurate to AEGIS `v0.3.2`, shipped on `2026-04-05`.*

Enterprise AI is moving fast, but most governance still lives in the wrong place. It lives in slide decks, policy documents, prompt instructions, and architecture reviews that never make it into the actual runtime path of a model call.

That gap is exactly where AEGIS fits.

AEGIS, short for **Auditable Intelligence Governance Contract**, is a Python SDK for deterministic, fail-closed governance of AI model invocations. It does not try to replace your model, your orchestration framework, or your application logic. Instead, it sits at the invocation boundary between your system and the model provider, validates each call against policy, and emits a tamper-evident audit artifact whether the invocation passes or fails.

That distinction matters. AEGIS is not governance as advice. It is governance as runtime enforcement.

## Part 1: Why AEGIS exists

Most teams already know they need AI governance. The problem is that "governance" often means one of four weak substitutes:

- a PDF that says which models are allowed
- a prompt that tells the model to behave responsibly
- a dashboard that reports issues after the fact
- a manual review process that is disconnected from the actual call path

Those controls are useful, but they are not enough for enterprise systems that need evidence, repeatability, and a clear decision boundary before an AI-generated result is trusted or acted on.

AEGIS was built to close that gap with three ideas:

- **Contract**: policy is declared as structured YAML, validated against schema, and versioned.
- **Control**: the policy is enforced deterministically in a fixed gate order with fail-closed behavior for core governance checks.
- **Check**: every invocation attempt produces a structured audit artifact with checksums and supporting metadata.

In other words, AEGIS turns governance from a governance program into a runtime contract.

## Part 2: What AEGIS actually is in `v0.3.2`

As of the shipped `0.3.2` release, AEGIS is a provider-agnostic Python SDK that can govern AI invocations in either of two ways:

- **Unified enforcement**, which evaluates the full invocation in one call after model output exists.
- **Split enforcement**, introduced in `0.3.2`, which lets a host run pre-call authorization checks before token spend and run output-side validation afterward.

The core public entry points are:

- `enforce_invocation()` and `enforce_invocation_async()`
- `enforce_pre_call()` and `enforce_post_call()` with async parity
- `AEGIS(...)` for instance-scoped runtime configuration
- `@governed(...)` for wrapping a model call site directly, with opt-in split mode via `pre_call_enforcement=True`

What can AEGIS govern at runtime?

- policy loading and schema validation
- role allowlists
- typed preconditions over invocation context
- tool allowlists and tool budgets
- output schema validation
- postconditions
- optional custom enforcement gates at four fixed insertion points
- optional risk scoring
- audit artifact generation and emission

What it does not do is equally important:

- it does not make model calls
- it does not replace application authorization
- it does not store artifacts for you
- it does not replace domain compliance workflows

AEGIS governs the invocation boundary. The host application still owns orchestration, state, model execution, and any irreversible actions.

## Part 3: The intent behind the architecture

The architecture is opinionated in a way many enterprise AI stacks are not.

The basic runtime shape looks like this:

1. The host application assembles an invocation and points it at a policy file.
2. AEGIS loads and validates the policy.
3. AEGIS runs a fixed governance pipeline.
4. AEGIS returns or emits exactly one final PASS or FAIL audit artifact for that invocation attempt.

In unified mode, that all happens in one enforcement call.

In split mode, the boundary moves:

- **Phase A / pre-call** runs policy load, custom pre-authorization gates, guard evaluation, role validation, precondition validation, tool constraints, and custom post-authorization gates.
- **Phase B / post-call** runs custom pre-output gates, output schema validation, postconditions, custom post-output gates, risk scoring, and final artifact generation.

That is the key architectural point in `0.3.2`: the model-call boundary moved, but the gate ordering did not.

This matters because AEGIS is built around a set of non-negotiable invariants:

- governance must be deterministic
- core enforcement must be fail-closed
- gate ordering must stay fixed
- audit evidence must be tamper-evident
- unified mode must remain backward-compatible

So the `0.3.2` release was not just "add two new functions." It was a structural change that preserved the original enforcement semantics while giving enterprise hosts a way to block before token spend.

## Part 4: What shipped in `0.3.2`, and why it matters

The headline feature in `0.3.2` is split enforcement:

- `enforce_pre_call()` authorizes the invocation before the model call
- `enforce_post_call()` validates the returned output afterward
- `PreCallResult` is the one-time handoff token between the two phases
- audit schema `v1.3` adds split-mode metadata such as `enforcement_mode`, `pre_call_gates_evaluated`, `post_call_gates_evaluated`, `pre_call_timestamp`, and `post_call_timestamp`

For enterprise teams, that means AEGIS can now answer two separate operational questions:

- "Was this invocation authorized to happen at all?"
- "Did the output satisfy the contract once the model responded?"

Just as important, `0.3.2` also shipped hardening work driven by an audit on `2026-04-05`. In practical terms, the release tightened the integrity of the pre-call handoff so Phase B does not trust mutable runtime state. Instead, it validates signed evidence, verifies captured gate fingerprints, rejects replayed or cloned handoff tokens, and sources FAIL artifact identity fields from verified evidence bytes.

That is exactly the kind of engineering detail enterprises should care about. When a system claims to govern calls across a split execution path, the handoff itself becomes part of the trust boundary.

The repo's current release baseline is also not a thin prototype. The shipped line documents `818 tests` and coverage above the `90%` CI gate.

## Part 5: What AEGIS does for enterprises

The simplest way to understand AEGIS's enterprise value is to treat it as a governance substrate rather than a model feature.

### 1. It makes policy executable

Instead of saying "only approved roles may use this model" or "outputs must match this structure," AEGIS turns those into enforceable runtime checks.

### 2. It gives enterprises a stable control boundary

Because AEGIS governs invocations rather than providers, teams can change model vendors, change orchestration frameworks, or add new AI features without throwing away their governance layer.

### 3. It separates authorization from generation

This became much more useful in `0.3.2`. In systems where token spend, rate limits, or provider cost matter, pre-call enforcement lets the host reject unauthorized invocations before the model runs.

### 4. It creates usable evidence, not just logs

An audit artifact is more than a log line. It carries structured identity fields, checksums, result status, failure details, and ordered gate metadata. Optional signing, audit chaining, and compliance export extend that evidence after enforcement.

### 5. It supports controlled extensibility

Many enterprise controls are domain-specific. AEGIS supports custom gates at `pre_authorization`, `post_authorization`, `pre_output`, and `post_output`, but still keeps them inside a declared, auditable pipeline.

### 6. It helps governance survive real operating conditions

Beyond the core pipeline, the `0.3.x` line includes practical capabilities enterprises usually need:

- pluggable policy loaders
- policy effective and expiration dates
- policy composition strategies
- telemetry hooks
- policy testing helpers
- compliance export over stored audit trails

Taken together, that makes AEGIS more useful as an operational library than as a theoretical framework.

## Part 6: The demo app is not just a UI, it is the learning surface

One of the most important changes in the recent release line is that the maintained demo surface is now a React frontend plus FastAPI backend. In `0.3.1`, the demo became the primary hands-on surface. In `0.3.2`, it was updated to teach the current architecture, including unified default mode and opt-in split enforcement.

The demo walks through seven labs:

- risk scoring
- signing and verification
- audit chain
- policy composition
- loaders and policy versioning
- custom gates
- compliance dashboard and export

That matters for new readers because it shows AEGIS as a working system rather than a library with abstract claims.

For example, the demo backend exposes real scenarios around medical AI policies, split-flow enforcement, custom gates like session authorization and domain allowlisting, response-length checks, confidence checks, and PII detection. It is opinionated, but it maps cleanly to real enterprise questions:

- should this invocation be allowed?
- which safeguards were actually applied?
- can we prove a record was not tampered with?
- how do base and child policies change effective behavior?
- how do we export evidence for compliance review?

In that sense, the demo is a practical guide to the intent of the SDK.

## Part 7: A real-world use case where AEGIS fits

Take a healthcare enterprise building a clinical support assistant for discharge summaries and medication guidance.

The organization does not want the model making autonomous medical decisions. It wants the model to produce proposals under controlled conditions, with human review, structured output, and an audit trail that can survive internal review or an external investigation.

This is a strong fit for AEGIS.

Just as importantly, the host system still owns the final action. The model can propose content, but the application decides what to do with it. AEGIS reinforces that boundary by governing the invocation and validating the output before downstream systems trust it.

### Step 1: The hospital defines the contract

The team writes a policy that declares:

- which roles are allowed, such as `doctor` or `nurse`
- which preconditions must be present in context, such as `role_declared` and `schema_exists`
- the required output schema
- postconditions like `output_schema_valid`
- tool allowlists, for example medical databases or drug-interaction lookups
- optional risk scoring rules

In the demo repo, the sample medical policies show exactly this pattern. The lower-risk version keeps tighter roles and safeguards. The higher-risk version intentionally broadens roles and removes safeguards so the risk lab can show how the score changes.

### Step 2: The host runs pre-call governance

Now imagine a clinician asks:

> "Draft discharge instructions for patient #9812."

With split enforcement, the host can call `enforce_pre_call()` before spending tokens.

At this point AEGIS can block the invocation if:

- the role is not allowed
- required context is missing
- tool usage would exceed policy
- a custom pre-authorization gate fails

The demo includes exactly this kind of scenario: a split-flow example where the invocation is missing `role_declared` in context, so Phase A fails before the model call runs.

That is not just a performance optimization. It is a cleaner control boundary. The enterprise can prove it never authorized the call in the first place.

### Step 3: The model responds, and AEGIS validates the output

If Phase A passes, the host executes the model call and hands the result to `enforce_post_call()`.

Now AEGIS validates:

- output schema
- postconditions
- custom output-side gates
- risk scoring

If the result is malformed, too permissive, contains restricted content, or fails a custom gate, the invocation fails with a typed exception and a FAIL artifact. If risk scoring is configured, the final treatment depends on the selected mode: `strict` can block, while `risk_scored` and `warn_only` record the risk without turning that alone into a hard failure.

### Step 4: The organization gets evidence, not guesswork

Whether the invocation passes or fails, the final artifact records the governance result, policy identity, model identity, checksums, timestamps, and ordered gate metadata.

If signing is enabled, the artifact can be HMAC-signed.

If chaining is enabled, the artifact can be linked into a tamper-evident sequence.

If the compliance team wants a report later, the audit trail can be exported offline.

### Step 5: The outcome improves in concrete ways

For the enterprise, the outcome is not "the AI is safe." That is too vague to be useful.

The outcome is more specific:

- unauthorized invocations are blocked deterministically
- output contracts are enforced before downstream systems trust the result
- evidence exists for both PASS and FAIL paths
- governance survives model swaps because it is provider-agnostic
- domain-specific controls can be added without forking the SDK

That is the kind of improvement enterprises can operationalize.

## Part 8: Other real-world use cases beyond the demo

Healthcare is a natural example because the demo uses medical policies, but the same governance pattern maps to other domains:

- **Financial services**: govern analyst assistants that summarize filings, propose risk notes, or call approved internal search tools under tenant and session constraints.
- **Customer support**: enforce structured response formats, role-specific permissions, and auditable handling of escalations before results are written into a CRM.
- **Internal knowledge assistants**: restrict tools, require tenant context, and add custom gates for domain allowlists or data sensitivity checks.
- **Compliance-heavy copilots**: use policy dates, policy composition, signing, and exportable audit trails to keep governance tied to the same runtime where AI output is generated.

The specific rules change by domain. The architectural need does not.

## Part 9: What AEGIS is not

This is worth stating clearly, because it is easy to over-claim governance tools.

AEGIS is not:

- a model safety layer that guarantees factual correctness
- an autonomous compliance program
- a replacement for application-layer authorization
- a substitute for human review in high-stakes domains
- a hosted control plane that stores and manages all enterprise governance state

It is a deterministic enforcement SDK around AI invocation boundaries.

That may sound narrower than some AI governance marketing. In practice, it is what makes the project credible.

## Part 10: What is next for AEGIS

The repo is disciplined about separating shipped features from future-facing ideas, so it is worth being careful here.

There is no public claim in `0.3.2` that a full `v0.4.0` feature set is ready yet. But the documentation does point to a few likely next steps:

- planned extension points such as `register_validator` and `register_resolver`
- richer guard-expression support like dotted attribute access, list literals, and negated membership
- continued evolution around extensibility without weakening the deterministic, fail-closed core

That is the right direction for a project like this. The next phase should not make AEGIS looser. It should make it easier to integrate into more enterprise systems while preserving the same architectural invariants that make the current release trustworthy.

## Closing

AEGIS is interesting because it takes a hard line on where AI governance should live: not in documents, not in prompts, and not only in after-the-fact reporting, but in the runtime path of the invocation itself.

In the shipped `0.3.2` release, that idea has matured into a clearer architecture:

- policy as code
- deterministic enforcement
- unified default mode plus opt-in split enforcement
- tamper-evident audit artifacts
- optional integrity and compliance utilities around the core

For enterprises, that is the real value proposition. AEGIS does not ask leaders to trust that governance happened. It gives them a way to enforce it, prove it, and inspect it as part of the system that actually made the AI call.
