# AIGC v0.3.2: Put Governance Where the Model Call Actually Happens

Most AI governance does not govern anything at runtime.

It lives in policy decks, review boards, prompt instructions, and dashboards. Useful, yes. Enforceable in the moment a model is called, usually no.

AIGC takes a harder position.

It puts governance at the **invocation boundary**: the exact point where an application attempts to use a model. That means policy is checked in the execution path, not in a separate document and not only after the fact.

That is the core idea behind **AIGC — the Auditable Intelligence Governance Contract**.

## The governing principle

Yes. This is a correct way to state AIGC’s governing principle, and it aligns with the project docs:

> **No AI-influenced behavior is valid unless it is:**
> 1. **Explicitly specified**
> 2. **Deterministically enforceable**
> 3. **Externally observable**
> 4. **Replayable and auditable**
> 5. **Governed independently of any specific model or provider**

That wording is stronger and more accurate than a looser “AI should be governed responsibly” statement because it makes five implementation-level claims. In AIGC, those are not aspirations. They are design constraints.

If you want the crispest version for a Medium article, I would use this sentence:

> **AIGC’s governing principle is simple: no AI-influenced behavior is valid unless it is explicitly specified, deterministically enforceable, externally observable, replayable and auditable, and governed independently of any specific model or provider.**

That version stays faithful to the repo and reads well for publication.

---

## Why this matters

A lot of enterprise AI governance is still built around weak substitutes:

- a policy PDF
- a prompt that says “be safe”
- an approval process outside the runtime path
- a dashboard that explains what went wrong after the system already acted

Those things may help with oversight. They do not guarantee runtime control.

AIGC is built on a narrower and more practical claim:

**if governance does not execute when the invocation happens, it is not governance infrastructure. It is documentation.**

That distinction matters when the stakes are real.

If a model is called by the wrong role, if required context is missing, if a tool exceeds its policy cap, or if the output breaks the declared schema, AIGC is designed to catch that in the enforcement path and emit an audit artifact for the result.

Pass or fail. No silent best effort mode.

---

## What AIGC actually is

AIGC is a **provider-agnostic Python SDK** for governance at the AI invocation boundary.

It does **not** replace your application, agent framework, workflow engine, or orchestration layer. It does **not** own your business state. It does **not** claim to solve all model risk.

It does one job:

**take a declared policy, enforce it deterministically around a model invocation, and produce an auditable result.**

That narrower scope is exactly why the design is credible.

---

## The architecture in one line

Think of AIGC as the layer between your application and the model provider:

**Application → AIGC governance → Model provider**

The application owns the business workflow.
AIGC owns the enforcement boundary.
The model provider supplies the model.

That separation is deliberate.

---

## The four core pieces

### 1) Policy
A declarative YAML contract that defines what is allowed.

### 2) Invocation
The structured input to enforcement: policy, provider, model, role, input, output, and context.

### 3) Enforcement pipeline
A fixed sequence of gates that evaluates the invocation.

### 4) Audit artifact
A tamper-evident record showing what was checked and whether the invocation passed or failed.

---

## What the pipeline checks

In v0.3.2, AIGC runs enforcement through a fixed gate sequence. The important point is not memorizing every internal step. The important point is that **gate ordering is fixed and enforcement is fail-closed**.

In practical terms, AIGC checks things like:

- can this role invoke this capability?
- are the required preconditions present?
- are tool constraints satisfied?
- does the output match the declared schema?
- do postconditions hold?
- does risk scoring merely record risk, warn, or block?

And on every path, AIGC produces evidence.

That is what turns governance from a statement into a system property.

---

## A minimal example

Here is a small policy that captures the basic shape of the SDK without drowning the reader in code:

```yaml
policy_version: "1.0"
roles: [assistant]

pre_conditions:
  required: [user_id]

output_schema:
  type: object
  required: [reply]
  properties:
    reply:
      type: string
```

This policy says three things:

- only the `assistant` role is allowed
- `user_id` must exist in context
- the model output must include a string field called `reply`

And the corresponding enforcement call can be shown just as simply:

```python
from aigc import enforce_invocation

artifact = enforce_invocation({
    "policy_file": "policies/hello.yaml",
    "model_provider": "anthropic",
    "model_identifier": "claude-sonnet-4-6",
    "role": "assistant",
    "input": {"prompt": "Summarize this report."},
    "output": {"reply": "Here is the summary."},
    "context": {"user_id": "user-001"},
})
```

That is enough to make the point.

You do not need a page of scaffolding to understand the model:

**declared contract in, governed artifact out.**

---

## What happens when enforcement fails

This is where AIGC becomes more interesting than a validator.

Failure is not just an exception. It is also an artifact.

AIGC raises typed errors, and the failure path carries structured evidence with it. That matters because enterprises do not just need to know that something broke. They need to know:

- which gate failed
- why it failed
- what policy applied
- what was evaluated
- what evidence exists for audit and replay

In other words, **AIGC treats failure as a first-class governance event**.

---

## Why split enforcement is the real v0.3.2 story

The headline feature in v0.3.2 is **split enforcement**.

Before that, enforcement happened in one pass. That worked, but it had a limitation: some checks necessarily happened after the model had already run.

Split enforcement separates the lifecycle into two phases:

### Phase A: before the model call
This verifies whether the invocation is authorized to happen at all.

### Phase B: after the model call
This verifies whether the model’s output satisfies the contract.

That sounds like a small change. It is not.

It means AIGC can now block unauthorized invocations **before token spend**.

That changes both cost and evidence.

The organization can show not just that it detected a violation, but that it **never authorized the call to happen in the first place**.

---

## Split enforcement, shown simply

The implementation is straightforward enough to explain in a few lines:

```python
from aigc import enforce_pre_call, enforce_post_call

pre = enforce_pre_call(invocation)
output = model.generate(invocation["input"])
artifact = enforce_post_call(pre, output)
```

That is the right amount of code for an article.

It shows the design without dragging the reader through all the machinery underneath it.

What matters is the boundary:

- **pre-call** enforcement authorizes the invocation
- **post-call** enforcement validates the result
- the handoff between them is signed and one-time use

That last detail matters because it prevents replay and substitution tricks at the phase boundary.

---

## Why the handoff token matters

AIGC’s `PreCallResult` is not just a convenience object. It is the evidence bridge between Phase A and Phase B.

In v0.3.2, that bridge was hardened so that post-call enforcement depends on signed evidence from the pre-call phase rather than trusting mutable runtime state.

That is exactly the kind of implementation detail most governance products skip and most real systems eventually need.

Because once governance becomes part of a production path, the question stops being “do you have a policy?” and becomes:

**what prevents a valid pre-check from being reused, swapped, or replayed later?**

AIGC answers that with a signed, one-time-use handoff.

---

## The audit artifact is the product

A lot of teams think the model call is the product.

In governed AI systems, the audit artifact matters just as much.

AIGC artifacts are designed to carry:

- model identity
- policy identity
- enforcement result
- checksums
- gate metadata
- optional signatures
- failure details on FAIL paths

That is what makes the system externally observable and replay-friendly.

Not because someone wrote a good compliance memo, but because the runtime emitted evidence that can be inspected later.

---

## What AIGC does not claim

This is one of the strongest parts of the project.

AIGC does not pretend to be a universal AI safety layer. It does not promise factual correctness. It does not replace application authorization. It does not eliminate the need for human review in high-stakes settings.

Instead, it makes a narrower claim:

**govern the invocation boundary well, and you can make AI behavior enforceable, inspectable, and operationally defensible.**

That is the right scope.

---

## Where this fits in the enterprise

The pattern is portable even though the policies differ.

In financial services, it can govern which assistants may summarize filings or use approved internal tools.

In customer support, it can enforce structured outputs before responses flow into a CRM.

In clinical or operational environments, it can ensure that proposed actions match a declared contract before downstream systems trust them.

The details change. The architecture does not.

That is the value of a provider-agnostic governance layer.

---

## The deeper idea behind AIGC

AIGC is built on a simple but important inversion:

Most systems treat the model as the center and governance as an accessory.

AIGC treats governance as part of the execution contract and the model as a pluggable probabilistic component inside that boundary.

That is why terms like **deterministic wrapper around a probabilistic core** fit this project so well.

The model can vary.
The provider can vary.
The policy can evolve.
But the governance boundary remains explicit.

---

## Final take

AIGC is not interesting because it says governance matters.

Everyone says that.

It is interesting because it treats governance as something that must be:

- declared
- executed
- evidenced
- replayed
- kept independent from any single model vendor

That is a stronger standard than most AI tooling imposes on itself.

And in v0.3.2, split enforcement makes that standard more operationally useful by moving authorization checks ahead of token spend while preserving a signed, auditable handoff into post-call validation.

That is what real governance infrastructure looks like.

Not advice.
Not a dashboard.
Not a prompt.

**A boundary that executes.**
