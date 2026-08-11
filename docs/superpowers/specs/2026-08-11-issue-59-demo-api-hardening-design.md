# Issue #59 Demo API Resource and Diagnostic Hardening Design

**Status:** Approved design; pending written-spec review

**Date:** 2026-08-11

**Issue:** [#59 — security: demo API permits YAML amplification, unbounded bodies, and diagnostic leakage](https://github.com/nealsolves/aegis/issues/59)

## Problem

The public FastAPI demo accepts attacker-controlled JSON and YAML without a
request-body limit or per-client rate limit. `/api/compose` and
`/api/policy/load-inmemory` construct Python objects with `yaml.safe_load()` and
return or reserialize those objects. `safe_load()` prevents arbitrary Python
object construction, but it does not bound alias fan-out or the cost of later
JSON/YAML serialization.

On current `main`, a 211-byte YAML document using seven anchors and 36 aliases
produces a 1,478,378-byte response from `/api/policy/load-inmemory`, an
amplification factor of approximately 7,006.5. Malformed YAML is returned with
PyYAML's complete diagnostic, including source coordinates and snippets.

The demo also returns `str(exc)`, subprocess stderr, and other internal
diagnostics from several routes. Some finalized artifacts contain local policy
paths. Removing those fields after finalization would invalidate their checksum
or signature, so confidentiality must be established before evidence is
finalized rather than by mutating evidence on the way out.

## Goals

- Reject oversized declared and streamed HTTP request bodies before FastAPI,
  Pydantic, or route parsing.
- Bound every demo-owned raw-YAML boundary by encoded bytes, anchors, aliases,
  nesting depth, scalar count, collection count, expanded nodes, expanded
  scalar bytes, and serialized response bytes.
- Reject ambiguous or non-JSON-compatible YAML, including duplicate keys,
  merge keys, cycles, non-string mapping keys, timestamps, binary values, sets,
  custom tags, and non-finite numbers.
- Reject the issue's bounded amplification payload before response
  serialization.
- Add bounded process-local per-client rate limiting plus a process-wide
  backstop for the current single-worker Render deployment.
- State and test the trusted-proxy policy explicitly; never trust an arbitrary
  caller-supplied forwarding chain.
- Return stable public error codes and short messages without parser output,
  exception strings, local paths, subprocess output, or stack traces.
- Retain bounded internal diagnostics in server logs, correlated by a
  server-generated request ID.
- Preserve evidence checksums and signatures by using public-safe logical
  policy references before finalization.
- Add real subprocess timeouts without retrying failed or timed-out work.
- Keep the published demo examples and valid compose/load workflows usable.
- Document monitoring, single-process limits, and the separation between demo
  edge controls and enforcement-core guarantees.

## Non-goals

- A distributed or multi-worker rate-limit store.
- DDoS protection at network or Render edge scale.
- A general-purpose hostile-YAML sandbox for the core SDK.
- A generic ASGI response-buffering layer for every response.
- Caller-configurable security limits.
- Retrying YAML parsing, subprocesses, or other expensive work after a
  resource-control failure.
- Repairing unrelated demo/core API drift already present on `main` except
  where a narrow compatibility adjustment is required to execute an issue #59
  acceptance path.
- Replacing #56's no-schema-I/O compiler contract or claiming that demo edge
  controls harden the enforcement core.

## Threat Assumptions

Request methods, paths, headers, declared lengths, body chunking, JSON values,
YAML strings, scenario identifiers, artifact-shaped request values, and
forwarding headers are untrusted. Attackers may coordinate many client
identities, send bodies slowly, omit or understate `Content-Length`, reuse YAML
anchors, construct cyclic YAML graphs, trigger exceptional code paths, and use
diagnostic values containing local paths or control characters.

The Render service is currently one Uvicorn worker on a free web-service
instance. The application port is reachable through Render's managed ingress,
not directly from the public internet. The design does not assume that every
forwarding header supplied to the application has been sanitized; a deployment
smoke test must verify that Render appends or replaces the rightmost
`X-Forwarded-For` hop as expected.

An attacker who can alter deployed policy files, replace the Python process,
or execute code in-process is outside this demo-edge threat model.

## Approaches Considered

### Chosen: dedicated demo-edge and bounded-YAML boundaries

Add one pure ASGI edge middleware, one bounded YAML module, and one public error
module. Migrate every applicable route and custom loader to those shared
boundaries.

Advantages:

- Enforces request limits before Pydantic.
- Makes declared, chunked, slow-body, rate, and proxy behavior independently
  testable.
- Keeps YAML constraints identical across routes.
- Avoids a new service or runtime dependency.
- Keeps finalized evidence immutable.

Costs:

- Adds demo-specific security code that must remain covered by adversarial
  tests.
- Process-local limiter state resets on restart and cannot coordinate multiple
  workers.
- Requires a Render forwarding-behavior deployment gate.

### Rejected: third-party rate middleware plus local YAML guards

A third-party limiter would reduce token-bucket code but would not solve body
streaming, proxy identity, YAML graph limits, evidence path leakage, response
amplification, or safe diagnostic handling. It would split one security
boundary across decorators and local utilities while adding a dependency.

### Rejected: route-local checks

Route-local body checks occur after request parsing and cannot guarantee a
`413` for streamed bodies before Pydantic. Repeating YAML and exception logic
would also make omissions likely as the demo evolves.

## Central Limits

All numeric limits live in `demo-app-api/demo_limits.py` as immutable module
constants. They are not read from request parameters, query parameters,
headers, cookies, or environment variables.

| Constant | Value | Meaning |
| --- | ---: | --- |
| `REQUEST_BODY_MAX_BYTES` | `65_536` | Maximum encoded HTTP request body |
| `REQUEST_BODY_READ_TIMEOUT_SECONDS` | `4.0` | Total wall-clock budget to receive a body |
| `YAML_MAX_ENCODED_BYTES` | `24_576` | Maximum UTF-8 bytes per YAML document |
| `YAML_MAX_ANCHORS` | `24` | Maximum anchor definitions per document |
| `YAML_MAX_ALIASES` | `24` | Maximum alias events per document |
| `YAML_MAX_NESTING_DEPTH` | `20` | Maximum mapping/sequence nesting depth |
| `YAML_MAX_SCALARS` | `2_048` | Maximum scalar events before construction |
| `YAML_MAX_COLLECTIONS` | `512` | Maximum mapping/sequence start events |
| `YAML_MAX_EXPANDED_NODES` | `4_096` | Maximum root/key/value/item occurrences after construction |
| `YAML_MAX_EXPANDED_SCALAR_BYTES` | `131_072` | Maximum repeated UTF-8 scalar bytes in the expanded graph |
| `YAML_RESPONSE_MAX_BYTES` | `262_144` | Maximum incrementally encoded endpoint response containing parsed YAML |
| `CLIENT_RATE_CAPACITY` | `30` | Per-client token-bucket burst capacity |
| `CLIENT_RATE_REFILL_PER_SECOND` | `1.0` | Sustained per-client rate, 60 requests/minute |
| `GLOBAL_RATE_CAPACITY` | `120` | Process-wide burst capacity |
| `GLOBAL_RATE_REFILL_PER_SECOND` | `10.0` | Process-wide sustained rate, 600 requests/minute |
| `RATE_LIMIT_MAX_IDENTITIES` | `2_048` | Maximum retained client buckets |
| `RATE_LIMIT_IDENTITY_TTL_SECONDS` | `300.0` | Idle client-bucket retention |
| `SUBPROCESS_TIMEOUT_SECONDS` | `10.0` | Maximum workflow CLI subprocess duration |
| `INTERNAL_DIAGNOSTIC_MAX_BYTES` | `8_192` | Maximum logged diagnostic payload per failure |

The largest checked-in demo policy is 2,114 bytes, so the YAML byte limit is
more than eleven times the current valid maximum. The global request limit also
applies to JSON framing and escaping, so two documents that each independently
reach the YAML maximum are not guaranteed to fit in one compose request. The
checked-in compose pair is well below both boundaries. The limits must be
tested against every checked-in sample and compose pair before merge.

## File and Responsibility Boundaries

### `demo_limits.py`

Owns only the constants above. Importing it performs no I/O and reads no
configuration.

### `demo_errors.py`

Defines:

- `DemoPublicError`, carrying `status_code`, stable `code`, fixed `message`, and
  optional safe headers;
- the common JSON error envelope;
- allowlisted public messages for known AEGIS failure codes;
- request-validation, HTTP, and unexpected-exception handlers; and
- bounded correlated logging helpers.

It must not import route modules or parse request bodies.

### `demo_edge.py`

Defines the pure ASGI edge middleware, body receiver/replayer, client identity
resolver, and bounded token-bucket store. Connection-specific state is created
inside `__call__`; no request state is stored on middleware instance fields.
Limiter tables and clocks are the only shared process state. The edge stores
the request ID and limiter identity source in ASGI `scope["state"]` and binds the
request ID to a `ContextVar` for code that does not receive a `Request` object.
The binding is reset in `finally`; AnyIO's sync-route thread dispatch receives
the copied context rather than a process-global mutable value.

### `bounded_yaml.py`

Defines the bounded loader, event-budget scanner, expanded-graph validator,
JSON-compatible type validator, and incremental response-size preflight.
Neither routes nor custom loaders call PyYAML directly.

### Existing route and service modules

`main.py`, `loaders.py`, `workflow_routes.py`, `demo_scenario_service.py`, and
`demo_adapter_service.py` consume the shared boundaries. They retain
route-specific success shapes but do not construct public messages from raw
exceptions.

## Edge Request Flow

For every HTTP request, the effective order is:

1. The outer edge generates a 128-bit random lowercase hexadecimal request ID
   with `secrets.token_hex(16)`. It stores the value in ASGI state and the
   request context, and never accepts a caller-provided correlation ID as
   authoritative.
2. Health checks and `OPTIONS` requests bypass rate consumption. All other
   HTTP paths, including unknown paths and documentation routes, atomically
   consume client and global rate tokens before further application work.
3. Conflicting, repeated-with-different-value, negative, or non-numeric
   `Content-Length` values produce `400 INVALID_CONTENT_LENGTH`.
4. A declared length above `REQUEST_BODY_MAX_BYTES` produces `413
   REQUEST_BODY_TOO_LARGE` without reading the body.
5. A non-identity `Content-Encoding` produces `415
   UNSUPPORTED_CONTENT_ENCODING`; the demo does not decompress request bodies.
6. The edge receives the complete body under one total monotonic deadline,
   retaining at most `REQUEST_BODY_MAX_BYTES + 1` bytes. Crossing the byte limit
   produces `413`; crossing the deadline produces `408 REQUEST_BODY_TIMEOUT`.
7. The bounded body is replayed as one `http.request` message to the inner
   `CORSMiddleware`, which handles preflight or forwards to FastAPI.
8. Every response receives `X-Request-ID`. Public error bodies contain the
    same request ID.

Pre-buffering is deliberate. Merely wrapping `receive()` could discover an
oversized stream after downstream code starts a response. No current demo
route needs streaming request semantics, and 65,536 bytes is a small bounded
buffer.

The edge handles `http.disconnect` without logging a fabricated application
failure. It must not drain an oversized or timed-out body, retry body reads, or
forward a partially received body to FastAPI.

When one request violates more than one control, the first evaluated control
wins. In particular, a non-exempt client that has exhausted its rate bucket
receives `429` without body inspection; body-limit tests use a fresh limiter to
assert `413`. This ordering prevents malformed or oversized requests from
bypassing rate consumption merely because another rejection also applies.

## Middleware Ordering

The edge must be outside CORS so preflight requests cannot short-circuit the
global body limit. `main.py` constructs an inner FastAPI application, wraps it
with `CORSMiddleware`, then exports
`DemoEdgeMiddleware(cors_app, allowed_origins=...)` as the ASGI `app`.

The allowed-origin tuple is created once and passed to both middlewares. For a
known failure emitted before CORS runs, the edge applies the same exact-origin
check and emits the corresponding `Access-Control-Allow-Origin`, `Vary:
Origin`, and exposed-header policy. It never reflects an origin outside the
allowlist. Normal responses, preflight success, and FastAPI's normalized errors
pass through `CORSMiddleware`. The edge exposes `X-Request-ID` and
`Retry-After` to allowed browser origins.

The edge also catches an unexpected exception escaping the entire inner stack,
logs it, and emits the fixed `INTERNAL_ERROR` envelope with the same CORS helper.
Tests assert CORS parity for preflight, known edge failures, normalized FastAPI
failures, and unexpected outer failures rather than relying on comments about
middleware order.

## Rate Limiting

### Token behavior

The limiter uses a monotonic clock injected at construction for deterministic
tests. Client and global availability are checked and decremented in one small
critical section. If either bucket lacks a token, neither bucket is decremented
and the request receives `429 RATE_LIMIT_EXCEEDED` plus a conservative integer
`Retry-After` derived from the limiting bucket.

The production server runs one event loop, but the critical section uses a
short non-awaiting lock so tests or alternate ASGI hosts cannot interleave
updates across threads. No network or file I/O occurs while the lock is held.

### Bounded identity storage

Expired identities are pruned opportunistically. Once 2,048 non-expired
identities are retained, previously unseen identities share one overflow
bucket until capacity becomes available. The implementation does not evict an
active known client merely to admit attacker-generated identities. Raw request
headers are never used as dictionary keys.

The global bucket applies regardless of client identity. It bounds total work
even if an upstream forwarding assumption fails or an attacker distributes
requests across many valid source addresses.

### Trusted-proxy contract

`render.yaml` starts Uvicorn with `--no-proxy-headers`. The application, not
both Uvicorn and the application, owns forwarded-address interpretation.

The resolver follows this exact policy:

1. Parse the immediate ASGI peer as an IP address. If it is absent or invalid,
   use the stable shared identity `unknown-peer`.
2. By default, use the canonical immediate peer address.
3. Only when the immediate peer is loopback or private may the resolver inspect
   `X-Forwarded-For`.
4. Join repeated header fields in wire order, split on commas, and inspect only
   the rightmost non-empty token.
5. Use that token only if it is one valid IPv4 or IPv6 address. Otherwise fall
   back to the immediate peer.

The resolver never trusts the leftmost address, never accepts a host name, and
never treats `*` as a trusted proxy set. Direct-peer and selected-client values
are canonicalized with `ipaddress` before use.

Render deployment is gated by a smoke test that sends a stable request sequence
while varying a caller-supplied `X-Forwarded-For`. If the forged values create
new client buckets, deployment fails and the service remains on direct-peer
identity plus the global bucket until the ingress contract is corrected. A
multi-worker deployment is prohibited until a shared limiter is designed.

## Bounded YAML Contract

### Stage 1: encoded input

The parser accepts a Python string, encodes it as strict UTF-8, and rejects
encoding failures or more than 24,576 bytes with a stable `422` error. No
normalization occurs before byte accounting.

### Stage 2: event scan

`yaml.parse(..., Loader=yaml.SafeLoader)` is consumed once to enforce:

- exactly one document;
- at most 24 anchor definitions;
- at most 24 `AliasEvent` instances;
- at most 20 simultaneous mapping/sequence levels;
- at most 2,048 scalar events;
- at most 512 mapping/sequence start events;
- no explicit custom tags; and
- no scalar mapping key equal to YAML's merge key `<<`, quoted or unquoted.

Anchor definitions are counted on scalar, mapping-start, and sequence-start
events carrying an anchor. Alias references are counted only as alias events,
not as additional anchor definitions. A parser exception becomes `422
YAML_INVALID`; its original text is logged but never returned.

### Stage 3: safe construction with strict mappings

A private `yaml.SafeLoader` subclass rejects duplicate mapping keys before
constructing their values. Mapping keys must be strings. YAML merge keys are
already rejected and are not flattened. Unknown or explicit custom tags fail
closed.

Construction must yield only:

- `dict[str, value]`;
- `list[value]`;
- `str`;
- `bool`;
- finite `int` or `float`; or
- `None`.

Because `bool` is a subclass of `int`, type checks handle booleans before
numbers. Timestamps, dates, bytes, sets, tuples, custom objects, non-finite
floats, and every other constructed type are rejected with `422
YAML_UNSUPPORTED_VALUE`.

### Stage 4: expanded graph validation

An iterative enter/exit traversal avoids Python recursion. It keeps an
ancestor identity set for containers:

- revisiting a container on the current path is a cycle and produces `422
  YAML_CYCLE_REJECTED`;
- revisiting a shared container through another occurrence traverses and counts
  it again; and
- globally deduplicating shared objects is forbidden because that would
  undercount alias fan-out.

The count includes the root, every mapping key occurrence, every mapping value
occurrence, and every list item occurrence. Traversal stops immediately above
4,096 occurrences or 131,072 repeated scalar UTF-8 bytes with `422
YAML_LIMIT_EXCEEDED`.

This stage rejects the issue's seven-level, width-six reproduction even though
its 211 encoded bytes, seven anchors, and preconstruction collection counts are
small.

### Stage 5: response preflight

Routes build their complete success payload and pass it through
`json.JSONEncoder(ensure_ascii=False, allow_nan=False, separators=(",", ":"))`
using `iterencode()`. The preflight sums UTF-8 chunk sizes and stops above
262,144 bytes without joining an oversized string. Only then may FastAPI encode
the actual response.

`/api/compose` may call `yaml.safe_dump()` only after expanded-graph limits
succeed. The bounded graph makes dump cost finite; the complete route payload,
including `merged_yaml`, still passes the incremental JSON preflight.

## YAML Boundary Coverage

The following paths use the same bounded parser and limits:

- `/api/compose` for both `parent_yaml` and `child_yaml`;
- `/api/policy/load-inmemory` through `InMemoryPolicyLoader`;
- `InMemoryPolicyLoader` when constructed directly by demo code; and
- `/api/policy/load` before a checked-in policy is returned to the caller.

No `yaml.safe_load`, `yaml.load`, or custom loader call remains in demo-owned
code outside `bounded_yaml.py`. Checked-in demo and sample policies are tested
against the same limits. Core SDK policy loading remains governed by its own
contract and is not silently replaced by this demo-specific parser.

## Evidence Integrity and Path Confidentiality

Finalized invocation and workflow artifacts are immutable. The demo never
removes or rewrites a path, failure message, checksum, or signature after
finalization.

Instead, every demo-owned AEGIS invocation uses a root-bound
`FilePolicyLoader` and a public logical policy reference such as
`medical_ai.yaml`, `northstar.yaml`, or `policy.yaml`. The loader resolves the
logical reference inside its fixed server-owned root; the logical reference is
what enters the invocation and therefore what is checksum- and
signature-covered.

The workflow starter harness calls generated functions with `policy.yaml` and
injects a module-local AEGIS factory bound to that starter directory. It does
not mutate the process-wide `aegis.AEGIS` symbol and does not `chdir()`, which
would be unsafe under concurrent requests. Generated artifacts therefore carry
`policy.yaml`, not an absolute temporary directory.

If an exceptional path cannot produce finalized evidence with public-safe
inputs, it returns no artifact. A separate explicitly non-evidence summary may
contain only allowlisted status, stable reason code, and request ID. It must not
copy checksum or signature fields or imply that the summary is verifiable.

Known expected governance rejections may return their original finalized
artifact only after tests prove that every string in the serialized response is
free of absolute paths, parser diagnostics, subprocess output, stack traces,
and injected secret sentinels. Unknown exceptions never return an attached
artifact.

Non-evidence diagnostics are projected independently. Negative adapter
`normalized_evidence` contains only allowlisted protocol fields and its stable
`reason_code`; it never returns `exc.details` wholesale. Workflow-doctor
findings retain stable code, severity, message, and next action, but any path is
converted relative to the already trusted starter root and then restricted to
the logical names `policy.yaml`, `workflow_example.py`, or `README.md`. A value
that cannot be mapped to that allowlist is omitted. Trace artifacts acquire
logical policy references at finalization and therefore require no path
rewriting.

## Public Error Contract

HTTP failures use this envelope:

```json
{
  "detail": {
    "code": "YAML_LIMIT_EXCEEDED",
    "message": "YAML input exceeds the public demo limits.",
    "request_id": "0123456789abcdef0123456789abcdef"
  }
}
```

Codes and messages are fixed constants. User-controlled values, exception
strings, parser marks, local paths, and subprocess output are never
interpolated. At minimum the stable code set includes:

- `INVALID_REQUEST` (`422`);
- `INVALID_CONTENT_LENGTH` (`400`);
- `NOT_FOUND` (`404`);
- `METHOD_NOT_ALLOWED` (`405`);
- `REQUEST_BODY_TIMEOUT` (`408`);
- `REQUEST_BODY_TOO_LARGE` (`413`);
- `UNSUPPORTED_CONTENT_ENCODING` (`415`);
- `YAML_INVALID` (`422`);
- `YAML_UNSUPPORTED_VALUE` (`422`);
- `YAML_CYCLE_REJECTED` (`422`);
- `YAML_LIMIT_EXCEEDED` (`422`);
- `RATE_LIMIT_EXCEEDED` (`429`);
- `DEMO_OPERATION_TIMEOUT` (`503`);
- `DEMO_OPERATION_FAILED` (`500`); and
- `INTERNAL_ERROR` (`500`).

FastAPI request-validation failures do not return `exc.errors()` or the input
body. Unknown `HTTPException.detail` values are not passed through. Route code
uses `DemoPublicError` for intentional public failures.

Expected demo outcomes that intentionally return HTTP `200` retain their
existing response shape, but `error.code` is allowlisted and `error.message` is
a fixed public explanation derived from that code. Unknown AEGIS codes map to
`AEGIS_ENFORCEMENT_FAILED`; they do not expose `str(exc)`.

Existing `UNKNOWN_DEMO_ID` failures retain their stable code and allowlisted
`id_type`, but omit the caller-supplied identifier and use a fixed message.
Unknown routes and methods use the stable `NOT_FOUND` and
`METHOD_NOT_ALLOWED` envelopes rather than Starlette's free-form detail.

## Correlated Internal Diagnostics

Every normalized failure logs:

- request ID;
- method and matched route template when available;
- stable public code;
- exception class;
- limiter identity source (`direct`, `forwarded-rightmost`, `overflow`, or
  `unknown`) without logging arbitrary header text; and
- at most 8,192 UTF-8 bytes of internal diagnostic text.

Logging never records the request body, authorization/cookie headers, the raw
forwarding chain, or caller-provided correlation IDs. Control characters in
single-field diagnostics are escaped or represented so they cannot forge a new
structured log record. Parser diagnostics and subprocess stderr may appear only
inside the bounded internal diagnostic field.

## Subprocess Resource Handling

Every `subprocess.run()` in `workflow_routes.py` uses
`timeout=SUBPROCESS_TIMEOUT_SECONDS`, captures output, and performs no retry.
`subprocess.TimeoutExpired`, nonzero exit, empty output, and malformed JSON are
logged with the request ID and mapped to fixed public errors.

Captured stdout/stderr is truncated to 8,192 UTF-8 bytes before logging.
Neither stream is returned to the client. Cleanup errors are logged separately
and cannot replace the primary operation failure.

YAML parsing is not wrapped in a thread timeout that abandons a still-running
worker. Its actual resource guarantee comes from encoded, event, graph, and
serialization budgets. Hard timeouts are used only for subprocesses that can
be terminated by `subprocess.run()`.

## Frontend Compatibility

`demo-app-react/src/hooks/useApi.ts` parses the stable error envelope before
handling a non-2xx response. It displays the fixed public message and may append
the request ID for support correlation. It never displays an arbitrary response
body or `JSON.stringify()` of unknown details.

Labs 4 and 5 continue to show actionable safe messages for malformed or
over-limit YAML even though those failures now use HTTP `422` instead of a
successful response carrying an error string. Valid sample-policy and compose
flows remain unchanged.

## Test Strategy

### Edge middleware unit tests

- Declared body of exactly 65,536 bytes is admitted; 65,537 is rejected.
- A streamed body crossing the limit is rejected before the downstream app is
  called.
- A body split into chunks without `Content-Length` is bounded.
- An understated `Content-Length` cannot bypass streamed counting.
- Conflicting and malformed lengths are rejected.
- The total body deadline is enforced with an injected clock/receiver.
- Early `408`, `413`, and `429` responses include CORS and one request ID.
- An unexpected normalized `500` includes CORS but no internal diagnostic.
- Rate buckets refill deterministically and update atomically.
- A 2,049th active identity uses the overflow bucket without growing storage.
- Varied leftmost forwarding values cannot change the selected rightmost
  identity.
- Forwarding headers from an untrusted direct peer are ignored.
- The global bucket limits distributed or spoofed identities.

### YAML unit tests

Test each limit at the boundary and one unit above it. Include malformed YAML,
multiple documents, duplicate keys, merge keys, custom tags, timestamp and
binary construction, non-string keys, `NaN`/infinities, cyclic aliases, deep
nesting, wide collections, high scalar counts, repeated long scalars, and
fan-out that remains below the raw alias limit.

The exact 211-byte reproduction from issue #59 must return `422` from both
`/api/policy/load-inmemory` and the applicable compose side without constructing
or encoding a megabyte response.

### Route and diagnostic tests

- `/api/compose` and `/api/policy/load-inmemory` return stable YAML codes.
- Every checked-in valid demo/sample policy passes the limits.
- Valid Lab 4 and Lab 5 workflows remain usable.
- Injected parser snippets, absolute paths, subprocess stderr, stack traces,
  control characters, and unique secret sentinels appear in logs but nowhere in
  response headers or bodies.
- Negative adapter evidence and workflow-doctor findings expose only their
  allowlisted public projections.
- Expected governance failures use allowlisted public codes/messages.
- Unknown exceptions return no attached artifact.
- Returned finalized artifacts retain valid checksums/signatures and contain
  logical policy references rather than local paths.
- Workflow subprocess timeout and failure paths return stable codes and do not
  retry.
- Response preflight rejects payloads above 262,144 bytes.

### Baseline handling

At design time, the security-adjacent compose/load test subset passes seven
tests. The full demo suite has 38 passes and 61 pre-existing failures caused by
demo/core API drift on current `main`. Implementation verification records that
baseline separately. New issue #59 tests must be green, and any change in the
unrelated failure set must be explained; this issue does not claim the existing
suite is healthy merely because its focused tests pass.

## Deployment and Monitoring

`demo-app-api/render.yaml` records:

- one Uvicorn worker;
- `--no-proxy-headers` so proxy interpretation has one owner;
- the fixed limits in operator-facing documentation; and
- the single-process limiter limitation.

Deployment is incomplete until smoke checks verify valid examples, declared and
streamed `413`, deterministic `429`, malformed-YAML `422`, amplification
rejection, safe errors, CORS on early failures, and forwarding-header behavior.

Operators monitor counts and rates of `408`, `413`, YAML `422`, `429`, `5xx`,
subprocess timeout, limiter overflow use, worker restart, memory use, and
response latency. Request IDs correlate client reports with server logs. A rise
in overflow-bucket or global-limit events is treated as possible distributed
abuse, not as evidence that the application should raise its limits.

## Relationship to Enforcement-Core Security Work

These controls protect the public demo's HTTP, parsing, serialization, and
diagnostic boundaries. They do not replace or weaken:

- #56's no-network/no-filesystem output-schema resolution contract;
- #53's typed and bounded precondition compilation;
- #38's distinction between core conformance guarantees and demo controls; or
- the Track A/Track B compiler and evidence-finalizer invariants in the approved
  enforcement-core remediation design.

Documentation must link issue #59 as a separate demo-edge hardening layer so
core changes cannot claim the public demo is hardened by implication.

## Acceptance Mapping

| Issue criterion | Design mechanism |
| --- | --- |
| Oversized fixed and streamed bodies receive `413` before parsing | Edge pre-buffer, declared-length check, replay boundary |
| YAML alias, anchor, depth, scalar, and aggregate limits return stable `422` | Five-stage bounded YAML contract |
| 211-byte amplification is rejected | Alias and expanded-occurrence budgets |
| Valid policies and compose examples work | Eleven-times byte headroom and sample matrix |
| Per-client `429` and trusted proxy behavior | Client/global buckets, rightmost-hop contract, Render smoke gate |
| No raw client diagnostics or local paths | Stable errors, logical policy refs before evidence finalization |
| Correlated server diagnostics | Server-generated request ID and bounded internal logging |
| No retry of expensive parsing/operations | Fail-once YAML boundary and subprocess timeout contract |
| Required route/error/resource tests | Edge, YAML, route, frontend, and deployment test matrices |
| Deployment limits and monitoring documented | Render and operator sections above |

## Completion Conditions

Issue #59 is complete only when:

1. all new focused tests pass;
2. the valid sample matrix passes;
3. the issue reproduction returns stable `422` without amplified output;
4. no demo-owned direct YAML parse or raw exception/subprocess response remains;
5. returned evidence remains verifiable and path-safe;
6. the Render smoke matrix passes, including forwarding-header behavior;
7. deployment and monitoring documentation is published; and
8. unrelated baseline failures are reported honestly rather than attributed to
   or hidden by this issue.
