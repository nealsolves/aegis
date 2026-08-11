# Issue #59 Demo API Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Harden the public demo API against oversized and adversarial requests, YAML expansion, response amplification, request floods, subprocess exhaustion, and diagnostic disclosure while preserving the demo's valid user flows.

**Architecture:** Put one dependency-free ASGI edge wrapper around CORS and the FastAPI application so rate admission, proxy-aware client identity, request IDs, and total-body enforcement happen before validation and for every HTTP route. Route YAML through one strict bounded loader, construct AEGIS instances through one root-bound demo runtime, preflight amplified responses before serialization, and translate all public failures through a correlated stable error contract while retaining raw details only in server logs.

**Tech Stack:** Python 3.10+, FastAPI, Starlette ASGI, Pydantic, PyYAML 6+, Uvicorn, pytest, React 18, TypeScript, Vitest.

## Global Constraints

- Preserve the exact approved limits in `demo_limits.py`: request body 65,536 bytes, total-body deadline 4 seconds, YAML input 24,576 bytes, 24 anchors, 24 aliases, depth 20, 2,048 scalars, 512 collections, 4,096 expanded occurrences, 131,072 expanded scalar bytes, YAML response 262,144 bytes, per-client token capacity 30/refill 1 per second, global capacity 120/refill 10 per second, 2,048 tracked identities with 300-second idle TTL, subprocess timeout 10 seconds, and diagnostic capture 8,192 bytes.
- The outer application order is `DemoEdgeMiddleware(CORSMiddleware(inner_api, ...))`. Edge failures add CORS headers from the same immutable origin tuple; normal responses receive CORS from Starlette.
- For non-exempt requests, rate admission occurs before header/body work, so an exhausted rate budget returns 429 even when the same request is oversized. `/health` and `OPTIONS` bypass rate charging but remain body-bounded.
- The global rate bucket always applies. `X-Forwarded-For` is honored only when the immediate peer is loopback or private; use the rightmost syntactically valid forwarded address. Uvicorn runs with `--no-proxy-headers`.
- Request IDs are 32 lowercase hexadecimal characters from `secrets.token_hex(16)`, are stored in ASGI scope state and a `ContextVar`, and appear in `X-Request-ID` plus every public error envelope.
- Public non-2xx responses use only `{"detail":{"code":"...","message":"...","request_id":"..."}}`. Never return exception text, parser marks, paths, command lines, stdout, stderr, traceback text, Pydantic input values, or cause chains.
- YAML accepts only the JSON-compatible data model: mappings with unique string keys, lists, strings, finite numbers, booleans, and null. Reject merge keys, custom tags, sets, timestamps, binary values, non-string keys, duplicate keys, cycles, and every configured structural or expansion limit.
- Never redact an artifact after AEGIS finalization because doing so invalidates checksums or signatures. Keep protected paths out before finalization by using root-bound `FilePolicyLoader` instances and logical policy references.
- All demo-owned AEGIS creation supplies an explicit sink. Generated workflow modules receive a module-local `aegis` proxy that injects the root-bound loader and sink without changing installed SDK behavior.
- Subprocesses have one 10-second deadline, no retry, bounded captured diagnostics, and stable timeout/failure projections.
- Do not add a runtime dependency or a distributed rate-limit claim. The implementation supports the current single-worker Render topology; multi-worker deployment requires a shared limiter before scaling worker count.
- Preserve the user's unrelated `.gitignore` modification. Each task stages only its listed files.
- The existing full demo suite has documented pre-existing core/demo drift. Do not expand this issue to repair unrelated failures; new security tests and the previously green security-adjacent subset must pass.

---

## File and responsibility map

- `demo-app-api/demo_limits.py`: immutable numerical limits and public-safe error messages/codes using the exact approved names.
- `demo-app-api/demo_errors.py`: request-ID context, `DemoPublicError`, safe response construction, public error translation, and bounded internal diagnostic logging.
- `demo-app-api/demo_edge.py`: ASGI request admission, client identity, bounded token buckets, total-body buffering/deadline, CORS on edge failures, and request-ID propagation.
- `demo-app-api/bounded_yaml.py`: strict event scanning, construction, expanded-graph validation, cycle detection, JSON-compatible type validation, and response-size preflight.
- `demo-app-api/demo_runtime.py`: root-bound AEGIS factory, discard audit sink, logical policy references, and generated-module proxy.
- `demo-app-api/main.py`: inner FastAPI app, exception handlers, edge/CORS composition, bounded YAML route adoption, logical policy references, and safe route projections.
- `demo-app-api/loaders.py`: in-memory loader delegates YAML parsing to the bounded loader.
- `demo-app-api/demo_adapter_service.py`, `demo-app-api/demo_scenario_service.py`: root-bound AEGIS construction and public-safe errors.
- `demo-app-api/workflow_routes.py`: generated-module containment, bounded subprocess helper, safe doctor/trace projections, and timeout handling.
- `demo-app-api/tests/test_demo_edge.py`: isolated ASGI edge and limiter unit tests.
- `demo-app-api/tests/test_bounded_yaml.py`: adversarial YAML and amplification unit tests.
- `demo-app-api/tests/test_api_security.py`: end-to-end body, error, CORS, YAML, evidence, path, and subprocess security tests.
- Existing demo tests: focused compatibility checks for valid flows touched by this issue.
- `demo-app-react/src/lib/publicError.ts`: one strict public-error parser/type/formatter shared by non-2xx handling and HTTP-200 demo outcomes.
- `demo-app-react/src/hooks/useApi.ts`, `demo-app-react/src/hooks/useApi.test.ts`: safe public error-envelope parsing and hostile-response fallback.
- Affected lab/scenario/adapter components and parsers: consume structured `{code, message, request_id}` outcomes without rendering unknown response values.
- `demo-app-api/render.yaml`, `demo-app-api/README.md`, `SECURITY.md`: single-worker/proxy contract, exact limits, monitoring, operational responses, and relationship to enforcement-core security.
- `scripts/smoke_demo_security.py`: API-only deployment smoke for request/YAML/rate/CORS/proxy controls; the existing page/browser smoke remains unchanged.

---

### Task 1: Central limits and correlated public errors

**Files:**
- Create: `demo-app-api/demo_limits.py`
- Create: `demo-app-api/demo_errors.py`
- Create: `demo-app-api/tests/test_demo_errors.py`

**Interfaces:**
- Produces `REQUEST_BODY_MAX_BYTES`, `REQUEST_BODY_READ_TIMEOUT_SECONDS`, `YAML_MAX_ENCODED_BYTES`, `YAML_MAX_ANCHORS`, `YAML_MAX_ALIASES`, `YAML_MAX_NESTING_DEPTH`, `YAML_MAX_SCALARS`, `YAML_MAX_COLLECTIONS`, `YAML_MAX_EXPANDED_NODES`, `YAML_MAX_EXPANDED_SCALAR_BYTES`, `YAML_RESPONSE_MAX_BYTES`, `CLIENT_RATE_CAPACITY`, `CLIENT_RATE_REFILL_PER_SECOND`, `GLOBAL_RATE_CAPACITY`, `GLOBAL_RATE_REFILL_PER_SECOND`, `RATE_LIMIT_MAX_IDENTITIES`, `RATE_LIMIT_IDENTITY_TTL_SECONDS`, `SUBPROCESS_TIMEOUT_SECONDS`, and `INTERNAL_DIAGNOSTIC_MAX_BYTES` with the approved values.
- Produces `DemoPublicError(code: str, message: str, status_code: int, headers: Mapping[str, str] | None = None)`.
- Produces `REQUEST_ID: ContextVar[str | None]`, `request_id_from_scope(scope) -> str`, `current_request_id() -> str`, `public_error_response(...) -> JSONResponse`, `public_demo_error(code: str) -> dict[str, str]`, `log_internal_failure(...) -> None`, and `safe_demo_message(code: str) -> str`.

- [ ] **Step 1: Add failing contract tests**

Create tests proving the error shape, header, context lookup, absence of exception/path text, and diagnostic truncation:

```python
def test_public_error_response_has_only_stable_detail_fields() -> None:
    response = public_error_response(
        status_code=413,
        code="REQUEST_BODY_TOO_LARGE",
        message=safe_demo_message("REQUEST_BODY_TOO_LARGE"),
        request_id="a" * 32,
    )
    body = json.loads(response.body)
    assert body == {"detail": {
        "code": "REQUEST_BODY_TOO_LARGE",
        "message": "Request body exceeds the demo limit.",
        "request_id": "a" * 32,
    }}
    assert response.headers["x-request-id"] == "a" * 32


def test_internal_failure_logs_request_id_but_bounds_diagnostic(
    caplog: pytest.LogCaptureFixture,
) -> None:
    log_internal_failure("b" * 32, "yaml_parse", ValueError("secret/" + "x" * 9000))
    record = caplog.records[-1]
    assert record.request_id == "b" * 32
    assert len(record.internal_diagnostic.encode("utf-8")) <= INTERNAL_DIAGNOSTIC_MAX_BYTES
```

- [ ] **Step 2: Run the tests to verify RED**

Run:

```bash
PYTHONPATH="$PWD" /Users/neal/Documents/_Shenanigans/_myProjects/aegis/.venv/bin/python -m pytest -q demo-app-api/tests/test_demo_errors.py
```

Expected: collection fails because the two modules do not exist.

- [ ] **Step 3: Implement limits and error primitives**

Use integer/float constants, a read-only code-to-message mapping, a slotted exception, and one response constructor. `log_internal_failure` must truncate UTF-8 without splitting a code point and must log the exception only as a bounded field rather than interpolating it into a public value:

```python
REQUEST_ID: ContextVar[str | None] = ContextVar("demo_request_id", default=None)


class DemoPublicError(Exception):
    def __init__(self, code: str, message: str, status_code: int,
                 headers: Mapping[str, str] | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code
        self.headers = dict(headers or {})


def public_error_response(*, status_code: int, code: str, message: str,
                          request_id: str, headers: Mapping[str, str] | None = None
                          ) -> JSONResponse:
    response_headers = {"X-Request-ID": request_id, **dict(headers or {})}
    return JSONResponse(
        status_code=status_code,
        headers=response_headers,
        content={"detail": {"code": code, "message": message,
                            "request_id": request_id}},
    )
```

`public_demo_error(code)` returns exactly `{"code": code, "message": safe_demo_message(code), "request_id": current_request_id()}` for intentional HTTP-200 governed outcomes. `current_request_id()` must fail closed to a newly generated opaque ID only for non-request test/service calls; normal route execution always inherits the edge-generated context.

Keep messages generic and code-owned. Include the approved codes used later: `INVALID_REQUEST`, `INVALID_CONTENT_LENGTH`, `NOT_FOUND`, `METHOD_NOT_ALLOWED`, `REQUEST_BODY_TIMEOUT`, `REQUEST_BODY_TOO_LARGE`, `UNSUPPORTED_CONTENT_ENCODING`, `YAML_INVALID`, `YAML_UNSUPPORTED_VALUE`, `YAML_CYCLE_REJECTED`, `YAML_LIMIT_EXCEEDED`, `RESPONSE_TOO_LARGE`, `RATE_LIMIT_EXCEEDED`, `DEMO_OPERATION_TIMEOUT`, `DEMO_OPERATION_FAILED`, and `INTERNAL_ERROR`.

- [ ] **Step 4: Run tests to verify GREEN**

Run the command from Step 2. Expected: all tests pass.

- [ ] **Step 5: Commit the error boundary**

```bash
git add demo-app-api/demo_limits.py demo-app-api/demo_errors.py demo-app-api/tests/test_demo_errors.py
git commit -m "feat(demo): add bounded public error contract"
```

---

### Task 2: Strict bounded YAML input and output

**Files:**
- Create: `demo-app-api/bounded_yaml.py`
- Create: `demo-app-api/tests/test_bounded_yaml.py`

**Interfaces:**
- Produces recursive aliases `JsonScalar` and `JsonValue`.
- Produces `load_bounded_yaml(text: str, *, require_mapping: bool = True) -> dict[str, JsonValue] | JsonValue`.
- Produces `ensure_bounded_json_response(payload: JsonValue, *, max_bytes: int = YAML_RESPONSE_MAX_BYTES) -> None`.
- Raises only `DemoPublicError` at its public boundary.

- [ ] **Step 1: Add failing adversarial YAML tests**

Cover each stage independently:

```python
@pytest.mark.parametrize("body", [
    "x: !!python/object/apply:os.system ['id']",
    "x: 2026-08-11",
    "x: !!binary SGVsbG8=",
    "x: !!set {a: null}",
    "{1: value}",
    "x: .nan",
    "x: .inf",
    "base: &base {x: 1}\nmerged: {<<: *base}\n",
    "x: 1\nx: 2\n",
])
def test_rejects_non_json_or_ambiguous_yaml(body: str) -> None:
    with pytest.raises(DemoPublicError) as caught:
        load_bounded_yaml(body)
    assert caught.value.code in {"YAML_INVALID", "YAML_UNSUPPORTED_VALUE"}


def _issue_59_reproduction() -> str:
    width = 6
    lines: list[str] = []
    previous: str | None = None
    for name in "abcdefg":
        values = ["x"] * width if previous is None else [f"*{previous}"] * width
        lines.append(f"{name}: &{name} [" + ", ".join(values) + "]")
        previous = name
    body = "\n".join(lines) + "\n"
    assert len(body.encode("utf-8")) == 211
    return body


def test_rejects_exact_issue_59_expansion_before_response_amplification() -> None:
    body = _issue_59_reproduction()
    with pytest.raises(DemoPublicError) as caught:
        load_bounded_yaml(body)
    assert caught.value.code == "YAML_LIMIT_EXCEEDED"


def test_response_preflight_counts_encoded_json_incrementally() -> None:
    ensure_bounded_json_response({"value": "x" * 32}, max_bytes=64)
    with pytest.raises(DemoPublicError) as caught:
        ensure_bounded_json_response({"value": "x" * 128}, max_bytes=64)
    assert caught.value.code == "RESPONSE_TOO_LARGE"
```

Also add generated tests for encoded-byte length, anchor count, alias count, nested depth, scalar count, collection count, expanded occurrence count, expanded scalar bytes, direct/indirect cycles, malformed syntax, non-mapping root, valid anchors under every limit, and multibyte UTF-8 boundaries. Assert `YAML_INVALID` for syntax, `YAML_UNSUPPORTED_VALUE` for type/tag/key restrictions, `YAML_CYCLE_REJECTED` for cycles, and `YAML_LIMIT_EXCEEDED` for every configured budget.

- [ ] **Step 2: Run the tests to verify RED**

```bash
PYTHONPATH="$PWD" /Users/neal/Documents/_Shenanigans/_myProjects/aegis/.venv/bin/python -m pytest -q demo-app-api/tests/test_bounded_yaml.py
```

Expected: collection fails because `bounded_yaml` does not exist.

- [ ] **Step 3: Implement event scanning and strict construction**

Scan `yaml.parse(text, Loader=yaml.SafeLoader)` before construction. Maintain an explicit collection stack, mapping key/value position, and counts for anchors, aliases, maximum depth, scalar events, and collection-start events. This makes a scalar mapping key equal to `<<` fail whether quoted or unquoted. Reject explicit custom tags and limit violations without including event values or parser marks in the public exception.

Subclass `yaml.SafeLoader` only to narrow behavior. Override mapping construction to reject `<<`, duplicate keys, and non-string keys before inserting values. Do not mutate `yaml.SafeLoader`'s shared class dictionaries. Validate the constructed result recursively so implicit/explicit timestamps, binary values, sets, tuples, and other non-JSON types are rejected and floats must be finite.

- [ ] **Step 4: Validate the expanded object graph and response size**

Walk occurrences, not unique object identities. Track the active object-ID stack to reject cycles, count every list/dict/value occurrence against `YAML_MAX_EXPANDED_NODES`, and sum UTF-8 bytes for every repeated string/key occurrence against `YAML_MAX_EXPANDED_SCALAR_BYTES`.

For response preflight, use `json.JSONEncoder(ensure_ascii=False, allow_nan=False, separators=(",", ":")).iterencode(payload)` and stop as soon as cumulative UTF-8 length exceeds the output limit. Do not allocate a second complete JSON string.

- [ ] **Step 5: Run tests to verify GREEN**

Run the command from Step 2. Expected: all tests pass.

- [ ] **Step 6: Commit bounded YAML**

```bash
git add demo-app-api/bounded_yaml.py demo-app-api/tests/test_bounded_yaml.py
git commit -m "feat(demo): enforce bounded strict YAML"
```

---

### Task 3: ASGI admission, rate limits, and bounded body buffering

**Files:**
- Create: `demo-app-api/demo_edge.py`
- Create: `demo-app-api/tests/test_demo_edge.py`

**Interfaces:**
- Produces `TokenBucketLimiter(*, clock=time.monotonic, client_capacity=CLIENT_RATE_CAPACITY, client_refill=CLIENT_RATE_REFILL_PER_SECOND, global_capacity=GLOBAL_RATE_CAPACITY, global_refill=GLOBAL_RATE_REFILL_PER_SECOND, max_identities=RATE_LIMIT_MAX_IDENTITIES, identity_ttl=RATE_LIMIT_IDENTITY_TTL_SECONDS)` with `admit(identity: str) -> tuple[bool, int]`.
- Produces `DemoEdgeMiddleware(app, *, allowed_origins: tuple[str, ...], limiter: TokenBucketLimiter | None = None, body_timeout_seconds: float = REQUEST_BODY_READ_TIMEOUT_SECONDS)` as a raw ASGI callable. Injectable limiter/timeout seams are for deterministic tests; production construction uses defaults.
- Consumes limits and public response utilities from Tasks 1–2.

- [ ] **Step 1: Add deterministic limiter tests**

Inject a fake monotonic clock. Prove per-client and global exhaustion, fractional refill, global isolation from identity churn, TTL pruning, the 2,048-identity bound, overflow-bucket behavior, and integer `Retry-After` rounded up to at least one second.

```python
def test_global_bucket_applies_across_distinct_clients(fake_clock: FakeClock) -> None:
    limiter = TokenBucketLimiter(clock=fake_clock, client_capacity=1000,
                                 global_capacity=2)
    assert limiter.admit("192.0.2.1")[0]
    assert limiter.admit("192.0.2.2")[0]
    admitted, retry_after = limiter.admit("192.0.2.3")
    assert not admitted
    assert retry_after == 1
```

- [ ] **Step 2: Add isolated ASGI middleware tests**

Use a tiny echo ASGI app and handcrafted HTTP scopes/receive messages. Prove:

- fixed and multi-chunk bodies over 65,536 bytes return 413 and never call the inner app;
- a missing/lying `Content-Length` cannot bypass streamed counting;
- an oversized declared `Content-Length` short-circuits without reading;
- conflicting repeated values, negative values, and non-decimal `Content-Length` return `400 INVALID_CONTENT_LENGTH` without reading;
- any non-identity `Content-Encoding`, including stacked encodings, returns `415 UNSUPPORTED_CONTENT_ENCODING` without decompression;
- a receive callable that outlives an injected 10-millisecond body deadline produces 408 without waiting four seconds;
- accepted input is replayed once to the inner app with correct `more_body` semantics;
- rate exhaustion is checked before the oversized-header/body path and returns 429;
- `/health` and `OPTIONS` avoid token charging but still return 413 for oversized bodies;
- direct public peers cannot influence identity using `X-Forwarded-For`;
- loopback/private peers use the rightmost valid forwarded address, ignoring malformed elements;
- every response gets one valid request ID, replacing untrusted inbound IDs;
- edge failures add allow-origin/vary headers only for configured origins;
- an unknown-origin CORS preflight is normalized to `400 INVALID_REQUEST` after its body is bounded, while an allowed preflight succeeds through `CORSMiddleware`.

- [ ] **Step 3: Run edge tests to verify RED**

```bash
PYTHONPATH="$PWD" /Users/neal/Documents/_Shenanigans/_myProjects/aegis/.venv/bin/python -m pytest -q demo-app-api/tests/test_demo_edge.py
```

Expected: collection fails because `demo_edge` does not exist.

- [ ] **Step 4: Implement bounded token buckets and identity selection**

Use a lock around limiter state because sync endpoints may run concurrently. Store `_Bucket(tokens: float, updated_at: float, last_seen: float)` records in insertion-ordered identity storage. Prune idle entries before admitting a new identity; when still full, charge a single overflow bucket rather than allocating attacker-controlled keys. Always charge the global bucket and the selected client/overflow bucket atomically; do not partially consume if either denies admission.

Parse peer and forwarded addresses with `ipaddress.ip_address`. Trust forwarded input only when the peer is `is_private` or `is_loopback`. Scan XFF right-to-left and select the first valid IP; otherwise use the peer or the fixed `unknown` identity.

- [ ] **Step 5: Implement pre-buffering and deadline behavior**

For HTTP scopes only: mint request ID, attach it to `scope.setdefault("state", {})["request_id"]`, set the `ContextVar`, perform rate admission, validate all `Content-Length` fields, reject non-identity `Content-Encoding`, and read at most `REQUEST_BODY_MAX_BYTES + 1` bytes. Put the complete receive loop in one coroutine and wrap that coroutine with Python-3.10-compatible `asyncio.wait_for(..., timeout=REQUEST_BODY_READ_TIMEOUT_SECONDS)` so the deadline covers the total body rather than each chunk. Reject disconnects and timeouts safely. Replay the accepted bytes through a private receive callable; never forward the original receive after buffering. Await the inner app before resetting the `ContextVar` token in `finally`, allowing AnyIO's sync-route threadpool copy to retain correlation.

After body buffering, detect a true CORS preflight (`OPTIONS` plus `Origin` and `Access-Control-Request-Method`); reject a non-allowlisted origin with the stable envelope, and pass an allowlisted preflight to CORS. Wrap `send` to add `X-Request-ID` to all `http.response.start` messages and track whether response start was sent. For edge failures before response start, use `public_error_response` and add CORS from the supplied immutable allowlist. Catch exceptions escaping the entire CORS/FastAPI stack: log the bounded internal diagnostic with method and identity-source metadata, return `500 INTERNAL_ERROR` only if no response has started, and re-raise without a second send if FastAPI's error middleware already sent the normalized response.

- [ ] **Step 6: Run edge tests to verify GREEN**

Run the command from Step 3. Expected: all tests pass.

- [ ] **Step 7: Commit the edge boundary**

```bash
git add demo-app-api/demo_edge.py demo-app-api/tests/test_demo_edge.py
git commit -m "feat(demo): add bounded ASGI admission edge"
```

---

### Task 4: Compose the edge with FastAPI and normalize framework errors

**Files:**
- Modify: `demo-app-api/main.py`
- Create: `demo-app-api/tests/test_api_security.py`
- Modify: `demo-app-api/tests/test_api.py`

**Interfaces:**
- Exports `api: FastAPI` for route registration and `app: ASGIApp` for Uvicorn/TestClient.
- Registers handlers for `DemoPublicError`, `RequestValidationError`, `HTTPException`, and uncaught `Exception` on `api`.
- Uses one `ALLOWED_ORIGINS: tuple[str, ...]` passed to both CORS and the edge.

- [ ] **Step 1: Add failing integration tests**

Use `TestClient(main.app, raise_server_exceptions=False)` and assert:

```python
def assert_safe_error(response, status: int, code: str) -> str:
    assert response.status_code == status
    detail = response.json()["detail"]
    assert set(detail) == {"code", "message", "request_id"}
    assert detail["code"] == code
    assert response.headers["x-request-id"] == detail["request_id"]
    assert re.fullmatch(r"[0-9a-f]{32}", detail["request_id"])
    return detail["request_id"]


def test_validation_error_does_not_echo_hostile_input(client: TestClient) -> None:
    marker = "/private/secret-policy.yaml"
    response = client.post("/api/enforce", json={"scenario_key": marker})
    assert_safe_error(response, 422, "INVALID_REQUEST")
    assert marker not in response.text
```

Add tests for fixed/chunked 413 before Pydantic, stable malformed JSON, unknown scenario/key/index errors, uncaught-exception normalization, request-ID correlation in captured logs, CORS on edge 413/429, no CORS reflection for an unknown origin, OPTIONS body bounding, and health rate exemption.

- [ ] **Step 2: Run focused tests to verify RED**

```bash
PYTHONPATH="$PWD" /Users/neal/Documents/_Shenanigans/_myProjects/aegis/.venv/bin/python -m pytest -q demo-app-api/tests/test_api_security.py -k 'body or validation or cors or request_id'
```

Expected: tests fail because the app is still FastAPI with route-local/default error behavior.

- [ ] **Step 3: Refactor application assembly without changing routes**

Rename the inner instance to `api`, update every decorator/include call from `app` to `api`, and assemble after all routes are registered:

```python
ALLOWED_ORIGINS = (
    "https://nealsolves.github.io",
    "http://localhost:5173",
    "http://localhost:3000",
)

cors_app = CORSMiddleware(
    api,
    allow_origins=list(ALLOWED_ORIGINS),
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Request-ID", "Retry-After"],
)
app = DemoEdgeMiddleware(cors_app, allowed_origins=ALLOWED_ORIGINS)
```

Do not use `api.add_middleware(CORSMiddleware, ...)`: it would put CORS inside FastAPI but would not share explicit assembly order with the raw edge.

- [ ] **Step 4: Add stable FastAPI exception handlers**

Read `request.state.request_id`; never serialize `exc.detail`, `exc.errors()`, or `str(exc)`. Map request validation to `INVALID_REQUEST`, unknown routes to `NOT_FOUND`, and methods to `METHOD_NOT_ALLOWED`. Log normalized failures with request ID, method, matched route template when present, public code, exception class, and a bounded control-character-safe diagnostic; do not log bodies, sensitive headers, or raw forwarding chains. Recognized demo-operation failures raise `DemoPublicError(code="DEMO_OPERATION_FAILED", ...)`; the catch-all FastAPI handler returns `INTERNAL_ERROR`, which is the already-started normalized response if Starlette re-raises to the outer edge. `DemoPublicError` preserves its explicit status/code/message and optional headers.

- [ ] **Step 5: Run integration and existing API smoke tests**

```bash
PYTHONPATH="$PWD" /Users/neal/Documents/_Shenanigans/_myProjects/aegis/.venv/bin/python -m pytest -q demo-app-api/tests/test_api_security.py -k 'body or validation or cors or request_id'
PYTHONPATH="$PWD" /Users/neal/Documents/_Shenanigans/_myProjects/aegis/.venv/bin/python -m pytest -q demo-app-api/tests/test_api.py -k 'health or scenarios or policies'
```

Expected: selected tests pass.

- [ ] **Step 6: Commit app composition**

```bash
git add demo-app-api/main.py demo-app-api/tests/test_api_security.py demo-app-api/tests/test_api.py
git commit -m "feat(demo): compose edge and safe API errors"
```

---

### Task 5: Adopt bounded YAML at every demo boundary

**Files:**
- Modify: `demo-app-api/loaders.py`
- Modify: `demo-app-api/main.py`
- Modify: `demo-app-api/tests/test_bounded_yaml.py`
- Modify: `demo-app-api/tests/test_api_security.py`
- Modify: `demo-app-api/tests/test_api.py`

**Interfaces:**
- `InMemoryPolicyLoader.load()` delegates to `load_bounded_yaml` and returns a detached mapping.
- `/api/policy/load` and `/api/policy/load-inmemory` call the same bounded loader.
- Any YAML-derived response calls `ensure_bounded_json_response` before FastAPI serialization.

- [ ] **Step 1: Add failing route-boundary tests**

Prove `/api/compose` (both documents), `/api/policy/load-inmemory`, direct `InMemoryPolicyLoader` construction, and `/api/policy/load` reject malformed/custom/duplicate/merge/oversized/expanding input with the stable envelope; use `_issue_59_reproduction()` for both public input endpoints and assert `422 YAML_LIMIT_EXCEEDED` with response size far below 262,144 bytes. Prove a valid policy round-trips, disk-loaded YAML is governed by the same parser, and a response over 262,144 bytes returns `422 RESPONSE_TOO_LARGE` without serializing the expanded payload. Run every checked-in demo/sample policy and the checked-in compose pair through the bounded parser as a valid-sample matrix.

Add a guard test that searches demo Python sources for direct `yaml.safe_load`, `yaml.full_load`, and `yaml.load` calls outside `bounded_yaml.py` and fails with the violating path/line.

- [ ] **Step 2: Run YAML integration tests to verify RED**

```bash
PYTHONPATH="$PWD" /Users/neal/Documents/_Shenanigans/_myProjects/aegis/.venv/bin/python -m pytest -q demo-app-api/tests/test_api_security.py -k yaml
```

Expected: hostile YAML is accepted or exposes parser diagnostics.

- [ ] **Step 3: Replace direct parsing and unsafe route projections**

Use UTF-8 byte checks before parsing files. Convert expected demo-form validation failures to stable `DemoPublicError`; never return `str(exc)`. In `/api/compose`, bound both source documents, call `merge_policies`, remove composition-only fields, and call `yaml.safe_dump()` only after expanded-graph validation; `safe_dump` is the sole permitted demo-owned YAML dump. Run output preflight on the complete response, including `merged_yaml`, `escalations`, `diff`, `policy`, and any echoed YAML text, before returning it. Retain the lab's valid `yaml_text` echo only when it is within the input limit and parsed successfully.

- [ ] **Step 4: Run focused and compatibility tests**

```bash
PYTHONPATH="$PWD" /Users/neal/Documents/_Shenanigans/_myProjects/aegis/.venv/bin/python -m pytest -q demo-app-api/tests/test_bounded_yaml.py demo-app-api/tests/test_api_security.py -k yaml
PYTHONPATH="$PWD" /Users/neal/Documents/_Shenanigans/_myProjects/aegis/.venv/bin/python -m pytest -q demo-app-api/tests/test_api.py -k 'policy_load or inmemory'
```

Expected: all new YAML tests pass; touched valid-flow tests pass after updating only assertions intentionally changed by the stable error contract.

- [ ] **Step 5: Commit YAML adoption**

```bash
git add demo-app-api/loaders.py demo-app-api/main.py demo-app-api/tests/test_bounded_yaml.py demo-app-api/tests/test_api_security.py demo-app-api/tests/test_api.py
git commit -m "feat(demo): route YAML through bounded loader"
```

---

### Task 6: Root-bound demo runtime and evidence confidentiality

**Files:**
- Create: `demo-app-api/demo_runtime.py`
- Modify: `demo-app-api/main.py`
- Modify: `demo-app-api/demo_adapter_service.py`
- Modify: `demo-app-api/demo_scenario_service.py`
- Modify: `demo-app-api/workflow_routes.py`
- Modify: `demo-app-api/tests/test_api_security.py`
- Modify: `demo-app-api/tests/test_demo_adapters.py`
- Modify: `demo-app-api/tests/test_demo_scenarios.py`
- Modify: `demo-app-api/tests/test_workflow_routes.py`

**Interfaces:**
- Produces `demo_aegis(policy_root: str | Path, **kwargs: Any) -> AEGIS`.
- Produces `logical_policy_ref(policy_root: Path, policy_path: Path) -> str`.
- Produces `DemoAegisModuleProxy(original_module: ModuleType, policy_root: Path)` with delegated attributes and an `AEGIS` factory method.

- [ ] **Step 1: Add failing evidence/path tests**

Test that every successful/failed artifact returned by enforce, sign, chain, labs, adapters, scenarios, and workflows contains no absolute demo root, temp root, `/private/`, `/tmp/`, or `policy_file` value outside the logical reference. Recursively inspect keys and string values. Also monkeypatch `main.AEGIS`, service `AEGIS`, or module generation seams to fail if any demo code constructs AEGIS without a sink and root-bound `FilePolicyLoader`.

For generated workflow modules, assert the proxy receives `policy.yaml`, the installed `aegis` module remains unchanged, and the finalized artifact verifies before response delivery.

- [ ] **Step 2: Run focused tests to verify RED**

```bash
PYTHONPATH="$PWD" /Users/neal/Documents/_Shenanigans/_myProjects/aegis/.venv/bin/python -m pytest -q demo-app-api/tests/test_api_security.py -k 'path or evidence or sink' demo-app-api/tests/test_workflow_routes.py -k regulated
```

Expected: absolute paths appear and several AEGIS constructors omit a sink/loader.

- [ ] **Step 3: Implement the root-bound factory and logical references**

Each factory call creates a `CallbackAuditSink(lambda _artifact: None)` and `FilePolicyLoader(Path(policy_root).resolve())`; reject `sink` and `policy_loader` overrides to keep the authority single and explicit. Preserve legitimate keyword arguments such as signer, custom gates, risk config, and evidence profile.

```python
def demo_aegis(policy_root: str | Path, **kwargs: Any) -> AEGIS:
    if "sink" in kwargs or "policy_loader" in kwargs:
        raise TypeError("demo_aegis owns sink and policy_loader")
    return AEGIS(
        sink=CallbackAuditSink(lambda _artifact: None),
        policy_loader=FilePolicyLoader(policy_root),
        **kwargs,
    )
```

Where a route intentionally needs a JSONL sink, add a separate `demo_aegis_with_sink(policy_root, sink, **kwargs)` that still owns the loader; do not weaken `demo_aegis` with arbitrary authority injection.

- [ ] **Step 4: Convert static demo routes and services**

Use root-relative policy names (`medical_ai.yaml`, scenario policy basename, preset basename) in invocation/session/test-case structures. Construct the engine with the directory as its policy root. Remove the obsolete `"output": {}` field from every `enforce_step_pre_call` invocation in `workflow_routes.py`; post-call output continues through `enforce_step_post_call`. Convert public expected-error fields to `{code, message, request_id}` objects with code-owned demo messages while leaving full details in correlated logs.

- [ ] **Step 5: Contain generated workflow modules before execution**

After loading a generated module, replace only that module object's `aegis` global with `DemoAegisModuleProxy(mod.aegis, starter_dir)`. The proxy delegates all non-AEGIS attributes and injects a root-bound loader/sink when generated code calls `aegis.AEGIS(...)`. The checked-in starter contract accepts an optional policy reference, so invoke `run_regulated_workflow("policy.yaml")` explicitly. Never edit finalized artifacts.

- [ ] **Step 6: Run confidentiality and touched-flow tests**

```bash
PYTHONPATH="$PWD" /Users/neal/Documents/_Shenanigans/_myProjects/aegis/.venv/bin/python -m pytest -q demo-app-api/tests/test_api_security.py -k 'path or evidence or sink' demo-app-api/tests/test_demo_adapters.py demo-app-api/tests/test_demo_scenarios.py demo-app-api/tests/test_workflow_routes.py
```

Expected: new confidentiality tests pass. If an unrelated pre-existing assertion still reflects core/demo drift, record it in the final baseline report rather than weakening the security boundary.

- [ ] **Step 7: Commit root-bound runtime**

```bash
git add demo-app-api/demo_runtime.py demo-app-api/main.py demo-app-api/demo_adapter_service.py demo-app-api/demo_scenario_service.py demo-app-api/workflow_routes.py demo-app-api/tests/test_api_security.py demo-app-api/tests/test_demo_adapters.py demo-app-api/tests/test_demo_scenarios.py demo-app-api/tests/test_workflow_routes.py
git commit -m "feat(demo): contain policy paths before finalization"
```

---

### Task 7: Bound workflow subprocesses and diagnostic projections

**Files:**
- Modify: `demo-app-api/workflow_routes.py`
- Modify: `demo-app-api/tests/test_workflow_routes.py`
- Modify: `demo-app-api/tests/test_api_security.py`

**Interfaces:**
- Produces `_run_demo_subprocess(args: Sequence[str], *, request_id: str) -> subprocess.CompletedProcess[str]`.
- Produces `_safe_doctor_findings(raw: object, *, starter_dir: Path) -> list[dict[str, str]]`.
- All workflow subprocess failure paths raise `DemoPublicError` or return approved demo-level errors, never raw diagnostics.

- [ ] **Step 1: Add failing timeout and disclosure tests**

Monkeypatch `subprocess.run` to assert `timeout=SUBPROCESS_TIMEOUT_SECONDS`, `capture_output=True`, `text=True`, and no retry. Raise `TimeoutExpired` containing hostile stdout/stderr/path text and assert a 503 `DEMO_OPERATION_TIMEOUT` response contains none of it. Return nonzero/malformed outputs for init, doctor, and trace; assert stable failures, bounded internal logs with the same request ID, and no command or path disclosure.

Test doctor allowlisting with hostile extra fields:

```python
raw = [{
    "code": "MISSING_SOURCE_IDS",
    "severity": "ERROR",
    "message": "Add source IDs",
    "next_action": "Edit workflow_example.py",
    "target_kind": "workflow",
    "path": "/private/secret/workflow_example.py",
    "traceback": "secret",
}]
assert _safe_doctor_findings(raw, starter_dir=starter) == [{
    "code": "MISSING_SOURCE_IDS",
    "severity": "ERROR",
    "message": "Add source IDs",
    "next_action": "Edit workflow_example.py",
    "target_kind": "workflow",
}]
```

- [ ] **Step 2: Run tests to verify RED**

```bash
PYTHONPATH="$PWD" /Users/neal/Documents/_Shenanigans/_myProjects/aegis/.venv/bin/python -m pytest -q demo-app-api/tests/test_workflow_routes.py demo-app-api/tests/test_api_security.py -k 'timeout or subprocess or doctor or trace'
```

Expected: subprocess calls have no timeout and raw diagnostics leak.

- [ ] **Step 3: Implement one subprocess boundary**

Call `subprocess.run` once with the exact timeout. Catch `TimeoutExpired` and `OSError`, log only a bounded diagnostic with the request ID from the context, and raise the stable public error without chaining. For nonzero exits, log bounded stdout/stderr internally; let callers decide whether a documented nonzero code (doctor findings) is valid.

- [ ] **Step 4: Project doctor and trace outputs**

Doctor accepts only a list of mappings and emits only the five allowlisted scalar fields; reject nested or unexpected types. Normalize any path-like values in approved messages/actions to logical basenames or fixed copy. Trace accepts a nonempty list of JSON-compatible mappings, preflights response size, and returns a fixed failure for empty/malformed output. No endpoint returns subprocess stdout/stderr.

- [ ] **Step 5: Run tests to verify GREEN**

Run the command from Step 2. Expected: all focused tests pass.

- [ ] **Step 6: Commit subprocess hardening**

```bash
git add demo-app-api/workflow_routes.py demo-app-api/tests/test_workflow_routes.py demo-app-api/tests/test_api_security.py
git commit -m "feat(demo): bound workflow subprocess diagnostics"
```

---

### Task 8: Parse only the safe frontend error contract

**Files:**
- Create: `demo-app-react/src/lib/publicError.ts`
- Create: `demo-app-react/src/lib/publicError.test.ts`
- Modify: `demo-app-react/src/hooks/useApi.ts`
- Modify: `demo-app-react/src/hooks/useApi.test.ts`
- Modify: `demo-app-react/src/lib/demoApi.ts`
- Modify: `demo-app-react/src/lib/demoApi.test.ts`
- Modify: `demo-app-react/src/types/demo.ts`
- Modify: `demo-app-react/src/labs/parseAdapterRunResponse.ts`
- Modify: `demo-app-react/src/routes/scenarios/parseScenarioRunResponse.ts`
- Modify: `demo-app-react/src/labs/Lab1RiskScoring.tsx`
- Modify: `demo-app-react/src/labs/Lab1RiskScoring.test.tsx`
- Modify: `demo-app-react/src/labs/Lab2Signing.tsx`
- Modify: `demo-app-react/src/labs/Lab4Composition.tsx`
- Modify: `demo-app-react/src/labs/Lab5Loaders.tsx`
- Modify: `demo-app-react/src/labs/Lab6CustomGates.tsx`
- Modify: `demo-app-react/src/labs/Lab8GovernedKnowledgeBase.tsx`
- Modify: `demo-app-react/src/labs/Lab9GovernedVsUngoverned.tsx`
- Modify: `demo-app-react/src/labs/Lab10SplitEnforcementExplorer.tsx`
- Modify: `demo-app-react/src/labs/Lab10SplitEnforcementExplorer.test.tsx`
- Modify: `demo-app-react/src/labs/Lab11WorkflowLab.tsx`
- Modify: `demo-app-react/src/labs/Lab11WorkflowLab.test.tsx`
- Modify: `demo-app-react/src/labs/Lab12IntegrationAdapters.test.tsx`
- Modify: `demo-app-react/src/routes/scenarios/ScenarioPage.test.tsx`

**Interfaces:**
- Produces `PublicDemoError { code: string; message: string; request_id: string }`, `parsePublicDemoError(value: unknown) -> PublicDemoError | null`, `formatPublicDemoError(value: unknown) -> string | null`, and `parsePublicApiError(response: Response) -> Promise<string>`.
- Displays approved `detail.message` and request ID only when the complete envelope validates; otherwise displays `Request failed (<status>).` for non-2xx responses or a fixed `The demo service returned an invalid error response.` for malformed HTTP-200 outcome fields.

- [ ] **Step 1: Add failing frontend tests**

Cover a valid safe envelope, malformed JSON, arbitrary `detail` strings, hostile nested fields, missing/invalid request ID, malformed HTTP-200 outcome error objects, and server status text containing sensitive content:

```typescript
it('uses only a complete safe error envelope', async () => {
  fetchMock.mockResolvedValue(new Response(JSON.stringify({
    detail: {code: 'RATE_LIMIT_EXCEEDED', message: 'Please try again shortly.', request_id: 'a'.repeat(32)},
    traceback: '/private/secret',
  }), {status: 429, statusText: '/private/secret'}));
  // render hook and trigger request
  expect(result.current.error).toBe('Please try again shortly. (request aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa)');
  expect(result.current.error).not.toContain('/private/');
});

it('falls back without echoing an unknown response body', async () => {
  fetchMock.mockResolvedValue(new Response('{"detail":"/private/secret"}', {status: 500}));
  // render hook and trigger request
  expect(result.current.error).toBe('Request failed (500).');
});

it('formats a validated HTTP-200 demo outcome without unknown fields', () => {
  expect(formatPublicDemoError({
    code: 'AEGIS_ENFORCEMENT_FAILED',
    message: 'The governed operation was rejected.',
    request_id: 'b'.repeat(32),
    diagnostic: '/private/secret',
  })).toBe('The governed operation was rejected. (request bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb)')
})
```

- [ ] **Step 2: Run frontend tests to verify RED**

```bash
cd demo-app-react
npm test -- --run src/lib/publicError.test.ts src/hooks/useApi.test.ts src/lib/demoApi.test.ts
```

Expected: `useApi` exposes status text/generic old formatting and the two clients differ.

- [ ] **Step 3: Implement one strict parser and adopt it**

Validate that `detail` is a plain object, code is a 1–64 character `[A-Z0-9_]+` string, message is a 1–512 character string without control characters, and request ID matches `/^[0-9a-f]{32}$/`. Ignore all other fields. Do not use `response.statusText`, raw body text, arbitrary `detail`, or JSON parse errors. Share the helper between `useApi` and `demoApi` rather than maintaining two contracts.

Change scenario/adapter `error` types and parsers to require `request_id` in addition to code/message. Change every legacy lab response interface from `error: string | null` to `error: PublicDemoError | null` and render it only through `formatPublicDemoError`. Update fixtures to structured fixed errors; add representative component assertions that hostile extra fields never render. Network errors maintained locally by `useApi` remain `string | null` and are not conflated with server outcome errors.

- [ ] **Step 4: Run frontend tests to verify GREEN**

Run the command from Step 2. Expected: all tests pass.

- [ ] **Step 5: Commit frontend compatibility**

```bash
git add demo-app-react/src/lib/publicError.ts demo-app-react/src/lib/publicError.test.ts \
  demo-app-react/src/hooks/useApi.ts demo-app-react/src/hooks/useApi.test.ts \
  demo-app-react/src/lib/demoApi.ts demo-app-react/src/lib/demoApi.test.ts \
  demo-app-react/src/types/demo.ts \
  demo-app-react/src/labs/parseAdapterRunResponse.ts \
  demo-app-react/src/routes/scenarios/parseScenarioRunResponse.ts \
  demo-app-react/src/labs/Lab1RiskScoring.tsx demo-app-react/src/labs/Lab1RiskScoring.test.tsx \
  demo-app-react/src/labs/Lab2Signing.tsx demo-app-react/src/labs/Lab4Composition.tsx \
  demo-app-react/src/labs/Lab5Loaders.tsx demo-app-react/src/labs/Lab6CustomGates.tsx \
  demo-app-react/src/labs/Lab8GovernedKnowledgeBase.tsx \
  demo-app-react/src/labs/Lab9GovernedVsUngoverned.tsx \
  demo-app-react/src/labs/Lab10SplitEnforcementExplorer.tsx \
  demo-app-react/src/labs/Lab10SplitEnforcementExplorer.test.tsx \
  demo-app-react/src/labs/Lab11WorkflowLab.tsx demo-app-react/src/labs/Lab11WorkflowLab.test.tsx \
  demo-app-react/src/labs/Lab12IntegrationAdapters.test.tsx \
  demo-app-react/src/routes/scenarios/ScenarioPage.test.tsx
git commit -m "fix(demo-ui): consume safe API error envelopes"
```

---

### Task 9: Deployment contract, operations, and security documentation

**Files:**
- Modify: `demo-app-api/render.yaml`
- Create: `demo-app-api/README.md`
- Modify: `SECURITY.md`
- Create: `scripts/smoke_demo_security.py`

**Interfaces:**
- Render start command explicitly disables proxy-header rewriting and runs one worker.
- API-only security smoke checks health, stable errors, declared/streamed request size, deterministic rate exhaustion, CORS, forwarding trust, amplification rejection, and a valid YAML flow without changing the existing frontend/browser smoke.

- [ ] **Step 1: Add smoke assertions before deployment edits**

Create a standard-library script accepting `--api-url`, `--timeout`, `--rate-probe-count`, and `--expect-forwarding-proxy`. It must assert a valid health response, one 65,537-byte declared request and one streamed request return 413, malformed/expanding YAML returns a safe 422 envelope with matching header/request ID, an allowed origin receives CORS on failure, an unknown origin is not reflected, and no response contains the submitted hostile marker. With `--expect-forwarding-proxy`, vary attacker-controlled leftmost XFF entries and verify they do not create independent buckets because the deployment proxy appends the stable rightmost client hop. Without the flag, omit XFF so direct local-loopback trust does not invalidate the test. Use fresh connections where required, run the deterministic 429 probe last, and stop immediately after the expected denial.

- [ ] **Step 2: Run the smoke script against a local server to verify RED**

In terminal 1:

```bash
PYTHONPATH="$PWD" /Users/neal/Documents/_Shenanigans/_myProjects/aegis/.venv/bin/python -m uvicorn main:app --app-dir demo-app-api --host 127.0.0.1 --port 8000 --no-proxy-headers
```

In terminal 2:

```bash
PYTHONPATH="$PWD" /Users/neal/Documents/_Shenanigans/_myProjects/aegis/.venv/bin/python scripts/smoke_demo_security.py --api-url http://127.0.0.1:8000
```

Expected before finishing this task: any missing smoke assertion or deployment contract fails clearly.

- [ ] **Step 3: Pin the Render process contract**

Set the start command to:

```yaml
startCommand: uvicorn main:app --app-dir demo-app-api --host 0.0.0.0 --port $PORT --workers 1 --no-proxy-headers
```

- [ ] **Step 4: Document exact operational behavior**

In `demo-app-api/README.md`, document every central limit, stable error format, request-ID lookup, rate semantics, health/OPTIONS exception, rightmost-XFF trust rule, single-worker requirement, why scale-out needs a shared limiter, body/YAML/rate/subprocess monitoring signals, and a rollback/incident checklist. State that the immediate upstream proxy must strip client-supplied forwarding headers and append its own address.

In `SECURITY.md`, describe the public-demo edge as defense in depth and link it to the separate enforcement-core security boundary; do not imply that demo limits change SDK policy-enforcement semantics.

- [ ] **Step 5: Re-run the local smoke script**

Use the commands from Step 2. Expected: security smoke passes with no server traceback or diagnostic content in responses. Run the existing combined frontend/browser smoke separately in deployment using its unchanged `--frontend-url` and `--api-url` interface.

- [ ] **Step 6: Commit deployment/docs**

```bash
git add demo-app-api/render.yaml demo-app-api/README.md SECURITY.md scripts/smoke_demo_security.py
git commit -m "docs(demo): define hardened deployment contract"
```

---

### Task 10: Final adversarial verification and issue acceptance audit

**Files:**
- Modify: `demo-app-api/tests/test_demo_edge.py`
- Modify: `demo-app-api/tests/test_bounded_yaml.py`
- Modify: `demo-app-api/tests/test_api_security.py`
- Modify: `demo-app-api/tests/test_workflow_routes.py`
- Modify: `demo-app-react/src/hooks/useApi.test.ts`
- Create: `docs/superpowers/reports/2026-08-11-issue-59-demo-api-hardening-verification.md`

**Interfaces:**
- Produces a verification report mapping every issue acceptance criterion to a passing command/test and separately recording pre-existing unrelated baseline failures.

- [ ] **Step 1: Run static security searches**

```bash
rg -n 'yaml\.(safe_load|full_load|load)\(' demo-app-api --glob '*.py' --glob '!bounded_yaml.py'
rg -n 'HTTPException\([^\n]*detail=(str\(|f")|"error": str\(|stderr|stdout' demo-app-api --glob '*.py'
rg -n 'AEGIS\(' demo-app-api --glob '*.py'
rg -n 'subprocess\.run\(' demo-app-api --glob '*.py'
```

Expected: no direct YAML parser outside the bounded module; no raw exception/diagnostic public projections; all demo-owned AEGIS calls are in the factory/proxy or intentionally use the root-bound factory; all subprocess calls route through the bounded helper.

- [ ] **Step 2: Run the complete new security suite**

```bash
PYTHONPATH="$PWD" /Users/neal/Documents/_Shenanigans/_myProjects/aegis/.venv/bin/python -m pytest -q \
  demo-app-api/tests/test_demo_errors.py \
  demo-app-api/tests/test_bounded_yaml.py \
  demo-app-api/tests/test_demo_edge.py \
  demo-app-api/tests/test_api_security.py \
  demo-app-api/tests/test_workflow_routes.py
```

Expected: all pass.

- [ ] **Step 3: Run the previously green security-adjacent subset**

Re-run the exact seven-test subset recorded during design discovery:

```bash
PYTHONPATH="$PWD" /Users/neal/Documents/_Shenanigans/_myProjects/aegis/.venv/bin/python -m pytest -q demo-app-api/tests/test_api.py -k 'compose or policy_load or load_inmemory'
```

Expected: the same seven valid YAML/load tests pass, with assertions updated only where issue #59 intentionally changes an error from HTTP 200/raw text to HTTP 422/stable envelope.

- [ ] **Step 4: Run touched backend and frontend suites**

```bash
PYTHONPATH="$PWD" /Users/neal/Documents/_Shenanigans/_myProjects/aegis/.venv/bin/python -m pytest -q \
  demo-app-api/tests/test_api.py \
  demo-app-api/tests/test_demo_adapters.py \
  demo-app-api/tests/test_demo_scenarios.py \
  demo-app-api/tests/test_workflow_routes.py
cd demo-app-react
npm test -- --run src/hooks/useApi.test.ts src/lib/demoApi.test.ts
```

Expected: touched valid flows pass. Any failure must be classified as introduced, intentionally changed contract, or pre-existing core/demo drift before proceeding.

- [ ] **Step 5: Re-run the full demo baseline without hiding drift**

```bash
PYTHONPATH="$PWD" /Users/neal/Documents/_Shenanigans/_myProjects/aegis/.venv/bin/python -m pytest -q demo-app-api/tests
```

Compare against the recorded pre-change baseline of 38 passed and 61 failed. The security work must not add a new failure category. Record remaining failures by root cause; do not describe the full suite as green if unrelated drift remains.

- [ ] **Step 6: Perform a bounded live adversarial smoke**

Start Uvicorn with the production flags and run `scripts/smoke_demo_security.py`; it sends the declared/chunked oversized bodies, alias-expansion YAML, hostile malformed YAML marker, rate probe, forwarding probe, and allowed/disallowed origins. Confirm 413/422/429 ordering as applicable, matching request IDs, correct CORS, bounded output, and no server path/diagnostic disclosure.

- [ ] **Step 7: Write the acceptance report**

For each issue criterion, record: implementation file, test node/command, observed result, and any deployment assumption. Include the single-worker/shared-store caveat, proxy contract, unchanged artifact-integrity rule, and the pre-existing baseline table. Do not claim resolution of enforcement-core resource limits outside issue #59.

- [ ] **Step 8: Run formatting/type checks already configured by the repository**

Discover configured commands from `pyproject.toml` and `demo-app-react/package.json`; run only repository-defined lint/type/format checks. Apply mechanical formatting only to issue files and rerun the relevant tests after any formatter change.

- [ ] **Step 9: Commit only verification artifacts or test gaps**

```bash
git add docs/superpowers/reports/2026-08-11-issue-59-demo-api-hardening-verification.md \
  demo-app-api/tests/test_demo_edge.py demo-app-api/tests/test_bounded_yaml.py \
  demo-app-api/tests/test_api_security.py demo-app-api/tests/test_workflow_routes.py \
  demo-app-react/src/hooks/useApi.test.ts
git commit -m "test(demo): verify issue 59 hardening"
```

- [ ] **Step 10: Inspect final scope**

```bash
git status --short
git diff --stat HEAD~10..HEAD
git log --oneline --decorate -12
```

Expected: only issue #59 files plus the user's pre-existing `.gitignore` change are present; the `.gitignore` change is unstaged and uncommitted by this work.
