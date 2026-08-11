# Public demo API operations

This FastAPI service is a public, deterministic demonstration surface. Its edge controls are defense in depth around the demo; they do not change AEGIS SDK enforcement semantics.

## Fixed limits

The limits in `demo_limits.py` are intentionally not client-configurable:

| Resource | Limit |
| --- | ---: |
| Request body | 65,536 bytes |
| Total request-body read deadline | 4 seconds |
| YAML input | 24,576 encoded bytes |
| YAML anchors / aliases | 24 / 24 |
| YAML nesting depth | 20 |
| YAML scalars / collections | 2,048 / 512 |
| Expanded YAML occurrences | 4,096 |
| Expanded scalar bytes | 131,072 |
| YAML/JSON response preflight | 262,144 bytes |
| Per-client rate bucket | capacity 30, refill 1/second |
| Global rate bucket | capacity 120, refill 10/second |
| Tracked client identities | 2,048, evicted after 300 idle seconds |
| Workflow subprocess | 10 seconds |
| Internal diagnostic capture | 8,192 bytes |

Every non-2xx response uses one envelope:

```json
{"detail":{"code":"INVALID_REQUEST","message":"Request is invalid.","request_id":"0123456789abcdef0123456789abcdef"}}
```

Use the `X-Request-ID` response header to locate the correlated bounded server log. Expected HTTP-200 demo outcomes use the same three-field error object in their `error` field. Bodies, caller-provided request IDs, raw parser output, subprocess output, filesystem paths, and exception strings are never public diagnostics.

## Rate and proxy semantics

`GET /health` and CORS `OPTIONS` requests bypass token consumption so health checks and browser preflights stay available; their bodies remain bounded. All other requests consume the global bucket and the resolved client bucket. A rate denial is evaluated before header/body validation, so a `429` can intentionally take precedence over `413`.

The service trusts only the rightmost `X-Forwarded-For` hop, and only when its immediate socket peer is private or loopback. The immediate deployment proxy must strip client-supplied forwarding headers and append its own authenticated client address. Uvicorn runs with `--no-proxy-headers` so it cannot rewrite the socket peer before the demo edge evaluates trust.

The limiter is process-local. Production must run exactly one worker, as pinned in `render.yaml`. Scaling to multiple processes or instances requires a shared atomic limiter and a reviewed identity/trust design first.

## Monitoring and response

Alert on sustained changes in the bounded log fields `public_code` and `operation`, especially body timeouts/size denials, `YAML_LIMIT_EXCEEDED`, `RATE_LIMIT_EXCEEDED`, workflow subprocess timeouts, response-size denials, and internal errors. Dashboards should group by route template and identity source, never request body or raw forwarding values.

For an incident:

1. Correlate reports with `X-Request-ID`; preserve bounded application and proxy logs.
2. Confirm the deployed command has one worker and `--no-proxy-headers`.
3. Verify the immediate proxy strips inbound forwarding headers and appends the trusted hop.
4. Run `scripts/smoke_demo_security.py` against the affected environment; use `--expect-forwarding-proxy` only behind the configured proxy.
5. If pressure continues, restrict or disable the demo at the deployment edge. Do not loosen limits as an emergency workaround.
6. Roll back to the last verified deployment, repeat the smoke probe, and document which public codes changed.

Local verification:

```bash
PYTHONPATH="$PWD" python -m uvicorn main:app --app-dir demo-app-api --host 127.0.0.1 --port 8000 --no-proxy-headers
python scripts/smoke_demo_security.py --api-url http://127.0.0.1:8000
```
