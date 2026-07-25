# Production Readiness Record

**Level:** <0/1/2/3 and policy-derived rationale>

**Environments:** <development/staging/production targets and separation>

**Dependencies:** <services, data stores, vendors, quotas, failure handling>

**Configuration:** <per-environment validation, secrets, safe defaults>

**Migrations:** <schema/data/config sequence, compatibility, locking, rehearsal>

**Deployment:** <mechanism, strategy, progressive controls, owner>

**Rollback:** <mechanism, criteria, tested result, data constraints>

**Health:** <liveness/readiness/dependency checks and success thresholds>

**Capacity:** <load assumptions, limits, degradation, performance evidence>

**Backups:** <coverage, schedule, integrity, restore verification>

**Recovery:** <RPO/RTO or equivalent targets, failure recovery evidence>

**Runbooks:** <detection, diagnosis, rollback/recovery, escalation links>

**Ownership:** <service, release, operations, and escalation owners>

**Verification:** <pre/post-deployment checks, monitoring window, result>

**Residual risk:** <open findings, tier, authority, exceptions, expiry>

**Evidence freshness:** `policy_hash=<sha256>; context_hash=<sha256>; change_hash=<sha256>`
