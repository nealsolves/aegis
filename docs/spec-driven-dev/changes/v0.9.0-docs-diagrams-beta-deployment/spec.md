# AEGIS Documentation, Diagram, and Beta Deployment Specification

**Change ID:** `v0.9.0-docs-diagrams-beta-deployment`

**Status:** Approved

**Approved by:** Neal Bhattacharya

The complete approved specification is maintained at
[`../../../superpowers/specs/2026-07-25-aegis-docs-diagrams-beta-deployment-design.md`](../../../superpowers/specs/2026-07-25-aegis-docs-diagrams-beta-deployment-design.md).

Its acceptance contract is:

1. Reconcile the repository map, README, release ownership, and requested
   reference documentation with the v0.9 beta code.
2. Retain or delete each requested document only after recording its durable
   reader, authoritative sources, inbound links, findings, and decision.
3. Repair generated component-diagram overflow without changing the documented
   AEGIS/host ownership boundary.
4. Configure the Render backend and GitHub Pages frontend to deploy the beta
   from `develop`.
5. Keep `main` unchanged until the owner explicitly approves a later cutover.
6. Validate locally, evaluate every remote action independently, and report
   any external configuration or access blocker without claiming deployment.
