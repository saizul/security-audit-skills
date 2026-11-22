# STRIDE guide

| Letter | Threat | Property violated | Typical controls |
| --- | --- | --- | --- |
| S | Spoofing identity | Authentication | MFA, OAuth/OIDC, mTLS, signed webhooks, API keys with scopes |
| T | Tampering with data | Integrity | Input validation, parameterized queries, TLS, signatures/HMAC, DB permissions |
| R | Repudiation | Non-repudiation | Audit logs with actor/time/request id, tamper-evident log storage |
| I | Information disclosure | Confidentiality | Authorization, encryption in transit/at rest, data minimisation, error handling |
| D | Denial of service | Availability | Rate limits, quotas, timeouts, size limits, autoscaling caps, queues |
| E | Elevation of privilege | Authorization | Deny by default, object-level checks, least-privilege runtime, sandboxing |

## STRIDE per element

| Element | S | T | R | I | D | E |
| --- | --- | --- | --- | --- | --- | --- |
| External entity | x |   | x |   |   |   |
| Process | x | x | x | x | x | x |
| Data store |   | x | x* | x | x |   |
| Data flow |   | x |   | x | x |   |

`*` repudiation applies to stores that hold audit/log data or records of who changed what.

## Questions that find real threats

Spoofing
- How does each receiver know who sent a request? What if the token is stolen, replayed or
  issued for another service (audience)?
- Can a webhook be sent by anyone who knows the URL?

Tampering
- Which inputs change money, permissions, ownership or state? Are they validated server-side?
- Could a message on a queue be forged by another internal service?

Repudiation
- If a customer says "I never did that", what evidence exists? Who can delete logs?

Information disclosure
- Which responses, logs, error messages, analytics events or backups contain personal data or
  secrets? Who can read the bucket/snapshot?
- Can user A see user B's object by changing an id?

Denial of service
- What is the most expensive request an anonymous user can make? What happens when a
  dependency is slow?

Elevation of privilege
- Where are roles checked? What does a support/admin tool let staff do, and how is it audited?
- Can an uploaded file or template ever be executed?

## Model schema

```json
{
  "system": "name",
  "elements": [
    {"id": "api", "type": "process|store|external", "name": "API", "zone": "dmz",
     "internet_facing": true, "data": ["pii"], "encrypted_at_rest": true}
  ],
  "flows": [
    {"from": "user", "to": "api", "name": "Login", "protocol": "https",
     "authenticated": false, "data": ["credentials"]}
  ]
}
```

Scoring in `stride.py`: likelihood and impact are 1-3, risk = likelihood x impact
(High 6-9, Medium 3-4, Low 1-2). Model facts raise the numbers: internet-facing processes
(tampering, DoS, EoP), sensitive data (impact 3 for tampering/disclosure), stores without
`encrypted_at_rest`, plain-text or unmarked protocols on flows, and flows that cross a zone
with `"authenticated": false` (an extra spoofing threat). TLS protocols lower in-transit
tampering/disclosure to likelihood 1. Treat the numbers as a sorting aid, not a measurement.

## Good threat statements

Bad: "Attacker hacks the database."
Good: "A tenant admin can export another tenant's invoices by changing `tenantId` in
`GET /export?tenantId=` because the export job trusts the query parameter (T, I, E)."

Format: actor + action + asset + how + impact. Each should be testable.
