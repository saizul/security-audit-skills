# Communication and post-incident templates

Keep messages factual, timestamped (UTC) and free of secrets and unnecessary personal data.
Have legal/privacy review any external notice.

## Internal status update

```
[SEV1] Incident: <title>  |  Status: investigating / contained / resolved  |  <UTC time>
What happened: <one or two sentences, facts only>
Impact: <systems, data, customers affected - or "none seen so far">
Done: <actions with times>
Next: <actions, owner, ETA>
Next update: <time>
Incident lead: <name>   Channel: <link>
```

## Customer notice (when their data or service was affected)

```
Subject: Security incident affecting <service>

On <date> we discovered <what happened, in plain language>. We <contained it by ...> on <date>.
What this means for you: <data involved / not involved>.
What we are doing: <fixes, monitoring>.
What you can do: <rotate API keys you created, review account activity, ...>.
Contact: <address>. We will update this notice at <link>.
```

## Regulatory notification

Personal data breaches may require notifying a regulator and affected people. Under the EU/UK
GDPR the controller notifies the supervisory authority without undue delay and, where
feasible, within 72 hours of becoming aware, unless the breach is unlikely to result in a risk
to individuals; other jurisdictions and contracts have their own rules. Record the facts,
effects and remedial actions either way, and involve legal/privacy early.

## Post-incident review (blameless)

```
# Post-incident review: <title>
Date / duration / severity / authors

## Summary
Two or three sentences.

## Timeline (UTC)
Copy from the incident record; mark detection, containment and resolution times.

## Impact
Systems, data, customers, cost.

## Root cause and contributing factors
Focus on conditions and systems, not individuals.

## What went well / what was hard

## Action items
| Action | Owner | Due | Ticket |
| Secret scanning + push protection on all repos | | | |
| Replace long-lived CI keys with OIDC | | | |
```

Useful metrics to track over time: time to detect, time to contain, time to resolve.
