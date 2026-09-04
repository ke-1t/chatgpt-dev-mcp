## Summary

What does this PR change and why?

## Contract impact

- [ ] v25 Stable Gateway surface (52 direct tools) unchanged
- [ ] Tool schemas / `tool_schema.hash` inputs unchanged, or updated deliberately with maintainer review
- [ ] Approval/lease/verification gates unchanged or strengthened
- [ ] No new dependency (or discussed in an issue first)
- [ ] No secrets, credentials, personal paths (`/Users/<name>/...`), or private project names added

## Testing

- [ ] New behavior covered by tests, including fail-closed denial paths
- [ ] `.venv/bin/python scripts/verify_fast.py` passes
- [ ] `.venv/bin/python scripts/verify_full.py` passes for changes touching surfaces, policy, Git closeout, persistence, or transport

## Docs

- [ ] README / OPERATIONS_GUIDE / FINAL_ARCHITECTURE / SECURITY_MODEL updated if contracts changed
