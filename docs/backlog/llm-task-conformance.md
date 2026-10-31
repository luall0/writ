# LLM task-conformance check

**Status:** idea, sketched. **Area:** Policy. **Kind:** feature.

## Proposal

A new category of check: **does this work match the task?** The signed ticket carries the task and the plan the agent committed to, which I reviewed. A small model flags commits or pushes that drift from it (touching billing, CI, removing tests…). Note: the plan was written by the agent, so it's a reference I validated, not a trusted instruction for the model.

Rules:
1. **Can only tighten, never loosen.** It can deny, notify or ask for approval. It can never approve what the policy denies.
2. **Facts, not raw prose.** The daemon extracts file paths, diff stats and sensitive areas (CI, secrets, lockfiles, tests). Raw diffs and commit messages are passed only if needed, marked as untrusted data, since the judge is itself exposed to prompt injection.
3. **Obvious cases stay deterministic.** Path globs, size and deletion thresholds are plain rules; the model handles the fuzzy middle.
4. **Local model preferred** (MLX / Ollama on the Mac, or on the server): code stays on my machines and it works offline.
5. **Explains denials** in notifications, alongside the raw facts.

Natural place: the push validation step, once the pack is in quarantine.

## Threat model impact

The judge reads agent-written content, so it is itself exposed to prompt injection: rule 1
(it can only tighten) is what keeps a fooled judge harmless. It closes part of
"signed content is good", which [Writ does not guarantee](../threat-model.md#what-writ-does-not-guarantee) today.

## Open questions

Not started: which model, which facts, latency budget on a push, what "ask for approval" looks like.

## Plan

Added when picked.
