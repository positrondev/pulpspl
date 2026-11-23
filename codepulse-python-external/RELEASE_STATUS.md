# Code Pulse — Python generic-engine development build

**Release gate: NOT PASSED. Do not deploy as a replacement for the original 77-rule analyzer.**

## Exact coverage

- Original rules: 77
- Original IDs with independently executable YAML definitions: 47/77
- Original IDs absent from YAML: 30/77
- Original YAML rules enabled by default: 27
- Additional custom rule IDs: 3
- Comprehensive parity certified rules: **0/77**
- No `src/codepulse/rules` implementation modules are present or imported by the external-only engine.
- The currently bundled 17 focused unit tests passed, along with branch, file and full/store integration tests in Linux using PYTHONPATH.
- Original-vs-external parity fixture: one matching E01.workflow-nondeterminism finding after correcting class context; other fixtures still have mismatches. **This is not certification.**
- Standard `pip install .` wheel build could not be verified here because the `hatchling` build dependency is unavailable offline. Windows installation is unverified.

## This build's changes

1. Read-only Python AST import-alias qualification and lexical scope context, plus reusable declarative predicates.
2. Seven additional original-rule YAML definitions using structural predicates; six default-disabled until precise parity is proven.
3. Conservative intra-function declarative data-flow matcher (`python_flow`) and three original-rule YAML definitions, all default-disabled until validated.
4. Scope-aware finding locations and fingerprints for AST/flow matches. This **can change finding identities** relative to earlier external builds.
5. `--repo` combined with relative `--files` resolves files against the specified repository, not the working directory.
6. Seventeen focused automated tests and isolated Git CLI integration checks.

## Remaining blockers

- 30 original sub-checks missing external implementations; 47 mapped sub-checks need full positive/negative/edge-case parity suites.
- Generic interprocedural data flow, cross-file test discovery, complete framework catalogs, candidate/semantic judgments, and external declarative message-details templates remain incomplete.
- Some heuristic rules are only syntactic approximations and are intentionally disabled.
- Regex safety limits and Windows packaging need further hardening and validation.

Use this build for developing and evaluating the rule language, **not** as the only production security or quality gate.
