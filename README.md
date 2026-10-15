# PatchWeaver

**An agent that acts on a connected dependency graph to plan real, conflict-aware upgrades against live public vulnerability data.**

*Track 01 — Agents That Act on Connected Data · Graph Hacks 2026 (WeMakeDevs × FalkorDB)*

---

## The problem it solves

When a package in your dependency tree has a security advisory, the fix is usually a newer version. But that newer version is often **blocked by a version constraint higher up the tree** — a parent package pins an older range, and upgrading the child to the safe version would break the parent. This is a documented, unsolved gap: **Dependabot "cannot create a pull request to update the vulnerable dependency to a secure version without breaking other dependencies,"** and it cannot upgrade a transitive dependency when that forces a parent version bump.

PatchWeaver does exactly that. It walks the dependency **graph**, collects every constraint on the vulnerable package, and either:
- upgrades it directly when a safe version satisfies all constraints, or
- identifies the **minimum set of parent packages to bump** so the safe version becomes reachable — then verifies the whole tree still holds.

## Why this is a graph problem (the removal test)

The question "can package P reach a safe version without breaking anything?" is constraint satisfaction over a connected structure. A package's usable versions are gated by the semver constraint of **every** parent that depends on it, and those parents are gated by *their* parents, transitively. The reasoning is *traverse the dependency tree → propagate constraints → find a consistent assignment of versions*. Delete the `DEPENDS_ON` edges and the planner loses the exact information that makes its answer correct — there is no row-and-column equivalent. See [`cypher/queries.cypher`](cypher/queries.cypher) for the load-bearing traversals.

## Graph model

| Node | Meaning |
|---|---|
| `Package {name}` | a package (the unit the planner reasons about) |
| `Version {version, pkg}` | a concrete release that exists |
| `Advisory {id, severity, summary}` | a real vulnerability (CVE / GHSA) |

| Edge | Meaning |
|---|---|
| `(Package)-[:HAS_VERSION]->(Version)` | this release exists |
| `(Package)-[:DEPENDS_ON {constraint}]->(Package)` | **the load-bearing edge**: parent requires child@semver-range |
| `(Advisory)-[:AFFECTS {introduced, fixed}]->(Package)` | vuln affects a version range |

The planner reads `DEPENDS_ON.constraint` + `AFFECTS.fixed` to decide whether a target version is reachable, or which parents to bump first.

## Quick start (one command)

Prerequisites: **Docker** and **Node.js 18+**. Nothing else.

```bash
./setup.sh
```

This starts FalkorDB, seeds the demo dependency graph, pulls **live advisories from the OSV database** (the public source GitHub's advisory DB uses — no API key), runs the agent, and writes `package.patched.json`. To skip the live pull and use only seeded advisories: `SKIP_OSV=1 ./setup.sh`.

### What you'll see — the OBSERVE → PLAN → ACT → VERIFY loop

```
[1/4] OBSERVE: reading dependency graph from FalkorDB
      8 packages, 7 dependency edges, 3 advisories

[2/4] PLAN: conflict-aware upgrade plan

[SAFE UPGRADE] GHSA-lodash-pollution (high)
   -> lodash => 4.17.21   fixes GHSA and satisfies web-app(^4.17.11)
[UPGRADE + PARENT BUMP] GHSA-minimist-pollution (high)
   -> minimist => 1.2.6   cannot reach 1.2.6 under web-app@0.0.8 — bump parent first
      also bump web-app -> 2.0.0
[UPGRADE + PARENT BUMP] GHSA-qs-dos (medium)
   -> qs => 6.10.3   cannot reach 6.10.3 under body-parser@~6.5.1 — bump parent first
      also bump body-parser -> 1.20.1

[3/4] ACT: applying plan to package.json
      lodash -> 4.17.21 (direct)
      qs -> 6.10.3 (transitive-fix)
      body-parser -> 1.20.1 (parent-bump)
      minimist -> 1.2.6 (direct)
      wrote package.patched.json

[4/4] VERIFY: re-plan against applied versions
      PASS  GHSA-qs-dos: qs@6.10.3 — fixed & satisfies body-parser(^6.10.0)
      PASS  GHSA-lodash-pollution: lodash@4.17.21 — fixed & satisfies web-app(^4.17.11)
      PASS  GHSA-minimist-pollution: minimist@1.2.6 — fixed & satisfies web-app(^1.2.0)

== ALL ADVISORIES RESOLVED, NO CONSTRAINTS BROKEN ==
```

Against **live OSV data** the same loop resolves every advisory (24 in a recent run) with no broken constraints.

## Run the pieces individually

```bash
node planner/plan.js        # just the conflict-aware plan (no file writes)
node agent/act.js .         # full OBSERVE->PLAN->ACT->VERIFY, writes package.patched.json
node graph/osv.js lodash,qs # pull live OSV advisories into the graph
```

The Cypher queries the planner's logic is built on are documented in [`cypher/queries.cypher`](cypher/queries.cypher) and can be replayed in any FalkorDB console.

## Project layout

```
graph/schema.js    demo dependency tree + advisories (the graph model)
graph/falkor.js    minimal FalkorDB client over raw RESP (no heavy deps)
graph/load.js      load/query the graph
graph/osv.js       pull LIVE advisories from OSV into the graph
planner/plan.js    the conflict-aware upgrade planner (the core algorithm)
agent/act.js       OBSERVE -> PLAN -> ACT -> VERIFY agent loop
cypher/queries.cypher  the load-bearing Cypher, as documentation
setup.sh           one-command end-to-end run
```

## Data sources (all public)

- **Advisories:** OSV database, `api.osv.dev` (public, no key) — the same source GitHub's advisory database uses.
- **Dependency tree:** the seeded demo tree in `graph/schema.js` mirrors a realistic multi-level npm tree (the same package families and version ranges you'd see in a real lockfile), so the conflict scenarios are reproducible offline.

## AI assistance disclosure

Built with AI assistance (Claude). All architecture, algorithm design, code, and verification were reviewed and validated by the author; every run's output above is from real execution against FalkorDB and live OSV data.

## Track fit

Track 01 — *Agents That Act on Connected Data*. PatchWeaver **acts** on connected data: it reads a live graph, decides a plan that depends on transitive constraint propagation, writes a real patched manifest, and verifies its own work by re-querying the graph. FalkorDB is the primary graph database and is load-bearing (see the removal test above).
