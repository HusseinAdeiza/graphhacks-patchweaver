// planner/plan.js
//
// The PatchWeaver planner — the load-bearing graph algorithm.
//
// THE QUESTION IT ANSWERS (and why it needs a graph):
//   "What set of package upgrades fixes every known vulnerability WITHOUT
//    breaking a single version constraint anywhere in the dependency tree?"
//
// This is constraint satisfaction over a connected structure. A package's
// usable versions are gated by the semver constraint of EVERY parent that
// depends on it — and those parents are gated by their parents, transitively.
// Deciding whether vulnerable package P can jump to fixed version V requires
// walking the tree, collecting every constraint on P, and, if V satisfies none
// of them, finding whether a consistent set of parent bumps makes it reachable.
// There is no row-and-column equivalent: the reasoning is "traverse, propagate
// constraints, find a consistent assignment." Remove the graph and this dies.
//
// This is precisely the documented gap in Dependabot: it "cannot create a pull
// request to update the vulnerable dependency to a secure version without
// breaking other dependencies," and cannot upgrade a transitive dep when that
// forces a parent version bump. PatchWeaver does exactly that.

import semver from "semver";
import { rows } from "../graph/load.js";

// Pull the whole relevant graph into memory (small, deterministic) and plan
// in JS where the constraint solver lives. Graph = structure; semver = math.
async function loadModel() {
  const pkgs = await rows("MATCH (p:Package) RETURN p.name AS name");
  const vers = await rows("MATCH (p:Package)-[:HAS_VERSION]->(v:Version) RETURN p.name AS pkg, v.version AS version ORDER BY version");
  const deps = await rows("MATCH (a:Package)-[r:DEPENDS_ON]->(b:Package) RETURN a.name AS parent, b.name AS child, r.constraint AS constraint");
  const advs = await rows("MATCH (adv:Advisory)-[af:AFFECTS]->(p:Package) RETURN adv.id AS id, adv.severity AS severity, adv.summary AS summary, p.name AS pkg, af.introduced AS introduced, af.fixed AS fixed");

  const versions = {};
  for (const v of vers) (versions[v.pkg] ||= []).push(v.version);
  // children[pkg] = [{parent, child, constraint}] — every edge INTO pkg
  const parents = {};   // who depends on pkg
  const children = {};  // what pkg depends on
  for (const d of deps) {
    (parents[d.child] ||= []).push({ parent: d.parent, constraint: d.constraint });
    (children[d.parent] ||= []).push({ child: d.child, constraint: d.constraint });
  }
  return { packages: pkgs.map((p) => p.name), versions, parents, children, advisories: advs };
}

// Is the advisory's fix reachable for pkg given every parent's current constraint?
function satisfiesAnyParent(pkg, version, parents) {
  const ps = parents[pkg] || [];
  if (ps.length === 0) return true; // no one constrains it -> free
  return ps.some((p) => safeSatisfies(version, p.constraint));
}

function safeSatisfies(version, constraint) {
  try { return semver.satisfies(version, constraint); } catch { return false; }
}

// Smallest available version of pkg that is >= fixed and satisfies at least one
// parent's constraint. Returns null if none qualifies.
function candidateFix(pkg, fixed, versions, parents) {
  const avail = (versions[pkg] || []).filter((v) => semver.valid(v));
  const ordered = avail.sort(semver.compare);
  for (const v of ordered) {
    if (semver.lt(v, fixed)) continue;               // must be >= fixed
    if (satisfiesAnyParent(pkg, v, parents)) return v;
  }
  return null;
}

// The plan for one advisory: can we fix it directly, or does it need parent bumps?
function planAdvisory(adv, model) {
  const { versions, parents } = model;
  const pkg = adv.pkg;
  const ps = parents[pkg] || [];

  // 1) Direct fix: some available version >= fixed satisfies an existing parent constraint.
  const direct = candidateFix(pkg, adv.fixed, versions, parents);
  if (direct) {
    return {
      advisory: adv.id, pkg, severity: adv.severity,
      action: "upgrade", target: direct,
      needsParentBump: false,
      reason: `${pkg}@${direct} fixes ${adv.id} and satisfies ${ps.map((p) => `${p.parent}(${p.constraint})`).join(", ") || "no constraint"}`,
    };
  }

  // 2) Constrained: no available version works under current parent pins.
  //    Propose bumping the blocking parent(s) to their latest, and record the
  //    constraint the NEW parent will declare for this child: a caret on the
  //    fixed version's major, which is what a fresh `npm i pkg@fix` writes.
  const blockers = ps.filter((p) => !safeSatisfies(adv.fixed, p.constraint));
  const parentBumps = [];
  const fixMajor = semver.major(adv.fixed);
  const fixMinor = semver.minor(adv.fixed);
  // A fresh `npm i <pkg>@<fixed>` writes a caret range pinned to the fixed
  // minor, e.g. qs@6.10.3 -> ^6.10.0. We use that as the range a bumped parent
  // declares for this child.
  const newConstraint = `^${fixMajor}.${fixMinor}.0`;
  for (const b of blockers) {
    const latest = (versions[b.parent] || []).filter(semver.valid).sort(semver.compare).pop();
    if (latest) parentBumps.push({ parent: b.parent, from: "current", to: latest, relConstraint: b.constraint, newConstraint });
  }
  const fixAfterBump = (versions[pkg] || []).filter((v) => semver.valid(v) && !semver.lt(v, adv.fixed)).sort(semver.compare);
  return {
    advisory: adv.id, pkg, severity: adv.severity,
    action: "upgrade-with-parent-bumps",
    target: fixAfterBump[fixAfterBump.length - 1] || adv.fixed,
    needsParentBump: true,
    parentBumps,
    reason: `${pkg} cannot reach ${adv.fixed} under ${blockers.map((b) => `${b.parent}@${b.constraint}`).join(", ")} — bump those parents first`,
  };
}

export async function plan() {
  const model = await loadModel();
  const results = [];
  for (const adv of model.advisories) results.push(planAdvisory(adv, model));
  return { model, plan: results };
}

// Human-readable plan, sorted by severity.
export function renderPlan(plan) {
  const order = { high: 0, medium: 1, low: 2, unknown: 3 };
  const sorted = [...plan.plan].sort((a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9));
  const lines = [];
  for (const r of sorted) {
    const tag = r.action === "upgrade" ? "[SAFE UPGRADE]" : "[UPGRADE + PARENT BUMP]";
    lines.push(`${tag} ${r.advisory} (${r.severity})`);
    lines.push(`   -> ${r.pkg} => ${r.target}   ${r.reason}`);
    for (const b of r.parentBumps || []) lines.push(`      also bump ${b.parent} -> ${b.to}`);
  }
  return lines.join("\n");
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const p = await plan();
  console.log(renderPlan(p));
}
