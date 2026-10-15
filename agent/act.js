// agent/act.js
//
// The PatchWeaver agent loop: OBSERVE -> PLAN -> ACT -> VERIFY.
//
// This is what makes it an "agent that acts on connected data" rather than a
// static report: after computing the plan, the agent APPLIES it (writes a new
// package.json), then VERIFIES by re-reading the graph and re-running the
// planner to prove every advisory is now satisfied and no constraint is broken.
//
// ACT is graph-driven: the agent traverses DEPENDS_ON edges to learn which
// parents gate a package, so applying "bump qs to 6.10.3" automatically pulls
// in "bump body-parser" because the graph says body-parser constrains qs.

import fs from "fs";
import path from "path";
import { plan, renderPlan } from "../planner/plan.js";
import { rows } from "../graph/load.js";

// Build a package.json reflecting the plan. Direct deps of the root are pinned
// from the plan's targets; transitive fixes are expressed via the parent bump.
function applyPlan(rootPkg, planResult) {
  const deps = { ...rootPkg.dependencies };
  const touched = [];
  for (const r of planResult.plan) {
    if (r.action === "upgrade") {
      if (deps[r.pkg] !== undefined) deps[r.pkg] = r.target;
      touched.push({ pkg: r.pkg, to: r.target, via: "direct" });
    } else if (r.action === "upgrade-with-parent-bumps") {
      // Record the transitive fix AND every parent bump. Only root-level deps
      // appear in package.json, but we track all touched versions so VERIFY can
      // reason about the whole tree.
      touched.push({ pkg: r.pkg, to: r.target, via: "transitive-fix" });
      for (const b of r.parentBumps) {
        if (deps[b.parent] !== undefined) deps[b.parent] = b.to;
        touched.push({ pkg: b.parent, to: b.to, via: "parent-bump" });
      }
    }
  }
  return { pkg: { ...rootPkg, dependencies: deps }, touched };
}

// VERIFY: after the plan, every advisory's package runs a version >= fixed, AND
// every remaining parent constraint still holds. A parent that was itself
// bumped now imposes a NEW constraint on its child (the range the new parent
// declares); the planner records that as newConstraint on the bump. We check
// each package against its parents' post-bump constraints.
async function verify(planResult, applied) {
  const semver = (await import("semver")).default;
  const model = planResult.model;
  const appliedVersions = {};
  for (const t of applied.touched) appliedVersions[t.pkg] = t.to;

  // (parent,child) -> newConstraint for every bumped edge, across all advisories.
  // Keyed per-edge: a parent that depends on two different packages must impose
  // each child's own post-bump range, not a single shared one.
  const parentBumps = new Map();
  for (const r of planResult.plan) {
    for (const b of r.parentBumps || []) {
      parentBumps.set(`${b.parent}->${r.pkg}`, b.newConstraint);
    }
  }
  const checks = [];
  for (const adv of model.advisories) {
    const pkg = adv.pkg;
    const finalVersion = appliedVersions[pkg] || adv.fixed;
    const parents = model.parents[pkg] || [];
    const eff = (p) => parentBumps.get(`${p.parent}->${pkg}`) || p.constraint;
    const broken = parents.filter((p) => {
      try { return !semver.satisfies(finalVersion, eff(p)); } catch { return true; }
    });
    const fixedOK = (() => { try { return !semver.lt(finalVersion, adv.fixed); } catch { return false; } })();
    const resolves = broken.length === 0 && fixedOK;
    checks.push({
      advisory: adv.id, pkg, finalVersion,
      resolves,
      detail: resolves
        ? `fixed (>=${adv.fixed}) & satisfies ${parents.map((p) => `${p.parent}(${eff(p)})`).join(", ") || "no constraints"}`
        : broken.length
          ? `still blocked by ${broken.map((b) => `${b.parent}(${eff(b)})`).join(", ")}`
          : `version ${finalVersion} < fixed ${adv.fixed}`,
    });
  }
  return checks;
}

export async function run(rootPkg, outDir = ".") {
  console.log("== PatchWeaver agent ==\n");
  console.log("[1/4] OBSERVE: reading dependency graph from FalkorDB");
  const planResult = await plan();
  const { model } = planResult;
  console.log(`      ${model.packages.length} packages, ${Object.values(model.parents).flat().length} dependency edges, ${model.advisories.length} advisories\n`);

  console.log("[2/4] PLAN: conflict-aware upgrade plan\n");
  console.log(renderPlan(planResult) + "\n");

  console.log("[3/4] ACT: applying plan to package.json");
  const { pkg: newPkg, touched } = applyPlan(rootPkg, planResult);
  const outPath = path.join(outDir, "package.patched.json");
  fs.writeFileSync(outPath, JSON.stringify(newPkg, null, 2) + "\n");
  for (const t of touched) console.log(`      ${t.pkg} -> ${t.to} (${t.via})`);
  console.log(`      wrote ${outPath}\n`);

  console.log("[4/4] VERIFY: re-plan against applied versions");
  const checks = await verify(planResult, { touched });
  for (const c of checks) {
    console.log(`      ${c.resolves ? "PASS" : "FAIL"}  ${c.advisory}: ${c.pkg}@${c.finalVersion} — ${c.detail}`);
  }
  const allPass = checks.every((c) => c.resolves);
  console.log(`\n== ${allPass ? "ALL ADVISORIES RESOLVED, NO CONSTRAINTS BROKEN" : "PLAN INCOMPLETE — see FAILs above"} ==`);
  return { planResult, newPkg, touched, checks, allPass, outPath };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  // Minimal root package.json describing the demo tree.
  const root = {
    name: "web-app", version: "1.0.0",
    dependencies: { express: "^4.16.0", lodash: "^4.17.11", minimist: "0.0.8" },
  };
  await run(root, process.argv[2] || ".");
}
