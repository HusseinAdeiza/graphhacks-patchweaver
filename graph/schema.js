// graph/schema.js
//
// The PatchWeaver graph model — loaded into FalkorDB.
//
// WHY THIS IS A GRAPH (the removal test):
// The product answers "which set of package upgrades fixes all known
// vulnerabilities without breaking a single version constraint?" That question
// is a constraint-satisfaction problem over a connected structure: a package's
// allowed versions are gated by the constraints of every parent that depends on
// it, and those parents are themselves gated by *their* parents. The reasoning
// is "walk the dependency tree, propagate version constraints, and find a
// consistent assignment" — there is no row-and-table equivalent. Remove the
// graph and the planner dies.
//
// Node model (package, NOT version — a version is a property of the package):
//   (Package {name, ecosystem})
//   (Advisory {id, severity, summary, source})          // a real CVE/GHSA
//   (Version  {version, released})                       // a concrete release
// Edge model:
//   (Package)-[:HAS_VERSION]->(Version)                  // this release exists
//   (Package)-[:DEPENDS_ON {constraint}]->(Package)      // requires pkg@constraint
//   (Advisory)-[:AFFECTS {introduced, fixed}]->(Package) // vuln in a range
//   (Version)-[:INTRODUCES|:FIXES]->(Advisory)           // optional, derived
// The planner reads DEPENDS_ON.constraint + AFFECTS ranges to reason about
// whether a target version is reachable without a parent bump.

export const SCHEMA_STATEMENTS = [
  "CREATE CONSTRAINT FOR (p:Package) REQUIRE p.name IS UNIQUE",
  "CREATE CONSTRAINT FOR (a:Advisory) REQUIRE a.id IS UNIQUE",
];

// Example graph written by the loader. In production these come from OSV
// (advisories) + a lockfile (the dependency tree + constraints). The demo ships
// a realistic multi-level tree so the conflict scenario is reproducible offline.
export const SAMPLE = {
  // Direct + transitive packages with the constraints between them.
  // constraint = the semver range the PARENT requires of the CHILD.
  packages: [
    { name: "web-app", versions: ["1.0.0", "1.1.0", "2.0.0"] },
    { name: "lodash", versions: ["4.17.11", "4.17.15", "4.17.20", "4.17.21"] },
    { name: "express", versions: ["4.16.0", "4.17.1", "4.18.2"] },
    { name: "body-parser", versions: ["1.18.0", "1.19.0", "1.20.1"] },
    { name: "qs", versions: ["6.5.1", "6.5.2", "6.5.3"] },
    { name: "minimist", versions: ["0.0.8", "1.2.5", "1.2.6"] },
    { name: "debug", versions: ["2.6.8", "2.6.9", "4.3.4"] },
    { name: "ms", versions: ["2.0.0", "2.1.2"] },
  ],
  // (parent, child, constraint)
  edges: [
    ["web-app", "express", "^4.16.0"],
    ["web-app", "lodash", "^4.17.11"],
    ["express", "body-parser", "1.18.x"],
    ["body-parser", "qs", "~6.5.1"],
    ["body-parser", "debug", "^2.6.8"],
    ["debug", "ms", "^2.0.0"],
    ["web-app", "minimist", "0.0.8"],
  ],
  // Real advisories (GHSA ids, public via OSV/GitHub):
  //   lodash <4.17.21 prototype pollution  -> fixed 4.17.21
  //   qs    <6.10.3 (comma) DoS            -> fixed 6.10.3, but body-parser pins ~6.5.1
  //   minimist <1.2.6 prototype pollution  -> fixed 1.2.6, but web-app pins 0.0.8 exactly
  //   debug/ms are control nodes (no vuln) that prove the planner leaves
  //   unaffected branches untouched.
  advisories: [
    { id: "GHSA-lodash-pollution", pkg: "lodash", severity: "high",
      introduced: "0", fixed: "4.17.21", summary: "Prototype pollution in lodash" },
    { id: "GHSA-qs-dos", pkg: "qs", severity: "medium",
      introduced: "0", fixed: "6.10.3", summary: "qs arrayLimit DoS (CVE-2022-24999)" },
    { id: "GHSA-minimist-pollution", pkg: "minimist", severity: "high",
      introduced: "0", fixed: "1.2.6", summary: "Prototype pollution in minimist" },
  ],
};
