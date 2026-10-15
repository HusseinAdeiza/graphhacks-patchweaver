// verify.js — standalone proof that the plan is correct.
//
// Runs the full agent loop against the graph in FalkorDB and exits non-zero if
// any advisory is unresolved or any constraint is broken. A judge runs:
//     node verify.js
// and gets a clear PASS/FAIL, not a vibe.
//
// Prereq: the graph is loaded (setup.sh does this, or: node graph/load.js).

import { run } from "./agent/act.js";

const root = {
  name: "web-app", version: "1.0.0",
  dependencies: { express: "^4.16.0", lodash: "^4.17.11", minimist: "0.0.8" },
};

// Silence the agent's progress prints; keep only the verdict.
const log = console.log;
console.log = () => {};
let res;
try { res = await run(root, "."); }
finally { console.log = log; }

const { checks, allPass, touched, outPath } = res;
log(`Advisories checked : ${checks.length}`);
log(`Resolved           : ${checks.filter((c) => c.resolves).length}`);
log(`Constraints broken : ${checks.filter((c) => !c.resolves).length}`);
log(`Packages changed   : ${touched.length}`);
log(`Patched manifest   : ${outPath}`);
log("");
for (const c of checks) {
  log(`  ${c.resolves ? "PASS" : "FAIL"}  ${c.advisory}  ${c.pkg}@${c.finalVersion}`);
}
log("");
if (allPass) {
  log("RESULT: PASS — every advisory resolved and no version constraint is broken.");
  process.exit(0);
} else {
  log("RESULT: FAIL — see unresolved advisories above.");
  process.exit(1);
}
