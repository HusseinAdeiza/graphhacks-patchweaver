// graph/osv.js
//
// Load LIVE advisories from the OSV database (api.osv.dev, public, no key) into
// the FalkorDB graph as (Advisory)-[:AFFECTS {introduced,fixed}]->(Package).
//
// This proves PatchWeaver runs against real, current vulnerability data — the
// same data source GitHub's own advisory database uses — not just a seeded demo.
// Each OSV vuln's affected[].ranges[].events give the introduced/fixed bounds.

import { Falkor, q } from "./falkor.js";

const ECOSYSTEM = "npm";

// Fetch all vulns for a package from OSV.
export async function fetchOSV(name, ecosystem = ECOSYSTEM) {
  const r = await fetch("https://api.osv.dev/v1/query", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ package: { name, ecosystem } }),
  });
  if (!r.ok) throw new Error(`OSV ${r.status} for ${name}`);
  const j = await r.json();
  return j.vulns || [];
}

// Extract introduced/fixed bounds from an OSV vuln. Prefer the SEMVER range
// type; fall back to the first range with a fixed event.
function bounds(vuln) {
  for (const aff of vuln.affected || []) {
    for (const range of aff.ranges || []) {
      if (range.type !== "SEMVER") continue;
      let introduced = "0", fixed = null;
      for (const ev of range.events || []) {
        if (ev.introduced) introduced = ev.introduced;
        if (ev.fixed) fixed = ev.fixed;
      }
      if (fixed) return { introduced, fixed };
    }
  }
  return null;
}

// Load live advisories for a list of packages into the graph.
export async function loadLiveAdvisories(packages) {
  const f = new Falkor();
  let loaded = 0, withFix = 0;
  for (const name of packages) {
    await f.query(`MERGE (p:Package {name:${q(name)}})`);
    let vulns;
    try { vulns = await fetchOSV(name); } catch (e) { console.warn(`  ! OSV failed for ${name}: ${e.message}`); continue; }
    for (const v of vulns) {
      const b = bounds(v);
      if (!b) continue; // no fix in this range -> not actionable by the planner
      const severity = v.severity?.[0]?.score || v.database_specific?.severity || "unknown";
      await f.query(
        `MERGE (adv:Advisory {id:${q(v.id)}, severity:${q(String(severity))}, summary:${q(v.summary || "")}})`);
      await f.query(
        `MATCH (adv:Advisory {id:${q(v.id)}}), (p:Package {name:${q(name)}}) ` +
        `MERGE (adv)-[:AFFECTS {introduced:${q(b.introduced)}, fixed:${q(b.fixed)}}]->(p)`);
      loaded++; withFix++;
    }
  }
  return { packages: packages.length, advisories: loaded };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const pkgs = (process.argv[2] || "lodash,qs,minimist").split(",");
  console.log("loading live OSV advisories for:", pkgs.join(", "));
  const r = await loadLiveAdvisories(pkgs);
  console.log("loaded:", r);
}
